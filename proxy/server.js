/**
 * 📺 WatchIt.maybe Stream Proxy — Node.js HTTP Server
 * ---------------------------------------------------------------------
 * Versi ini dibuat untuk platform NON-Cloudflare (Render, Fly.io, Railway, VPS).
 * Fungsi identik dengan versi Cloudflare Worker (index.js):
 *   1. Inject header Referer / User-Agent / Origin untuk bypass restriksi CDN.
 *   2. Tambah header CORS agar browser tidak memblokir stream.
 *   3. Proxy manifest HLS (.m3u8) & DASH (.mpd) + menulis ulang URL secara dinamis.
 *   4. Dukungan POST untuk permintaan lisensi DRM Widevine.
 *   5. Proteksi SSRF untuk mencegah penyalahgunaan IP lokal/privat.
 *
 * Deploy ke Render.com:
 *   - Build Command : npm install
 *   - Start Command : node server.js
 *   - Root Directory: proxy
 */

import http from 'http';
import { URL } from 'url';

const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGINS_ENV = process.env.ALLOWED_ORIGINS || '';
const MAX_URL_LENGTH = 2048;

/* ------------------------------------------------------------------ */
/*  HTTP Server                                                         */
/* ------------------------------------------------------------------ */

const server = http.createServer(async (req, res) => {
  const originHeader = req.headers['origin'] || '';
  const allowedOrigins = parseAllowedOrigins(ALLOWED_ORIGINS_ENV);
  const corsHeaders = getCorsHeaders(originHeader, allowedOrigins);

  // Handle Preflight (OPTIONS)
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  // Hanya izinkan GET, HEAD, POST
  if (!['GET', 'HEAD', 'POST'].includes(req.method)) {
    return sendDeny(res, 405, 'Method Not Allowed', corsHeaders);
  }

  // Proteksi Origin/Referer
  if (allowedOrigins.length > 0) {
    const refererHeader = req.headers['referer'] || '';
    const isAllowedOrigin = originHeader && allowedOrigins.includes(originHeader);
    const isAllowedReferer = refererHeader && allowedOrigins.some(o => refererHeader.startsWith(o));
    if ((originHeader && !isAllowedOrigin) || (!originHeader && refererHeader && !isAllowedReferer)) {
      return sendDeny(res, 403, 'Forbidden: Origin or Referer not allowed', corsHeaders);
    }
  }

  // Parse target URL & headers param
  const requestUrl = new URL(req.url, `http://${req.headers.host}`);
  let targetUrlString = '';
  let headersParam = '';

  const queryTarget = requestUrl.searchParams.get('url');
  if (queryTarget) {
    targetUrlString = queryTarget;
    headersParam = requestUrl.searchParams.get('h') || '';
  } else {
    const fullPath = req.url;
    const pathMatch = fullPath.match(/\/h_([^/]+)\/(https?:\/\/.+)$/);
    if (pathMatch) {
      headersParam = pathMatch[1];
      targetUrlString = pathMatch[2];
    } else {
      const noHeadersMatch = fullPath.match(/\/(https?:\/\/.+)$/);
      if (noHeadersMatch) {
        targetUrlString = noHeadersMatch[1];
      }
    }
  }

  if (!targetUrlString) {
    return sendDeny(res, 400, 'Missing target URL parameter in query or path', corsHeaders);
  }

  if (targetUrlString.length > MAX_URL_LENGTH) {
    return sendDeny(res, 414, 'URI Too Long', corsHeaders);
  }

  // Validasi URL Target (Cegah SSRF)
  let targetUrl;
  try {
    targetUrl = new URL(targetUrlString);
  } catch {
    return sendDeny(res, 400, 'Invalid target URL', corsHeaders);
  }

  if (targetUrl.protocol !== 'http:' && targetUrl.protocol !== 'https:') {
    return sendDeny(res, 400, 'Scheme not allowed (must be http or https)', corsHeaders);
  }

  if (isBlockedHost(targetUrl.hostname)) {
    return sendDeny(res, 403, 'Target host is blocked', corsHeaders);
  }

  if (targetUrl.hostname === requestUrl.hostname) {
    return sendDeny(res, 400, 'Refusing to proxy self', corsHeaders);
  }

  // Dekode header kustom dari parameter 'h' (Base64 JSON)
  let customHeaders = {};
  if (headersParam) {
    try {
      customHeaders = JSON.parse(Buffer.from(decodeURIComponent(headersParam), 'base64').toString('utf-8'));
    } catch {
      // Abaikan jika dekode gagal
    }
  }

  // Susun header untuk dikirim ke CDN target
  const ALLOWED_HEADERS_TO_FORWARD = ['referer', 'user-agent', 'origin'];
  const forwardHeaders = {};

  for (const [key, value] of Object.entries(customHeaders)) {
    if (ALLOWED_HEADERS_TO_FORWARD.includes(key.toLowerCase())) {
      forwardHeaders[key] = String(value).slice(0, 512);
    }
  }

  // Teruskan Content-Type dari client (penting untuk POST Widevine)
  if (req.headers['content-type']) {
    forwardHeaders['content-type'] = req.headers['content-type'];
  }

  // Teruskan Range header (penting untuk seeking)
  if (req.headers['range']) {
    forwardHeaders['range'] = req.headers['range'];
  }

  // Default User-Agent
  if (!forwardHeaders['user-agent'] && !forwardHeaders['User-Agent']) {
    forwardHeaders['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  }

  // Kumpulkan body jika POST
  let requestBody = null;
  if (req.method === 'POST') {
    requestBody = await readBody(req);
  }

  // Fetch ke upstream
  let upstreamRes;
  try {
    const fetchOptions = {
      method: req.method,
      headers: forwardHeaders,
      redirect: 'follow',
    };
    if (requestBody) {
      fetchOptions.body = requestBody;
    }
    upstreamRes = await fetch(targetUrl.toString(), fetchOptions);
  } catch (err) {
    return sendDeny(res, 502, 'Upstream fetch failed: ' + err.message, corsHeaders);
  }

  const contentType = (upstreamRes.headers.get('Content-Type') || '').toLowerCase();
  const isHls  = /mpegurl|m3u8/.test(contentType) || /\.m3u8(\?|$)/i.test(targetUrlString);
  const isDash = /dash\+xml|\.mpd/.test(contentType) || /\.mpd(\?|$)/i.test(targetUrlString);

  // Susun response headers
  const outHeaders = {
    ...corsHeaders,
    'X-Content-Type-Options': 'nosniff',
  };
  const HEADERS_TO_COPY = ['content-type', 'content-length', 'accept-ranges', 'content-range', 'cache-control'];
  for (const name of HEADERS_TO_COPY) {
    const val = upstreamRes.headers.get(name);
    if (val) outHeaders[name] = val;
  }

  // Rewrite manifest HLS / DASH
  if (isHls || isDash) {
    const selfProxyBase = `${requestUrl.protocol}//${requestUrl.host}`;
    const manifestText = await upstreamRes.text();
    const rewritten = isHls
      ? rewriteHlsManifest(manifestText, targetUrlString, selfProxyBase, headersParam)
      : rewriteDashManifest(manifestText, targetUrlString, selfProxyBase, headersParam);

    outHeaders['content-type'] = isHls ? 'application/vnd.apple.mpegurl' : 'application/dash+xml';
    delete outHeaders['content-length'];

    res.writeHead(upstreamRes.status, outHeaders);
    res.end(rewritten);
    return;
  }

  // Untuk segmen video — stream langsung
  res.writeHead(upstreamRes.status, outHeaders);
  const reader = upstreamRes.body.getReader();
  const pump = async () => {
    while (true) {
      const { done, value } = await reader.read();
      if (done) { res.end(); break; }
      res.write(Buffer.from(value));
    }
  };
  pump().catch(() => res.end());
});

server.listen(PORT, () => {
  console.log(`[WatchIt Proxy] Node.js server running on port ${PORT}`);
});

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendDeny(res, status, message, corsHeaders) {
  res.writeHead(status, { ...corsHeaders, 'Content-Type': 'text/plain' });
  res.end(message);
}

function parseAllowedOrigins(value) {
  return (value || '')
    .split(',')
    .map(o => o.trim().replace(/\/+$/, ''))
    .filter(Boolean);
}

function getCorsHeaders(origin, allowedOrigins) {
  const allowed = allowedOrigins.length === 0
    ? '*'
    : (allowedOrigins.includes(origin) ? origin : allowedOrigins[0]);
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges',
    'Vary': 'Origin',
  };
}

function isBlockedHost(hostname) {
  const h = (hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.localhost')) return true;
  if (h === 'metadata.google.internal') return true;
  if (h === '::1' || h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
  }
  return false;
}

function absolutizeUrl(relativeUrl, baseUrl) {
  try { return new URL(relativeUrl, baseUrl).toString(); }
  catch { return relativeUrl; }
}

function wrapUrlInProxy(absoluteUrl, selfProxyBase, headersParam) {
  if (headersParam) return `${selfProxyBase}/h_${headersParam}/${absoluteUrl}`;
  return `${selfProxyBase}/${absoluteUrl}`;
}

function rewriteHlsManifest(text, manifestUrl, selfProxyBase, headersParam) {
  return text.split(/\r?\n/).map(line => {
    const t = line.trim();
    if (!t) return line;
    if (t.startsWith('#')) {
      return t.replace(/URI="([^"]+)"/g, (_, uri) =>
        `URI="${wrapUrlInProxy(absolutizeUrl(uri, manifestUrl), selfProxyBase, headersParam)}"`
      );
    }
    return wrapUrlInProxy(absolutizeUrl(t, manifestUrl), selfProxyBase, headersParam);
  }).join('\n');
}

function rewriteDashManifest(text, manifestUrl, selfProxyBase, headersParam) {
  text = text.replace(/<BaseURL>([^<]+)<\/BaseURL>/g, (_, url) => {
    const abs = absolutizeUrl(url.trim(), manifestUrl);
    return `<BaseURL>${wrapUrlInProxy(abs, selfProxyBase, headersParam)}</BaseURL>`;
  });
  text = text.replace(/(media|initialization|sourceURL)="([^"]+)"/g, (_, attr, url) => {
    const abs = absolutizeUrl(url, manifestUrl);
    return `${attr}="${wrapUrlInProxy(abs, selfProxyBase, headersParam)}"`;
  });
  return text;
}
