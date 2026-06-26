/**
 * 📺 WatchIt.maybe Stream Proxy — Cloudflare Worker (ES Modules Version)
 * ---------------------------------------------------------------------
 * Fungsi:
 * 1. Inject header Referer / User-Agent / Origin untuk bypass restriksi CDN.
 * 2. Tambah header CORS agar browser tidak memblokir stream.
 * 3. Proxy manifest HLS (.m3u8) & DASH (.mpd) + menulis ulang URL di dalamnya secara dinamis.
 * 4. Proteksi SSRF untuk mencegah penyalahgunaan IP lokal/privat.
 */

const MAX_URL_LENGTH = 2048;

export default {
  async fetch(request, env) {
    const originHeader = request.headers.get('Origin') || '';
    const allowedOrigins = parseAllowedOrigins(env.ALLOWED_ORIGINS);
    const corsHeaders = getCorsHeaders(originHeader, allowedOrigins);

    // Handle Preflight Request (OPTIONS)
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // Hanya izinkan method GET, HEAD, dan POST
    if (request.method !== 'GET' && request.method !== 'HEAD' && request.method !== 'POST') {
      return denyResponse(405, 'Method Not Allowed', corsHeaders);
    }

    // Proteksi Origin/Referer (Anti-Abuse)
    if (allowedOrigins.length > 0) {
      const refererHeader = request.headers.get('Referer') || '';
      const isAllowedOrigin = originHeader && allowedOrigins.includes(originHeader);
      const isAllowedReferer = refererHeader && allowedOrigins.some(origin => refererHeader.startsWith(origin));

      if ((originHeader && !isAllowedOrigin) || (!originHeader && refererHeader && !isAllowedReferer)) {
        return denyResponse(403, 'Forbidden: Origin or Referer not allowed', corsHeaders);
      }
    }

    // Parse target URL and custom headers (supports query params and path-based routing)
    let targetUrlString = '';
    let headersParam = '';

    const requestUrl = new URL(request.url);
    const queryTarget = requestUrl.searchParams.get('url');

    if (queryTarget) {
      targetUrlString = queryTarget;
      headersParam = requestUrl.searchParams.get('h') || '';
    } else {
      // Path-based parsing
      // Pattern 1: /h_[base64-headers]/https://target-url.com/...
      // Pattern 2: /https://target-url.com/...
      const requestUrlString = request.url;
      const pathMatch = requestUrlString.match(/\/h_([^/]+)\/(https?:\/\/.+)$/);
      if (pathMatch) {
        headersParam = pathMatch[1];
        targetUrlString = pathMatch[2];
      } else {
        const noHeadersMatch = requestUrlString.match(/\/https?:\/\/.+$/);
        if (noHeadersMatch) {
          targetUrlString = noHeadersMatch[0].substring(1); // remove leading slash
        }
      }
    }

    if (!targetUrlString) {
      return denyResponse(400, 'Missing target URL parameter in query or path', corsHeaders);
    }

    if (targetUrlString.length > MAX_URL_LENGTH) {
      return denyResponse(414, 'URI Too Long', corsHeaders);
    }

    // Validasi URL Target (Cegah SSRF)
    let targetUrl;
    try {
      targetUrl = new URL(targetUrlString);
    } catch {
      return denyResponse(400, 'Invalid target URL', corsHeaders);
    }

    if (targetUrl.protocol !== 'http:' && targetUrl.protocol !== 'https:') {
      return denyResponse(400, 'Scheme not allowed (must be http or https)', corsHeaders);
    }

    if (isBlockedHost(targetUrl.hostname)) {
      return denyResponse(403, 'Target host is blocked', corsHeaders);
    }

    if (targetUrl.hostname === requestUrl.hostname) {
      return denyResponse(400, 'Refusing to proxy self', corsHeaders);
    }

    // Dekode header kustom dari parameter 'h' (Base64 JSON)
    let customHeaders = {};
    if (headersParam) {
      try {
        customHeaders = JSON.parse(atob(decodeURIComponent(headersParam)));
      } catch (err) {
        // Abaikan jika dekode gagal
      }
    }

    // Susun header untuk dikirim ke CDN target
    const forwardHeaders = new Headers();
    const ALLOWED_HEADERS_TO_FORWARD = ['referer', 'user-agent', 'origin'];

    for (const [key, value] of Object.entries(customHeaders)) {
      const normalizedKey = key.toLowerCase();
      if (ALLOWED_HEADERS_TO_FORWARD.includes(normalizedKey)) {
        forwardHeaders.set(key, String(value).slice(0, 512));
      }
    }

    // Meneruskan header penting dari request client asli (seperti Content-Type untuk POST)
    const incomingContentType = request.headers.get('Content-Type');
    if (incomingContentType) {
      forwardHeaders.set('Content-Type', incomingContentType);
    }

    // Teruskan header Range jika ada (sangat penting untuk seeking video)
    const rangeHeader = request.headers.get('Range');
    if (rangeHeader) {
      forwardHeaders.set('Range', rangeHeader);
    }

    // Default User-Agent jika tidak disediakan
    if (!forwardHeaders.has('User-Agent')) {
      forwardHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    }

    // Lakukan fetch ke CDN target
    let response;
    try {
      const fetchOptions = {
        method: request.method,
        headers: forwardHeaders,
        redirect: 'follow'
      };
      
      // Meneruskan body untuk request POST/PUT
      if (request.method !== 'GET' && request.method !== 'HEAD' && request.body) {
        fetchOptions.body = request.body;
      }

      response = await fetch(targetUrl.toString(), fetchOptions);
    } catch (err) {
      return denyResponse(502, 'Upstream fetch failed: ' + err.message, corsHeaders);
    }

    const contentType = (response.headers.get('Content-Type') || '').toLowerCase();
    const isHls = /mpegurl|m3u8/.test(contentType) || /\.m3u8(\?|$)/i.test(targetUrlString);
    const isDash = /dash\+xml|\.mpd/.test(contentType) || /\.mpd(\?|$)/i.test(targetUrlString);

    // Buat response headers baru dengan CORS
    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.set('X-Content-Type-Options', 'nosniff');

    const HEADERS_TO_COPY = ['Content-Type', 'Content-Length', 'Accept-Ranges', 'Content-Range', 'Cache-Control'];
    for (const name of HEADERS_TO_COPY) {
      const val = response.headers.get(name);
      if (val) responseHeaders.set(name, val);
    }

    // Jika manifest HLS atau DASH, kita harus membaca ulang isinya untuk merutekan link di dalamnya lewat proxy ini
    if (isHls || isDash) {
      const manifestText = await response.text();
      const selfProxyBase = requestUrl.origin;
      
      const rewrittenBody = isHls 
        ? rewriteHlsManifest(manifestText, targetUrlString, selfProxyBase, headersParam)
        : rewriteDashManifest(manifestText, targetUrlString, selfProxyBase, headersParam);

      responseHeaders.set('Content-Type', isHls ? 'application/vnd.apple.mpegurl' : 'application/dash+xml');
      responseHeaders.delete('Content-Length'); // Content-length berubah setelah di-rewrite

      return new Response(rewrittenBody, { status: response.status, headers: responseHeaders });
    }

    // Untuk segmen video (.ts / .m4s) langsung return stream body
    return new Response(response.body, { status: response.status, headers: responseHeaders });
  }
};

/* --- Helper Keamanan & CORS --- */

function parseAllowedOrigins(value) {
  return (value || '')
    .split(',')
    .map(origin => origin.trim().replace(/\/+$/, ''))
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
    'Vary': 'Origin'
  };
}

function denyResponse(status, message, corsHeaders) {
  return new Response(message, {
    status,
    headers: {
      ...corsHeaders,
      'Content-Type': 'text/plain'
    }
  });
}

function isBlockedHost(hostname) {
  const host = (hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return true;

  // Blokir localhost / nama host lokal
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localhost')) {
    return true;
  }

  // Blokir Cloud metadata endpoint
  if (host === 'metadata.google.internal') return true;

  // Blokir IPv6 loopback / local link
  if (host === '::1' || host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) {
    return true;
  }

  // Validasi IPv4 loopback & range privat
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = ipv4Regex.exec(host);
  if (match) {
    const a = parseInt(match[1], 10);
    const b = parseInt(match[2], 10);

    if (a === 127 || a === 10 || a === 0) return true; // Loopback & Private Class A
    if (a === 169 && b === 254) return true;           // Link-local (Metadata API)
    if (a === 192 && b === 168) return true;           // Private Class C
    if (a === 172 && b >= 16 && b <= 31) return true;  // Private Class B
    if (a === 100 && b >= 64 && b <= 127) return true; // Carrier-Grade NAT
    if (a >= 224) return true;                         // Multicast / Reserved
  }

  return false;
}

/* --- Helper Penulisan Ulang Manifest (Rewriter) --- */

function absolutizeUrl(relativeUrl, baseUrl) {
  try {
    return new URL(relativeUrl, baseUrl).toString();
  } catch {
    return relativeUrl;
  }
}

function wrapUrlInProxy(absoluteUrl, selfProxyBase, headersParam) {
  if (headersParam) {
    return `${selfProxyBase}/h_${headersParam}/${absoluteUrl}`;
  }
  return `${selfProxyBase}/${absoluteUrl}`;
}

function rewriteHlsManifest(text, manifestUrl, selfProxyBase, headersParam) {
  return text
    .split(/\r?\n/)
    .map(line => {
      const trimmed = line.trim();
      if (!trimmed) return line;

      // Ubah atribut URI eksternal (seperti key atau sub-playlist)
      if (trimmed.startsWith('#')) {
        return trimmed.replace(/URI="([^"]+)"/g, (_, uri) => {
          const abs = absolutizeUrl(uri, manifestUrl);
          return `URI="${wrapUrlInProxy(abs, selfProxyBase, headersParam)}"`;
        });
      }

      // Ubah URL segmen (.ts / .m4s)
      const absoluteSegmentUrl = absolutizeUrl(trimmed, manifestUrl);
      return wrapUrlInProxy(absoluteSegmentUrl, selfProxyBase, headersParam);
    })
    .join('\n');
}

function rewriteDashManifest(text, manifestUrl, selfProxyBase, headersParam) {
  // Ganti tag <BaseURL>...</BaseURL>
  text = text.replace(/<BaseURL>([^<]+)<\/BaseURL>/g, (_, url) => {
    const abs = absolutizeUrl(url.trim(), manifestUrl);
    const wrapped = wrapUrlInProxy(abs, selfProxyBase, headersParam);
    return `<BaseURL>${wrapped}</BaseURL>`;
  });

  // Ganti atribut media, initialization, dan sourceURL (mendukung relative & absolute)
  text = text.replace(/(media|initialization|sourceURL)="([^"]+)"/g, (_, attribute, url) => {
    const abs = absolutizeUrl(url, manifestUrl);
    const wrapped = wrapUrlInProxy(abs, selfProxyBase, headersParam);
    return `${attribute}="${wrapped}"`;
  });

  return text;
}
