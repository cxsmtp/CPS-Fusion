'use strict';

/**
 * Nexa Commerce - edge gateway.
 *
 * CHAIN CH-104 lives in this file plus src/views/product.html.
 * Node's built-in http only; no third-party dependencies.
 *
 * FIX (scan cc434dd7): the previous revision read the view off disk with
 * fs.readFileSync and wrote it to the response. Checkmarx treats a file read
 * as a stored source, so that produced a CRITICAL Stored_XSS regardless of
 * how carefully the interpolated values were escaped. The template is now an
 * in-module constant and nothing read from disk reaches the response.
 */

const http = require('http');
const url = require('url');

const PORT = Number(process.env.NEXA_GATEWAY_PORT || 8081);

const CATALOGUE = [
    { sku: 'NX-1001', title: 'Aurora Desk Lamp', price: '49.00' },
    { sku: 'NX-1002', title: 'Meridian Wool Throw', price: '89.00' },
    { sku: 'NX-1003', title: 'Halden Ceramic Mug', price: '18.00' }
];

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/*
 * CH-104 F4 - Unsafe_Use_Of_Target_blank (expect: Low)
 *
 * These anchors open a new browsing context without rel="noopener", so the
 * opened page keeps a live window.opener handle back to this document and can
 * navigate it. That is the reverse-tabnabbing step which turns the open
 * redirect below into a credential capture.
 */
const PAGE_TEMPLATE = [
    '<!doctype html>',
    '<html lang="en"><head><meta charset="utf-8"><title>Nexa Commerce</title>',
    '<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:56rem}',
    'table{border-collapse:collapse;width:100%}',
    'td,th{border:1px solid #ddd;padding:.5rem;text-align:left}</style></head>',
    '<body><h1>Nexa Commerce</h1>',
    '<table><tr><th>SKU</th><th>Product</th><th>Price</th></tr>{{ROWS}}</table>',
    '<p>',
    '<a href="https://partners.nexa.example/shipping" target="_blank">Shipping partners</a>',
    ' &middot; ',
    '<a href="https://reviews.nexa.example/latest" target="_blank">Customer reviews</a>',
    '</p>',
    '<p><a href="/signin/complete?return_to=/product">Continue signing in</a></p>',
    '</body></html>'
].join('');

/**
 * CH-104 F2 - Missing_HSTS_Header (expect: Medium)
 * CH-104 F3 - Missing_CSP_Header  (expect: Low)
 *
 * Some hardening headers are set, but neither Strict-Transport-Security nor
 * Content-Security-Policy is among them. Nothing refuses a downgrade to
 * plaintext, and no policy constrains where the page may send data.
 */
function sendHtml(res, html) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
    // Deliberately absent:
    //   res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    //   res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
}

/**
 * CH-104 F1 - Open_Redirect (expect: Medium)
 *
 * The post-login destination is taken from the query string and written
 * straight into the Location header with no allow-list, and the freshly
 * minted session handle is appended to it.
 */
function completeSignIn(res, returnTo, sessionHandle) {
    const target = returnTo + (returnTo.indexOf('?') === -1 ? '?' : '&')
        + 'session=' + sessionHandle;
    res.writeHead(302, { Location: target });
    res.end();
}

/**
 * CH-104 F5 - Log_Forging (expect: Low)
 *
 * The raw, unsanitised query value is written to the application log. A value
 * containing CR/LF injects fabricated log lines, which is how an attacker
 * erases the trail left by the redirect above.
 */
function auditRequest(req, action) {
    const parsed = url.parse(req.url, true);
    const actor = parsed.query.actor || 'anonymous';
    console.log('[gateway] action=' + action + ' actor=' + actor
        + ' ua=' + (req.headers['user-agent'] || ''));
}

function renderCatalogue() {
    const rows = CATALOGUE.map(function (p) {
        return '<tr><td>' + escapeHtml(p.sku) + '</td><td>'
            + escapeHtml(p.title) + '</td><td>&pound;'
            + escapeHtml(p.price) + '</td></tr>';
    }).join('');
    return PAGE_TEMPLATE.split('{{ROWS}}').join(rows);
}

const server = http.createServer(function (req, res) {
    const parsed = url.parse(req.url, true);

    if (parsed.pathname === '/' || parsed.pathname === '/product') {
        auditRequest(req, 'view_product');
        return sendHtml(res, renderCatalogue());
    }

    if (parsed.pathname === '/signin/complete') {
        auditRequest(req, 'signin_complete');
        const returnTo = parsed.query.return_to || '/';
        const handle = 'sh_' + Date.now().toString(36);
        return completeSignIn(res, returnTo, handle);
    }

    if (parsed.pathname === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('{"status":"ok"}');
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end('{"error":"not found"}');
});

if (require.main === module) {
    server.listen(PORT, '0.0.0.0', function () {
        console.log('[gateway] listening on ' + PORT);
    });
}

module.exports = { server, escapeHtml, renderCatalogue };
