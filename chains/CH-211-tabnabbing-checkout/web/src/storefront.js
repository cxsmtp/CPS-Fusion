/*
 * CH-211 - Reverse tabnabbing into a framed checkout.
 * DELIBERATELY VULNERABLE - do not deploy. Node built-in http only.
 */
'use strict';

const http = require('http');
const url = require('url');

const PAGE = [
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Checkout</title></head>',
    '<body><h1>Checkout</h1>',
    '<p><a href="https://partners.example.invalid/shipping" target="_blank">Shipping partners</a></p>',
    '<p><a href="https://reviews.example.invalid/latest" target="_blank">Customer reviews</a></p>',
    '<form method="post" action="/pay"><button>Pay now</button></form>',
    '</body></html>'
].join('\n');

const server = http.createServer(function (req, res) {
    const parsed = url.parse(req.url, true);
    console.log('[storefront] page view campaign=' + parsed.query.campaign);
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // No Content-Security-Policy and no X-Frame-Options / frame-ancestors.
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(PAGE);
});

if (require.main === module) {
    server.listen(5211, '127.0.0.1');
}

module.exports = { server };
