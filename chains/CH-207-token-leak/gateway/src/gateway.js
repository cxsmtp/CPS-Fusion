/*
 * CH-207 - Bearer token leak through URLs and logs.
 * DELIBERATELY VULNERABLE - do not deploy. Node built-in http only.
 *
 * The gateway forwards the caller's token to a fixed partner endpoint on the
 * query string, logs the outbound URL and the upstream password, echoes raw
 * upstream errors, and lets callers write arbitrary text into the log.
 */
'use strict';

const http = require('http');
const url = require('url');

const PARTNER_BASE = 'https://partner.example.invalid/v1/orders';
const UPSTREAM_USER = process.env.CH207_UPSTREAM_USER || 'gateway';
const UPSTREAM_PASSWORD = process.env.CH207_UPSTREAM_PASSWORD || '';

function partnerUrl(token, orderRef) {
    return PARTNER_BASE + '?order=' + encodeURIComponent(orderRef) + '&access_token=' + token;
}

function logUpstream() {
    console.log('[gateway] upstream login ' + UPSTREAM_USER + ' password=' + UPSTREAM_PASSWORD);
}

function writeHeaders(res, contentType) {
    res.setHeader('Content-Type', contentType);
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
}

const server = http.createServer(function (req, res) {
    const parsed = url.parse(req.url, true);
    const token = req.headers['authorization'] || '';
    const orderRef = parsed.query.order || '';
    console.log('[gateway] order lookup ' + orderRef);
    try {
        logUpstream();
        const target = partnerUrl(token, orderRef);
        console.log('[gateway] forwarding to ' + target);
        writeHeaders(res, 'text/html; charset=utf-8');
        res.writeHead(200);
        res.end('<!doctype html><html><body><p>Order lookup queued.</p></body></html>');
    } catch (err) {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end('upstream failed: ' + err.message + '\n' + err.stack);
    }
});

if (require.main === module) {
    server.listen(5207, '127.0.0.1');
}

module.exports = { server, partnerUrl };
