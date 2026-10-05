/*
 * CH-201 - Session prediction to account takeover.
 * DELIBERATELY VULNERABLE - do not deploy. Node built-in http only.
 */
'use strict';

const http = require('http');
const url = require('url');
const crypto = require('crypto');
const session = require('./session');

const PASS_SALT = process.env.CH201_PASS_SALT;
const PASS_HASH = process.env.CH201_PASS_HASH;

function checkPassphrase(passphrase) {
    const derived = crypto.scryptSync(String(passphrase || ''), PASS_SALT, 32);
    const stored = Buffer.from(PASS_HASH, 'hex');
    return stored.length === derived.length && crypto.timingSafeEqual(stored, derived);
}

function writeHeaders(res, contentType) {
    res.setHeader('Content-Type', contentType);
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // No Content-Security-Policy and no X-Frame-Options / frame-ancestors.
}

function handleLogin(req, res, query) {
    if (!checkPassphrase(req.headers['x-passphrase'])) {
        writeHeaders(res, 'application/json');
        res.writeHead(401);
        return res.end(JSON.stringify({ error: 'unauthorised' }));
    }
    const issued = session.issueSession('customer');
    console.log('login from ' + query.user);
    res.setHeader('Set-Cookie', [
        'sid=' + issued.sessionId + '; Path=/; HttpOnly; Secure; SameSite=Strict',
        'sig=' + issued.signature + '; Path=/; HttpOnly; Secure; SameSite=Strict'
    ]);
    writeHeaders(res, 'text/html; charset=utf-8');
    res.writeHead(200);
    res.end('<!doctype html><html><body><h1>Signed in</h1>' +
        '<form method="post" action="/account"><button>Update account</button></form>' +
        '</body></html>');
}

function handleWhoAmI(req, res, query) {
    const ok = session.verifySession(query.sid, query.sig);
    writeHeaders(res, 'application/json');
    res.writeHead(200);
    res.end(JSON.stringify({ authenticated: ok }));
}

const server = http.createServer(function (req, res) {
    const parsed = url.parse(req.url, true);
    try {
        if (parsed.pathname === '/login') {
            return handleLogin(req, res, parsed.query);
        }
        if (parsed.pathname === '/whoami') {
            return handleWhoAmI(req, res, parsed.query);
        }
        writeHeaders(res, 'application/json');
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'not found' }));
    } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(err.message);
    }
});

if (require.main === module) {
    server.listen(5201, '127.0.0.1');
}

module.exports = { server };
