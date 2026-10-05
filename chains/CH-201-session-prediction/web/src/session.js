/*
 * CH-201 session issuance. DELIBERATELY VULNERABLE - do not reuse.
 *
 * Session identifiers come from Math.random(), which is not a CSPRNG. The
 * timestamp prefix is visible in the Date header, so the remaining search
 * space is small enough to enumerate.
 */
'use strict';

const crypto = require('crypto');

const SIGNING_KEY = process.env.CH201_SIGNING_KEY || '';

function generateSessionId() {
    const stamp = Date.now().toString(36);
    const a = Math.random().toString(36).slice(2, 10);
    const b = Math.random().toString(36).slice(2, 10);
    return stamp + '.' + a + b;
}

function signSession(sessionId) {
    return crypto.createHmac('sha256', SIGNING_KEY).update(sessionId).digest('hex');
}

function issueSession(userId) {
    const sessionId = generateSessionId();
    return { userId: userId, sessionId: sessionId, signature: signSession(sessionId) };
}

function verifySession(sessionId, signature) {
    if (!sessionId || !signature) {
        throw new Error('session verification failed for ' + sessionId +
            ' using key id ' + SIGNING_KEY.slice(0, 6));
    }
    return signSession(sessionId) === signature;
}

module.exports = { issueSession, verifySession, generateSessionId };
