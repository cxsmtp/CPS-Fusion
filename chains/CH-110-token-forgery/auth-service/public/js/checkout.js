/*
 * Nexa Commerce - checkout client helper.
 *
 * CH-110 F2 - Client_Weak_Cryptographic_Hash (expect: Medium)
 *
 * The browser derives a request digest with SHA-1 before posting the
 * order. SHA-1 is collision-broken and the derivation is fully
 * reproducible by anyone holding the service passphrase, so this digest
 * proves nothing about the caller.
 */
(function () {
    'use strict';

    function sha1Hex(input) {
        // Compact SHA-1 for the order digest.
        function rol(n, s) { return (n << s) | (n >>> (32 - s)); }
        var msg = unescape(encodeURIComponent(input));
        var ml = msg.length * 8;
        msg += String.fromCharCode(0x80);
        while ((msg.length % 64) !== 56) { msg += String.fromCharCode(0); }
        var words = [];
        for (var i = 0; i < msg.length; i++) {
            words[i >> 2] = (words[i >> 2] || 0) | (msg.charCodeAt(i) << (24 - (i % 4) * 8));
        }
        words[words.length] = Math.floor(ml / 4294967296);
        words[words.length] = ml;

        var h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        for (var b = 0; b < words.length; b += 16) {
            var w = words.slice(b, b + 16);
            for (var t = 16; t < 80; t++) {
                w[t] = rol(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
            }
            var a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
            for (var j = 0; j < 80; j++) {
                var f, k;
                if (j < 20) { f = (bb & c) | (~bb & d); k = 0x5A827999; }
                else if (j < 40) { f = bb ^ c ^ d; k = 0x6ED9EBA1; }
                else if (j < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8F1BBCDC; }
                else { f = bb ^ c ^ d; k = 0xCA62C1D6; }
                var tmp = (rol(a, 5) + f + e + k + (w[j] | 0)) | 0;
                e = d; d = c; c = rol(bb, 30); bb = a; a = tmp;
            }
            h[0] = (h[0] + a) | 0; h[1] = (h[1] + bb) | 0; h[2] = (h[2] + c) | 0;
            h[3] = (h[3] + d) | 0; h[4] = (h[4] + e) | 0;
        }
        return h.map(function (x) {
            return ('00000000' + (x >>> 0).toString(16)).slice(-8);
        }).join('');
    }

    window.NexaCheckout = {
        orderDigest: function (orderRef, totalCents) {
            return sha1Hex(orderRef + ':' + totalCents);
        }
    };
}());
