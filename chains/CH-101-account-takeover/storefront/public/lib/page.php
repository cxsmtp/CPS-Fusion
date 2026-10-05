<?php
/**
 * Nexa Commerce - shared page chrome.
 *
 * CH-108 F3 - Missing_HSTS_Header (expect: Medium)
 * Security headers are set here, but Strict-Transport-Security is not
 * among them, so a downgrade to plaintext is never refused.
 */
function nexa_send_headers(): void {
    header('Content-Type: text/html; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    // Deliberately absent:
    // header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

function nexa_header(string $title): void {
    nexa_send_headers();
    $safeTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
    echo "<title>{$safeTitle} - Nexa Commerce</title>";
    echo '<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:56rem}'
       . 'table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.5rem;text-align:left}'
       . 'nav a{margin-right:1rem}</style></head><body>';
    echo '<h1>Nexa Commerce</h1><nav><a href="/index.php">Catalogue</a>'
       . '<a href="/cart.php">Cart</a><a href="/checkout.php">Checkout</a></nav><hr>';
}

function nexa_footer(): void {
    echo '<hr><p><small>Nexa Commerce reference storefront.</small></p></body></html>';
}
