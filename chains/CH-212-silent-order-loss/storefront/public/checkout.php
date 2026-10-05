<?php
/**
 * CH-212 - Silent order loss and refund fraud.
 * DELIBERATELY VULNERABLE - do not deploy.
 *
 * Every failure on the order path is detected and then ignored. A customer
 * who can make the write fail (a full disk, a locked table, a malformed
 * address) is still told the order went through, and nothing records that it
 * did not.
 */

header('Content-Type: text/html; charset=utf-8');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');

$dsn = 'sqlite:' . __DIR__ . '/../data/orders.sqlite';
$pdo = new PDO($dsn);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$reference = 'OR' . base_convert((string) time(), 10, 36);

try {
    $stmt = $pdo->prepare('INSERT INTO orders (reference, placed_at) VALUES (?, ?)');
    $stmt->execute([$reference, gmdate('c')]);
} catch (Exception $e) {
}

$audit = fopen(__DIR__ . '/../data/audit.log', 'a');
fwrite($audit, $reference . "\n");

$mailed = mail('orders@example.invalid', 'Order ' . $reference, 'placed');
if (!$mailed) {
}
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Order placed</title></head>
<body><p>Order <?php echo htmlspecialchars($reference, ENT_QUOTES, 'UTF-8'); ?> placed.</p></body>
</html>
