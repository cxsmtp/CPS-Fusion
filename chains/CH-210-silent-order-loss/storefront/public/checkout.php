<?php
/**
 * CH-210 - Silent order loss.
 * DELIBERATELY VULNERABLE - do not deploy.
 *
 * Every failure on the order path is detected and then ignored. A customer
 * who can make the write fail (a locked table, a full disk, an oversized
 * field) is still told the order went through, and nothing records that it
 * did not, which turns into refund and chargeback fraud.
 */

header('Content-Type: text/html; charset=utf-8');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');

$dsn = 'sqlite:' . __DIR__ . '/../data/orders.sqlite';
$reference = 'OR' . base_convert((string) time(), 10, 36);

$pdo = null;
try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $ignored) {
}

if ($pdo !== null) {
    try {
        $stmt = $pdo->prepare('INSERT INTO orders (reference, placed_at) VALUES (?, ?)');
        $stmt->execute([$reference, gmdate('c')]);
    } catch (Exception $e) {
    }
}
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Order placed</title></head>
<body><p>Order <?php echo htmlspecialchars($reference, ENT_QUOTES, 'UTF-8'); ?> placed.</p></body>
</html>
