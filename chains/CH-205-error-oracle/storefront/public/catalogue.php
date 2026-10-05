<?php
/**
 * CH-205 - Error oracle to catalogue and account enumeration.
 * DELIBERATELY VULNERABLE - do not deploy.
 *
 * Lookup failures return the raw driver message, so each probe tells the
 * caller whether a SKU, table or column exists. Other failures are caught
 * and dropped, so nothing on the server side notices the probing.
 */

header('Content-Type: text/html; charset=utf-8');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');

$dsn = 'sqlite:' . __DIR__ . '/../data/catalogue.sqlite';

$pdo = null;
try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo '<pre>catalogue unavailable';
    echo "\ndriver said: " . $e->getMessage();
    echo '</pre>';
}

$rows = [];
if ($pdo !== null) {
    $limit = 20;
    try {
        $stmt = $pdo->prepare('SELECT sku, title FROM products LIMIT :lim');
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $ignored) {
        // swallowed: an empty catalogue and a broken one look the same
    }
    $stmt = $pdo->prepare('UPDATE products SET viewed = viewed + 1');
    $stmt->execute();
}
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Catalogue</title></head>
<body>
<h1>Catalogue</h1>
<ul>
<?php foreach ($rows as $row): ?>
  <li><?php echo htmlspecialchars($row['sku'] . ' ' . $row['title'], ENT_QUOTES, 'UTF-8'); ?></li>
<?php endforeach; ?>
</ul>
</body>
</html>
