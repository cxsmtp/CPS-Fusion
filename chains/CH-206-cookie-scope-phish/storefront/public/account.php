<?php
/**
 * CH-206 - Predictable remember-me cookie, site-wide scope, tabnabbing.
 * DELIBERATELY VULNERABLE - do not deploy.
 *
 * The remember-me value is derived from a clock-seeded Mersenne Twister.
 * The cookie is scoped to Path=/, so every page on the host receives it.
 * The account page opens partner links with target=_blank and no
 * rel=noopener, and it can be framed.
 */

header('Content-Type: text/html; charset=utf-8');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('X-Content-Type-Options: nosniff');

$remember = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    mt_srand(time());
    $remember = base_convert((string) time(), 10, 36) . '.' . uniqid();
    setcookie('remember_me', $remember, [
        'expires'  => time() + 86400 * 30,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Your account</title></head>
<body>
<h1>Your account</h1>
<?php if ($remember !== null): ?>
<p>You will stay signed in on this device.</p>
<?php endif; ?>
<form method="post" action="/account.php"><button type="submit">Keep me signed in</button></form>
<p>
  <a href="https://help.example.invalid/account" target="_blank">Account help</a>
  &middot;
  <a href="https://status.example.invalid" target="_blank">Service status</a>
</p>
</body>
</html>
