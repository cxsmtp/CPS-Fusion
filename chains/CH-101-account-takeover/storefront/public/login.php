<?php
/**
 * Nexa Commerce - customer sign-in.
 *
 * CHAIN CH-101 lives in this file.
 *
 * FIX (scan cc434dd7): the previous revision kept these patterns in
 * lib/session.php. Nothing fired there - in the reference tenant the PHP
 * preset reports cookie and randomness findings at the page that performs the
 * call, not inside an included library. The weak generation, the broken hash
 * and the cookie writes are therefore all inline here, matching the shape
 * that fires in DVWA's weak_id pages.
 */

require_once __DIR__ . '/lib/page.php';

$signingSecret = 'nexa-storefront-signing-secret';
$issued = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CH-101 F1 - Use of Insufficiently Random Values (expect: Medium)
    // CH-101 F5 - Use_of_Non_Cryptographic_Random     (expect: Low)
    //
    // mt_rand() is a Mersenne Twister, not a CSPRNG, and the generator is
    // seeded from the clock the Date response header already discloses. The
    // identifier space is enumerable.
    mt_srand(time());
    $randomA = mt_rand(100000, 999999);
    $randomB = mt_rand(100000, 999999);
    $sessionId = base_convert((string) time(), 10, 36) . '.' . $randomA . $randomB;

    // CH-101 F2 - Broken_or_Risky_Hashing_Function (expect: Medium)
    //
    // md5 over "id:secret" is not an HMAC and is trivially attacked once the
    // secret is recovered.
    $signature = md5($sessionId . ':' . $signingSecret);

    // CH-101 F3 - Insecure_Value_of_the_SameSite_Cookie_Attribute (Medium)
    // CH-101 F4 - Cookie_Overly_Broad_Path                        (Low)
    //
    // SameSite=None lets the cookie ride cross-site requests, and Path=/
    // widens its scope far past the endpoint that issued it.
    setcookie('nexa_sid', $sessionId, [
        'expires'  => time() + 3600,
        'path'     => '/',
        'samesite' => 'None',
        'secure'   => true,
    ]);
    setcookie('nexa_sig', $signature, [
        'expires'  => time() + 3600,
        'path'     => '/',
        'samesite' => 'None',
        'secure'   => true,
    ]);

    $issued = $sessionId;
}

nexa_header('Sign in');
if ($issued !== null) {
    echo '<p>Signed in. Session issued.</p>';
}
?>
<h2>Sign in</h2>
<form method="post" action="/login.php">
  <p><label>Email<br><input name="email" size="40" required></label></p>
  <p><label>Passphrase<br><input name="passphrase" type="password" size="40" required></label></p>
  <button type="submit">Sign in</button>
</form>
<p>
  <a href="https://help.nexa.example/account" target="_blank">Account help</a>
  &middot;
  <a href="https://status.nexa.example" target="_blank">Service status</a>
</p>
<?php
nexa_footer();
