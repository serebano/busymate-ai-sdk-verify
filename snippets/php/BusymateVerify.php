<?php
declare(strict_types=1);
// Verify the Busymate AI connector actor token (bmai.actor/3, ES256 + JWKS). PHP >= 8.1, ext-openssl, no Composer packages.
//   $actor = BusymateVerify::verify(getallheaders(), ['audience' => 'https://mcp.acme.com', 'tenant_id' => 'acme', 'connector_id' => 'conn_1']);
//   // -> ['sub','idp','confirmed','tool','jti','support_session_id'] ; throws BusymateActorError with ->reason

final class BusymateActorError extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message = '')
    {
        parent::__construct($message !== '' ? $message : $reason);
    }
}

final class BusymateVerify
{
    public const DEFAULT_JWKS_URL = 'https://busymate.ai/.well-known/bmai-actor-jwks.json';
    private const ISSUER = 'https://busymate.ai';
    private const TYP = 'bmai-actor+jwt';
    private const SKEW = 10;
    private const MAX_LIFETIME = 120;
    /** @var array<string,int> jti => exp. Per process; use APCu/Redis for shared replay protection. */
    private static array $seen = [];
    private static array $jwks = ['url' => null, 'keys' => [], 'at' => 0, 'refetch' => 0];

    private static function b64d(string $s): string
    {
        $r = base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
        return $r === false ? '' : $r;
    }

    /** Raw token: X-Bmai-Actor first, else Authorization: Bearer only when its header typ is bmai-actor+jwt. */
    public static function tokenFrom(array $headers): ?string
    {
        $h = array_change_key_case($headers, CASE_LOWER);
        $x = trim((string)($h['x-bmai-actor'] ?? ''));
        if ($x !== '') return $x;
        $a = (string)($h['authorization'] ?? '');
        if (preg_match('/^Bearer\s+(\S+)$/i', $a, $m)) {
            $hd = json_decode(self::b64d(explode('.', $m[1])[0]), true);
            if (is_array($hd) && ($hd['typ'] ?? null) === self::TYP) return $m[1];
        }
        return null;
    }

    /** DER SubjectPublicKeyInfo PEM for a P-256 JWK. */
    private static function pem(array $k): ?string
    {
        $x = self::b64d((string)($k['x'] ?? ''));
        $y = self::b64d((string)($k['y'] ?? ''));
        if (strlen($x) !== 32 || strlen($y) !== 32) return null;
        $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function keysFrom(mixed $doc): array
    {
        $out = [];
        foreach ((is_array($doc) ? ($doc['keys'] ?? []) : []) as $k) {
            if (!is_array($k) || ($k['kty'] ?? '') !== 'EC' || ($k['crv'] ?? '') !== 'P-256' || !is_string($k['kid'] ?? null) || $k['kid'] === '') continue;
            if (isset($k['alg']) && $k['alg'] !== 'ES256') continue;
            if (isset($k['use']) && $k['use'] !== 'sig') continue;
            $pem = self::pem($k);
            if ($pem !== null) $out[$k['kid']] = $pem;
        }
        return $out;
    }

    private static function fetch(string $url): array
    {
        $body = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 5, 'header' => "Accept: application/json\r\n"]]));
        if ($body === false) throw new BusymateActorError('jwks_unavailable', 'JWKS fetch failed');
        $doc = json_decode($body, true);
        if (!is_array($doc)) throw new BusymateActorError('jwks_unavailable', 'JWKS is not JSON');
        return self::keysFrom($doc);
    }

    private static function keyFor(string $kid, ?array $jwks, string $url): string
    {
        if ($jwks !== null) {
            $key = self::keysFrom($jwks)[$kid] ?? null;
        } else {
            $now = time();
            if (self::$jwks['url'] !== $url || $now - self::$jwks['at'] > 600) {
                self::$jwks = ['url' => $url, 'keys' => self::fetch($url), 'at' => $now, 'refetch' => $now];
            }
            $key = self::$jwks['keys'][$kid] ?? null;
            if ($key === null && $now - self::$jwks['refetch'] > 30) { // unknown kid: rotation, refetch (rate-limited)
                self::$jwks['keys'] = self::fetch($url);
                self::$jwks['at'] = self::$jwks['refetch'] = $now;
                $key = self::$jwks['keys'][$kid] ?? null;
            }
        }
        if ($key === null) throw new BusymateActorError('unknown_kid');
        return $key;
    }

    /** raw r||s (64 bytes) -> DER ECDSA signature */
    private static function derSig(string $raw): string
    {
        $int = static function (string $b): string {
            $b = ltrim($b, "\x00");
            if ($b === '' || ord($b[0]) > 127) $b = "\x00" . $b;
            return "\x02" . chr(strlen($b)) . $b;
        };
        $body = $int(substr($raw, 0, 32)) . $int(substr($raw, 32));
        return "\x30" . chr(strlen($body)) . $body;
    }

    /**
     * @param array|string $headersOrToken  request headers array, or a raw token
     * @param array $o audience, tenant_id, connector_id, idp?, tool?, jwks_url?, jwks? (array), now? (int), seen? (&array replay store)
     */
    public static function verify(array|string $headersOrToken, array $o): array
    {
        $now = (int)($o['now'] ?? time());
        $token = is_string($headersOrToken) ? trim($headersOrToken) : self::tokenFrom($headersOrToken);
        if ($token === null || $token === '') throw new BusymateActorError('missing_token');
        $parts = explode('.', $token);
        if (count($parts) !== 3) throw new BusymateActorError('malformed');
        $hdr = json_decode(self::b64d($parts[0]), true);
        if (!is_array($hdr)) throw new BusymateActorError('malformed');
        if (($hdr['alg'] ?? null) !== 'ES256') throw new BusymateActorError('bad_alg');
        if (($hdr['typ'] ?? null) !== self::TYP) throw new BusymateActorError('bad_typ');
        $kid = $hdr['kid'] ?? null;
        if (!is_string($kid) || $kid === '') throw new BusymateActorError('unknown_kid');
        $pem = self::keyFor($kid, $o['jwks'] ?? null, $o['jwks_url'] ?? self::DEFAULT_JWKS_URL);
        $raw = self::b64d($parts[2]);
        if (strlen($raw) !== 64 || openssl_verify($parts[0] . '.' . $parts[1], self::derSig($raw), $pem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new BusymateActorError('bad_signature');
        }
        $p = json_decode(self::b64d($parts[1]), true);
        if (!is_array($p)) throw new BusymateActorError('malformed');

        if (($p['iss'] ?? null) !== self::ISSUER) throw new BusymateActorError('bad_issuer');
        $aud = $p['aud'] ?? null;
        if (!($aud === $o['audience'] || (is_array($aud) && $aud === [$o['audience']]))) throw new BusymateActorError('bad_audience');
        $sub = $p['sub'] ?? null; $jti = $p['jti'] ?? null; $iat = $p['iat'] ?? null; $exp = $p['exp'] ?? null; $nbf = $p['nbf'] ?? null;
        if (!is_string($sub) || $sub === '' || !is_string($jti) || $jti === '' || !(is_int($iat) || is_float($iat)) || !(is_int($exp) || is_float($exp))) {
            throw new BusymateActorError('missing_claim');
        }
        if ($now > $exp + self::SKEW) throw new BusymateActorError('expired');
        if ($iat > $now + self::SKEW || ((is_int($nbf) || is_float($nbf)) && $nbf > $now + self::SKEW)) throw new BusymateActorError('not_yet_valid');
        if ($exp - $iat > self::MAX_LIFETIME) throw new BusymateActorError('lifetime_too_long');
        if (($p['tenant_id'] ?? null) !== $o['tenant_id']) throw new BusymateActorError('tenant_mismatch');
        if (($p['connector_id'] ?? null) !== $o['connector_id']) throw new BusymateActorError('connector_mismatch');
        if (isset($o['idp']) && ($p['idp'] ?? null) !== $o['idp']) throw new BusymateActorError('idp_mismatch');
        if (($p['actor_kind'] ?? null) !== 'identified') throw new BusymateActorError('not_identified');
        if (isset($o['tool']) && ($p['tool'] ?? null) !== $o['tool']) throw new BusymateActorError('tool_mismatch');
        $store = &self::$seen;
        if (isset($o['seen'])) $store = &$o['seen'];
        foreach ($store as $k => $e) if ($e < $now) unset($store[$k]);
        if (isset($store[$jti])) throw new BusymateActorError('replay');
        $store[$jti] = (int)$exp;
        return [
            'sub' => $sub, 'idp' => is_string($p['idp'] ?? null) ? $p['idp'] : '', 'confirmed' => ($p['confirmed'] ?? null) === true,
            'tool' => is_string($p['tool'] ?? null) ? $p['tool'] : '', 'jti' => $jti,
            'support_session_id' => is_string($p['support_session_id'] ?? null) ? $p['support_session_id'] : null,
        ];
    }

    /** Money-moving and write tools need the customer's in-chat confirmation. */
    public static function requireConfirmed(array $actor, bool $isWriteTool = true): void
    {
        if ($isWriteTool && !$actor['confirmed']) throw new BusymateActorError('confirmation_required');
    }
}
