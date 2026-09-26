<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Certificate;

use gijsbos\ApiServer\OAuth2\Components\OAuth2VerificationPolicy;

use gijsbos\Http\Exceptions\InternalServerErrorException;
use gijsbos\Http\Http\HTTPRequest;
use gijsbos\Http\Exceptions\UnauthorizedException;

use Override;

/**
 * CertificateProvider
 *  Provides the policy's keys directly, or fetches an issuer's public keys either from
 *  a JWKS URL or via OpenID Connect discovery: {issuerUri}/.well-known/openid-configuration -> jwks_uri.
 *
 *  Fetched keys are cached per keysUri / issuerUri for $CACHE_TTL_SECONDS, in process memory and in APCu (when available).
 *  - A refresh (provide() with $refresh, e.g. for an unknown "kid" after a key rotation) refetches at most
 *    once per $REFRESH_COOLDOWN_SECONDS, so tokens with made-up kids cannot make every request fetch.
 *  - A failed fetch is remembered for $FAILURE_CACHE_TTL_SECONDS, so an unreachable issuer does not make
 *    every request wait for the HTTP timeout.
 */
class CertificateProvider implements CertificateProviderInterface
{
    const WELL_KNOWN_OPEN_ID_PATH = '/.well-known/openid-configuration';

    /**
     * Time keys stay cached before a fresh fetch is forced.
     * Key rotations are normally done with an overlap window measured in
     * days, so an hour-long cache keeps request volume down without risking
     * a long window of trusting a revoked key.
     */
    public static $CACHE_TTL_SECONDS = 3600;

    /**
     * Minimum time between two fetches of the same key source, bounds the refetches a refresh can cause
     */
    public static $REFRESH_COOLDOWN_SECONDS = 60;

    /**
     * Time a failed fetch is remembered and rethrown without contacting the issuer again
     */
    public static $FAILURE_CACHE_TTL_SECONDS = 30;

    /**
     * Timeouts of a single key or discovery fetch, this blocks the request being verified
     */
    public static $HTTP_TIMEOUT_SECONDS = 5;
    public static $HTTP_CONNECT_TIMEOUT_SECONDS = 3;

    /**
     * Per-process cache, checked before APCu. Keeps long-running workers from
     * fetching on every request when APCu is not available.
     */
    private static array $memoryCache = [];

    public function __construct()
    {}

    /**
     * Namespaced per key source, so the APCu entries neither collide with other
     * applications sharing APCu nor between a keysUri and an issuerUri of the same value
     */
    private static function cacheKey(string $source, string $uri) : string
    {
        return self::class . ":$source:$uri";
    }

    private static function cacheGet(string $key) : mixed
    {
        $entry = self::$memoryCache[$key] ?? null;

        if($entry !== null && $entry["expiresAt"] > time())
            return $entry["value"];

        unset(self::$memoryCache[$key]);

        if(function_exists('apcu_fetch'))
        {
            $value = \apcu_fetch($key, $success);

            if($success)
                return $value;
        }

        return null;
    }

    private static function cacheSet(string $key, mixed $value, int $ttl) : void
    {
        // A ttl of 0 disables the entry; APCu would read 0 as "never expires"
        if($ttl <= 0)
        {
            unset(self::$memoryCache[$key]);

            if(function_exists('apcu_delete'))
                \apcu_delete($key);

            return;
        }

        self::$memoryCache[$key] = ["value" => $value, "expiresAt" => time() + $ttl];

        if(function_exists('apcu_store'))
            \apcu_store($key, $value, $ttl);
    }

    /**
     * cacheAdd
     *  Stores only when the key is not set yet, returns whether it stored. Atomic across processes with APCu.
     */
    private static function cacheAdd(string $key, mixed $value, int $ttl) : bool
    {
        if($ttl <= 0)
            return true;

        $entry = self::$memoryCache[$key] ?? null;

        if($entry !== null && $entry["expiresAt"] > time())
            return false;

        if(function_exists('apcu_add') && !\apcu_add($key, $value, $ttl))
            return false;

        self::$memoryCache[$key] = ["value" => $value, "expiresAt" => time() + $ttl];

        return true;
    }

    /**
     * clearCache
     *  Drops all cached keys, failures and refresh cooldowns of this provider
     */
    public static function clearCache() : void
    {
        self::$memoryCache = [];

        if(class_exists('APCUIterator') && function_exists('apcu_delete'))
            \apcu_delete(new \APCUIterator('/^' . preg_quote(self::class . ":", '/') . '/'));
    }

    /**
     * fetchJson
     *  GETs $uri and returns the decoded JSON object, null when the request fails or the body is not an object
     */
    protected function fetchJson(string $uri) : null|array
    {
        $response = HTTPRequest::get([
            "uri" => $uri,
            "options" => [
                CURLOPT_TIMEOUT => self::$HTTP_TIMEOUT_SECONDS,
                CURLOPT_CONNECTTIMEOUT => self::$HTTP_CONNECT_TIMEOUT_SECONDS,
            ],
        ]);

        if(!$response->isSuccessful())
            return null;

        $data = $response->getParameters();

        return is_array($data) ? $data : null;
    }

    private function fetchKeysFromKeysUri(string $keysUri) : array
    {
        $data = $this->fetchJson($keysUri);

        if($data === null)
            throw new UnauthorizedException("tokenKeysUnavailable", "Could not retrieve public keys from \"$keysUri\"");

        if(!CertificateSet::arrayIsCertificateSet($data))
            throw new UnauthorizedException("tokenKeysUnavailable", "Public keys response from \"$keysUri\" did not contain a \"keys\" array");

        return ["keys" => $data["keys"]];
    }

    private function resolveKeysUriFromIssuerUri(string $issuerUri) : string
    {
        $wellKnownUri = rtrim($issuerUri, '/') . self::WELL_KNOWN_OPEN_ID_PATH;

        $data = $this->fetchJson($wellKnownUri);

        if($data === null)
            throw new UnauthorizedException("tokenIssuerUnavailable", "Could not retrieve OpenID configuration from \"$wellKnownUri\"");

        // OpenID Connect Discovery §4.3 / RFC 8414 §3.3: the document must be for the issuer it was fetched for.
        // A trailing slash is tolerated, as it is when building $wellKnownUri.
        $issuer = $data["issuer"] ?? null;

        if(!is_string($issuer) || rtrim($issuer, '/') !== rtrim($issuerUri, '/'))
            throw new UnauthorizedException("tokenIssuerUnavailable", "OpenID configuration at \"$wellKnownUri\" is not for issuer \"$issuerUri\"");

        $jwksUri = $data["jwks_uri"] ?? null;

        if(!is_string($jwksUri) || strlen($jwksUri) == 0)
            throw new UnauthorizedException("tokenIssuerUnavailable", "OpenID configuration at \"$wellKnownUri\" is missing \"jwks_uri\"");

        return $jwksUri;
    }

    /**
     * provideFetched
     *  Serves the keys of $cacheKey from cache, or fetches them with $fetch
     */
    private function provideFetched(string $cacheKey, callable $fetch, bool $refresh) : CertificateSet
    {
        $cachedKeysData = self::cacheGet("$cacheKey:keys");

        // A refresh only refetches when no fetch of this source happened within the cooldown
        if(is_array($cachedKeysData) && !($refresh && self::cacheAdd("$cacheKey:fetched", true, self::$REFRESH_COOLDOWN_SECONDS)))
            return CertificateSet::createFromArray($cachedKeysData);

        if(!is_array($cachedKeysData))
        {
            $failure = self::cacheGet("$cacheKey:failure");

            if(is_array($failure))
                throw new UnauthorizedException($failure["error"], $failure["errorDescription"]);
        }

        try
        {
            $certificateData = $fetch();
        }
        catch(UnauthorizedException $ex)
        {
            // A failed refresh keeps serving the keys that are known
            if(is_array($cachedKeysData))
                return CertificateSet::createFromArray($cachedKeysData);

            self::cacheSet("$cacheKey:failure", ["error" => $ex->getError(), "errorDescription" => $ex->getErrorDescription()], self::$FAILURE_CACHE_TTL_SECONDS);

            throw $ex;
        }

        self::cacheSet("$cacheKey:keys", $certificateData, self::$CACHE_TTL_SECONDS);
        self::cacheSet("$cacheKey:fetched", true, self::$REFRESH_COOLDOWN_SECONDS);

        return CertificateSet::createFromArray($certificateData);
    }

    #[Override]
    public function provide(OAuth2VerificationPolicy $oAuth2VerificationPolicy, bool $refresh = false) : CertificateSet
    {
        if($oAuth2VerificationPolicy->issuerUri === null && $oAuth2VerificationPolicy->keysUri === null && $oAuth2VerificationPolicy->keys === null)
            throw new \InvalidArgumentException("OAuth2VerificationPolicy requires at least one of \"keys\", \"keysUri\" or \"issuerUri\"");

        if($oAuth2VerificationPolicy->keys !== null)
        {
            return CertificateSet::createFromArray($oAuth2VerificationPolicy->keys);
        }

        if($oAuth2VerificationPolicy->keysUri)
        {
            $keysUri = $oAuth2VerificationPolicy->keysUri;

            return $this->provideFetched(self::cacheKey("keysUri", $keysUri), fn() => $this->fetchKeysFromKeysUri($keysUri), $refresh);
        }

        if($oAuth2VerificationPolicy->issuerUri)
        {
            $issuerUri = $oAuth2VerificationPolicy->issuerUri;

            return $this->provideFetched(
                self::cacheKey("issuerUri", $issuerUri),
                fn() => $this->fetchKeysFromKeysUri($this->resolveKeysUriFromIssuerUri($issuerUri)),
                $refresh
            );
        }

        throw new InternalServerErrorException("certificateProviderMisconfigured", "No certificate has been configured");
    }
}
