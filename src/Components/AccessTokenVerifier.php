<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use InvalidArgumentException;

use gijsbos\Http\Exceptions\ForbiddenException;
use gijsbos\Http\Exceptions\UnauthorizedException;

use gijsbos\ApiServer\OAuth2\Certificate\CertificateProviderInterface;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimExceptionInterface;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

use Psr\Clock\ClockInterface;

/**
 * AccessTokenVerifier
 */
class AccessTokenVerifier
{
    public function __construct(
        private CertificateProviderInterface $certificateProvider,
        private ClockInterface $clock = new SystemClock()
    )
    { }

    private function unserialize(string $accessToken) : JWS
    {
        try
        {
            return (new CompactSerializer())->unserialize($accessToken);
        }
        catch(InvalidArgumentException $ex)
        {
            throw new UnauthorizedException("tokenInvalid", "Access token is not a valid JWT");
        }
    }

    private function checkHeader(AccessTokenVerificationPolicy $accessTokenVerificationPolicy, JWS $jws) : void
    {
        $mandatory = $accessTokenVerificationPolicy->kidRequired ? ["alg", "kid"] : ["alg"];

        $algorithmNames = array_map(fn(Algorithm $algorithm) => $algorithm->name(), $accessTokenVerificationPolicy->allowedAlgorithms);

        $headerCheckerManager = new HeaderCheckerManager(
            [new AlgorithmChecker($algorithmNames)],
            [new JWSTokenSupport()]
        );

        try
        {
            $headerCheckerManager->check($jws, 0, $mandatory);
        }
        catch(MissingMandatoryHeaderParameterException | InvalidHeaderException $ex)
        {
            throw new UnauthorizedException("tokenHeaderInvalid", $ex->getMessage());
        }
    }

    private function verifySignature(AccessTokenVerificationPolicy $accessTokenVerificationPolicy, JWS $jws) : void
    {
        $signature = $jws->getSignature(0);
        $kid = $signature->hasProtectedHeaderParameter("kid") ? $signature->getProtectedHeaderParameter("kid") : null;

        $jwsVerifier = new JWSVerifier(
            new AlgorithmManager($accessTokenVerificationPolicy->allowedAlgorithms)
        );

        if(is_string($kid))
        {
            try
            {
                $jwk = $this->certificateProvider->provide($accessTokenVerificationPolicy)->toJWKSet()->get($kid);
            }
            catch(InvalidArgumentException $ex)
            {
                throw new UnauthorizedException("tokenKeyNotFound", "No public key found for the given \"kid\"");
            }

            $isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);
        }
        else
        {
            try
            {
                $jwkSet = $this->certificateProvider->provide($accessTokenVerificationPolicy)->toJWKSet();

                $isVerified = $jwsVerifier->verifyWithKeySet($jws, $jwkSet, 0);
            }
            catch(InvalidArgumentException $ex)
            {
                throw new UnauthorizedException("tokenKeyInvalid", "The public keys could not be used to verify the access token");
            }
        }

        if(!$isVerified)
            throw new UnauthorizedException("tokenInvalid", "Access token signature is invalid");
    }

    private function checkClaims(AccessTokenVerificationPolicy $accessTokenVerificationPolicy, array $payload) : void
    {
        $checkers = [
            new ExpirationTimeChecker($this->clock),
            new NotBeforeChecker($this->clock),
        ];

        $mandatory = ["exp"];

        if($accessTokenVerificationPolicy->issuerUri !== null)
        {
            $checkers[] = new IssuerChecker([$accessTokenVerificationPolicy->issuerUri]);
            $mandatory[] = "iss";
        }

        if($accessTokenVerificationPolicy->audience !== null)
        {
            $checkers[] = new AudienceChecker($accessTokenVerificationPolicy->audience);
            $mandatory[] = "aud";
        }

        $claimCheckerManager = new ClaimCheckerManager($checkers);

        try
        {
            $claimCheckerManager->check($payload, $mandatory);
        }
        catch(ClaimExceptionInterface $ex)
        {
            throw new UnauthorizedException("tokenPayloadInvalid", $ex->getMessage());
        }
    }

    /**
     * verifyHasAuthority
     *  $error/$errorDescription default to "insufficientScope", the camelCase form of
     *  RFC 6750 §3.1's "insufficient_scope", the correct code when checking OAuth2
     *  scopes. Callers checking something outside the OAuth2 spec (e.g. app-level
     *  roles) should pass their own, since there is no RFC-standard code for that case.
     */
    public static function verifyHasAuthority(
        array $permissions,
        array $requiredAuthority,
        string $error = "insufficientScope",
        string $errorDescription = "The request requires higher privileges than provided by the access token"
    ) : void
    {
        // Strict comparison, and "" never counts: loose in_array() lets e.g. true match any string,
        // and an empty entry on both sides (from a double space or a trailing comma) must not grant access
        foreach($permissions as $permission)
            if($permission !== "" && in_array($permission, $requiredAuthority, true))
                return;

        throw new ForbiddenException($error, $errorDescription);
    }

    public function verify(AccessTokenVerificationPolicy $accessTokenVerificationPolicy, string $accessToken) : array
    {
        $jws = $this->unserialize($accessToken);

        $this->checkHeader($accessTokenVerificationPolicy, $jws);

        $this->verifySignature($accessTokenVerificationPolicy, $jws);

        $payload = json_decode($jws->getPayload() ?? "", true);

        if(!is_array($payload))
            throw new UnauthorizedException("tokenPayloadInvalid", "Access token payload is not a JSON object");

        $this->checkClaims($accessTokenVerificationPolicy, $payload);

        return $payload;
    }
}
