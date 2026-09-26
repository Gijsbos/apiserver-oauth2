<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use InvalidArgumentException;

use gijsbos\Http\Exceptions\ForbiddenException;
use gijsbos\Http\Exceptions\UnauthorizedException;

use gijsbos\ApiServer\OAuth2\Certificate\CertificateProviderInterface;
use gijsbos\ApiServer\OAuth2\Interfaces\AccessTokenVerifierInterface;
use gijsbos\ApiServer\OAuth2\ValueObjects\JwtPayload;
use gijsbos\ApiServer\OAuth2\ValueObjects\TokenPayload;
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
class AccessTokenVerifier implements AccessTokenVerifierInterface
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
            $jws = (new CompactSerializer())->unserialize($accessToken);
        }
        catch(InvalidArgumentException $ex)
        {
            throw new UnauthorizedException("tokenInvalid", "Access token is not a valid JWT");
        }

        // An empty payload segment is a detached-payload JWS, which JWSVerifier rejects by throwing rather than returning false
        if($jws->getPayload() === null || $jws->getPayload() === "")
            throw new UnauthorizedException("tokenInvalid", "Access token is not a valid JWT");

        return $jws;
    }

    private function checkHeader(OAuth2VerificationPolicy $oAuth2VerificationPolicy, JWS $jws) : void
    {
        $mandatory = $oAuth2VerificationPolicy->kidRequired ? ["alg", "kid"] : ["alg"];

        $algorithmNames = array_map(fn(Algorithm $algorithm) => $algorithm->name(), $oAuth2VerificationPolicy->allowedAlgorithms);

        $headerCheckerManager = new HeaderCheckerManager(
            [new AlgorithmChecker($algorithmNames, true)],
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

    private function verifySignature(OAuth2VerificationPolicy $oAuth2VerificationPolicy, JWS $jws) : void
    {
        $signature = $jws->getSignature(0);
        $kid = $signature->hasProtectedHeaderParameter("kid") ? $signature->getProtectedHeaderParameter("kid") : null;

        $jwsVerifier = new JWSVerifier(
            new AlgorithmManager($oAuth2VerificationPolicy->allowedAlgorithms)
        );

        // Outside the try blocks below: a misconfigured policy must surface as a server error, not as a rejected token
        $certificateSet = $this->certificateProvider->provide($oAuth2VerificationPolicy);

        if(is_string($kid))
        {
            // An unknown kid may be a key the issuer rotated in after the set was cached
            if(!$certificateSet->hasKid($kid))
                $certificateSet = $this->certificateProvider->provide($oAuth2VerificationPolicy, true);

            try
            {
                $jwk = $certificateSet->toJWKSet()->get($kid);
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
                $jwkSet = $certificateSet->toJWKSet();

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

    private function checkClaims(OAuth2VerificationPolicy $oAuth2VerificationPolicy, array $payload) : void
    {
        $checkers = [
            new ExpirationTimeChecker($this->clock),
            new NotBeforeChecker($this->clock),
        ];

        $mandatory = ["exp"];

        if($oAuth2VerificationPolicy->issuerUri !== null)
        {
            $checkers[] = new IssuerChecker([$oAuth2VerificationPolicy->issuerUri]);
            $mandatory[] = "iss";
        }

        if($oAuth2VerificationPolicy->audience !== null)
        {
            $checkers[] = new AudienceChecker($oAuth2VerificationPolicy->audience);
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

    public function verify(OAuth2VerificationPolicy $oAuth2VerificationPolicy, string $accessToken) : TokenPayload
    {
        $jws = $this->unserialize($accessToken);

        $this->checkHeader($oAuth2VerificationPolicy, $jws);

        $this->verifySignature($oAuth2VerificationPolicy, $jws);

        $payload = json_decode($jws->getPayload() ?? "", true);

        if(!is_array($payload))
            throw new UnauthorizedException("tokenPayloadInvalid", "Access token payload is not a JSON object");

        $this->checkClaims($oAuth2VerificationPolicy, $payload);

        try
        {
            return TokenPayload::createFromArray($payload);
        }
        catch(InvalidArgumentException $ex)
        {
            throw new UnauthorizedException("tokenPayloadInvalid", $ex->getMessage());
        }
    }
}
