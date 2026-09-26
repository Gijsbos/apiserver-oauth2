<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Certificate;

use gijsbos\ApiServer\OAuth2\Components\OAuth2VerificationPolicy;

/**
 * CertificateProviderInterface
 */
interface CertificateProviderInterface
{
    /**
     * Returns an available certificate set used for either signing or token verification.
     * This interface is not intended for creating new certificates.
     *
     * $refresh asks to bypass cached keys, AccessTokenVerifier passes it when a token's "kid" is not in
     * the provided set (e.g. after a key rotation). Implementations may rate limit or ignore it.
     */
    public function provide(OAuth2VerificationPolicy $oAuth2VerificationPolicy, bool $refresh = false) : CertificateSet;
}