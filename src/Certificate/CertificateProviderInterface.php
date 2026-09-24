<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Certificate;

use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;

/**
 * CertificateProviderInterface
 */
interface CertificateProviderInterface
{
    /**
     * Returns an available certificate set used for either signing or token verification.
     * This interface is not intended for creating new certificates.
     */
    public function provide(AccessTokenVerificationPolicy $accessTokenVerificationPolicy) : CertificateSet;
}