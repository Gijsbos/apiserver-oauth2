<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * SystemClock
 *  Minimal PSR-20 clock backed by the system time, since only the
 *  interface (psr/clock) is vendored here, not an implementation. It is the
 *  AccessTokenVerifier default; pass any other Psr\Clock\ClockInterface to
 *  the verifier to control time (e.g. a frozen clock in tests).
 */
final class SystemClock implements ClockInterface
{
    public function now() : DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
