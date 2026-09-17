<?php
declare(strict_types=1);

namespace gijsbos\ApiServer\OAuth2\Components;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * SystemClock
 *  Minimal PSR-20 clock backed by the system time, since only the
 *  interface (psr/clock) is vendored here, not an implementation.
 */
final class SystemClock implements ClockInterface
{
    public function now() : DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
