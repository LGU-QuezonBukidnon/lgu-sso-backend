<?php

namespace App\Support;

use App\Models\Application;

/** Compatibility for the existing dedicated developer migration. */
final class ConnectDeveloperDesktopGrants
{
    public static function enabledFor(Application $application): bool
    {
        return ConnectDesktopGrants::Developer->enabledFor($application);
    }
}
