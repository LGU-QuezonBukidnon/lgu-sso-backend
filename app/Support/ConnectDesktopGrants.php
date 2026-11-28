<?php

namespace App\Support;

use App\Enums\AppRole;
use App\Models\Application;
use App\Models\Employee;
use App\Models\OAuthToken;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use RuntimeException;

enum ConnectDesktopGrants: string
{
    case Developer = 'developer';
    case Production = 'production';

    public function callback(): string
    {
        return match ($this) {
            self::Developer => 'https://connect.lgu.lan/auth/sso/callback',
            self::Production => 'https://connect.lguquezon.local/auth/sso/callback',
        };
    }

    public function view(): string
    {
        return match ($this) {
            self::Developer => 'connect_developer_authority.connect_developer_desktop_authorizations',
            self::Production => 'connect_production_authority.connect_desktop_authorizations',
        };
    }

    public function enabledFor(Application $application): bool
    {
        $issuerMatches = match ($this) {
            self::Developer => app()->environment('local', 'testing') && config('app.url') === 'https://sso.lgu.lan',
            self::Production => app()->environment('production') && config('app.url') === 'https://api.sso.lguquezon.local',
        };
        $client = config("sso.{$this->value}_desktop_client_id");

        return $issuerMatches && $application->is_active && is_string($client) && $client !== ''
            && hash_equals($client, $application->client_id)
            && in_array($this->callback(), $application->redirect_uris ?? [], true);
    }

    public static function forApplication(Application $application): ?self
    {
        foreach (self::cases() as $edition) {
            if ($edition->enabledFor($application)) {
                return $edition;
            }
        }

        return null;
    }

    /** Issued only while the verified exchange still holds the employee and application locks. */
    public function issue(OAuthToken $token, Application $application, Employee $employee): array
    {
        $minutes = config("sso.{$this->value}_desktop_ttl_minutes");
        if ($minutes !== null && filter_var($minutes, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 525600],
        ]) === false) {
            throw new RuntimeException('Invalid desktop grant lifetime.');
        }
        $expires = $minutes === null ? null : now()->utc()->addMinutes((int) $minutes);
        $assignment = DB::table('employee_application')->where('application_id', $application->id)
            ->where('employee_id', $employee->id)->sharedLock()->first(['id', 'role']);
        abort_unless($assignment && in_array($assignment->role, [AppRole::Standard->value, AppRole::Administrator->value, AppRole::SuperAdministrator->value], true), 403);
        $id = (string) Str::uuid();
        DB::table("connect_{$this->value}_desktop_grants")->insert([
            'id' => $id,
            'oauth_token_id' => $token->id,
            'assignment_id' => $assignment->id,
            'employee_id' => $employee->id,
            'application_id' => $application->id,
            'employee_uuid' => $employee->uuid,
            'client_id' => $application->client_id,
            'role' => $assignment->role,
            'expires_at' => $expires,
        ]);

        // The separately installed read surface is published only after every revocation trigger.
        if (! DB::table($this->view())->where('grant_id', $id)->exists()) {
            throw new RuntimeException('Desktop grant was not activated by SSO.');
        }

        return ['id' => $id, 'expires_at' => $expires?->toIso8601String()];
    }

    public function revoke(Application $application, string $id): void
    {
        $tokenId = DB::table("connect_{$this->value}_desktop_grants")->where('id', $id)
            ->where('application_id', $application->id)->value('oauth_token_id');
        if ($tokenId !== null) {
            OAuthToken::whereKey($tokenId)->where('application_id', $application->id)
                ->whereNull('revoked_at')->update(['revoked_at' => now()]);
        }
    }
}
