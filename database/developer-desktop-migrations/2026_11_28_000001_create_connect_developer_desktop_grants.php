<?php

use App\Models\Application;
use App\Support\ConnectDeveloperDesktopGrants;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    private const VIEW = 'connect_developer_authority.connect_developer_desktop_authorizations';

    public function up(): void
    {
        if (! app()->environment('local', 'testing') || DB::getDriverName() !== 'mysql') {
            throw new RuntimeException('The developer desktop authority can be installed only on local MySQL.');
        }
        $application = Application::where('client_id', config('sso.developer_desktop_client_id'))->where('is_active', true)->first();
        if (! $application || ! ConnectDeveloperDesktopGrants::enabledFor($application)) {
            throw new RuntimeException('Enable the local Connect Developer client and register its exact callback before installing the desktop authority.');
        }
        if (! Schema::hasTable('connect_developer_desktop_grants')) {
            Schema::create('connect_developer_desktop_grants', function (Blueprint $table) {
                $table->uuid('id')->primary();
                $table->foreignId('oauth_token_id')->unique()->constrained('oauth_tokens')->cascadeOnDelete();
                $table->foreignId('assignment_id')->constrained('employee_application')->cascadeOnDelete();
                $table->unsignedBigInteger('employee_id')->index();
                $table->unsignedBigInteger('application_id')->index();
                $table->uuid('employee_uuid');
                $table->string('client_id', 80);
                $table->string('role');
                $table->dateTime('expires_at')->nullable();
                $table->dateTime('revoked_at')->nullable();
            });
        }
        $id = (int) $application->id;
        // Create triggers before publishing the read view. Rerunning after interrupted DDL
        // never drops a live revocation trigger or exposes a partly installed projection.
        $this->onUpdate('employees', <<<'SQL'
            IF NEW.is_active = 0 OR NEW.must_change_password = 1 OR NEW.deleted_at IS NOT NULL
                OR BINARY NEW.uuid <> BINARY OLD.uuid OR BINARY NEW.password <> BINARY OLD.password THEN
                UPDATE connect_developer_desktop_grants SET revoked_at = UTC_TIMESTAMP()
                WHERE employee_id = OLD.id AND revoked_at IS NULL;
            END IF;
            SQL);
        $this->onUpdate('applications', <<<SQL
            IF OLD.id = $id AND (NEW.is_active = 0 OR NEW.deleted_at IS NOT NULL
                OR BINARY NEW.client_secret <> BINARY OLD.client_secret OR BINARY NEW.client_id <> BINARY OLD.client_id
                OR BINARY NEW.uuid <> BINARY OLD.uuid OR NOT COALESCE(JSON_CONTAINS(NEW.redirect_uris, JSON_QUOTE('https://connect.lgu.lan/auth/sso/callback')), 0)) THEN
                UPDATE connect_developer_desktop_grants SET revoked_at = UTC_TIMESTAMP()
                WHERE application_id = OLD.id AND revoked_at IS NULL;
            END IF;
            SQL);
        $this->onUpdate('oauth_tokens', <<<SQL
            IF OLD.application_id = $id AND (NEW.revoked_at IS NOT NULL OR NOT (OLD.application_id <=> NEW.application_id)
                OR OLD.employee_id <> NEW.employee_id OR BINARY OLD.access_token <> BINARY NEW.access_token) THEN
                UPDATE connect_developer_desktop_grants SET revoked_at = UTC_TIMESTAMP()
                WHERE oauth_token_id = OLD.id AND revoked_at IS NULL;
            END IF;
            SQL);
        $this->onUpdate('employee_application', <<<SQL
            IF OLD.application_id = $id THEN
                IF OLD.employee_id <> NEW.employee_id OR OLD.application_id <> NEW.application_id
                    OR BINARY NEW.role NOT IN ('standard','administrator','super_administrator') THEN
                    UPDATE connect_developer_desktop_grants SET revoked_at = UTC_TIMESTAMP()
                    WHERE assignment_id = OLD.id AND revoked_at IS NULL;
                ELSEIF BINARY OLD.role <> BINARY NEW.role THEN
                    UPDATE connect_developer_desktop_grants SET role = NEW.role
                    WHERE assignment_id = OLD.id AND revoked_at IS NULL;
                END IF;
            END IF;
            SQL);

        $source = str_replace('`', '``', DB::getDatabaseName());
        DB::statement('CREATE OR REPLACE ALGORITHM=MERGE SQL SECURITY DEFINER VIEW '.self::VIEW." AS
            SELECT id AS grant_id, client_id, employee_uuid, role, expires_at
            FROM `$source`.connect_developer_desktop_grants
            WHERE application_id = $id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())");
    }

    private function onUpdate(string $source, string $body): void
    {
        $name = 'connect_developer_desktop_'.$source.'_updated';
        $statement = "BEGIN $body END";
        $existing = DB::table('information_schema.TRIGGERS')->where('TRIGGER_SCHEMA', DB::getDatabaseName())
            ->where('TRIGGER_NAME', $name)->value('ACTION_STATEMENT');
        if ($existing === null) {
            DB::unprepared("CREATE TRIGGER $name AFTER UPDATE ON $source FOR EACH ROW $statement");
        } elseif ($existing !== $statement) {
            throw new RuntimeException('The installed desktop trigger differs from this client or release. Reprovision the developer authority before re-enabling it.');
        }
    }

    public function down(): void
    {
        DB::statement('DROP VIEW IF EXISTS '.self::VIEW);
        foreach (['employees', 'applications', 'oauth_tokens', 'employee_application'] as $source) {
            DB::statement('DROP TRIGGER IF EXISTS connect_developer_desktop_'.$source.'_updated');
        }
        Schema::dropIfExists('connect_developer_desktop_grants');
    }
};
