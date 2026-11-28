<?php

use App\Enums\AppRole;
use App\Models\Application;
use App\Models\Employee;
use App\Models\OAuthToken;
use App\Support\ConnectDesktopGrants;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

beforeEach(function () {
    if (getenv('SSO_DESKTOP_AUTHORITY_DISPOSABLE_MYSQL') !== '1') {
        $this->markTestSkipped('Requires the isolated MySQL desktop authority fixture.');
    }
    expect(DB::getDriverName())->toBe('mysql');
    expect(DB::getDatabaseName())->toBe('desktop_authority_fixture');
    $this->artisan('migrate:fresh', ['--force' => true])->assertSuccessful();
    $this->edition = ConnectDesktopGrants::from(getenv('SSO_DESKTOP_AUTHORITY_FIXTURE_EDITION'));
    $this->production = $this->edition === ConnectDesktopGrants::Production;
    $this->environment = $this->production ? 'production' : 'local';
    $this->issuer = $this->production ? 'https://api.sso.lguquezon.local' : 'https://sso.lgu.lan';
    $this->callback = $this->production ? 'https://connect.lguquezon.local/auth/sso/callback' : 'https://connect.lgu.lan/auth/sso/callback';
    $this->clientId = $this->edition->value.'-client';
    $this->clientConfig = 'sso.'.$this->edition->value.'_desktop_client_id';
    $this->ttlConfig = 'sso.'.$this->edition->value.'_desktop_ttl_minutes';
    $this->viewName = $this->production ? 'connect_production_authority.connect_desktop_authorizations' : 'connect_developer_authority.connect_developer_desktop_authorizations';
    $this->grantsTable = 'connect_'.$this->edition->value.'_desktop_grants';
    $this->migrationFile = $this->production
        ? 'production-desktop-migrations/2026_11_28_000002_create_connect_production_desktop_grants.php'
        : 'developer-desktop-migrations/2026_11_28_000001_create_connect_developer_desktop_grants.php';
    $this->app->instance('env', $this->environment);
    config(['app.url' => $this->issuer, $this->clientConfig => $this->clientId, 'jwt.ttl' => 1440]);
    $this->employee = Employee::factory()->create();
    $this->application = Application::factory()->create([
        'client_id' => $this->clientId, 'client_secret' => Hash::make('fixture-secret'),
        'redirect_uris' => [$this->callback],
    ]);
    $this->employee->applications()->attach($this->application->id, ['role' => AppRole::Standard->value]);
    $this->migration = require database_path($this->migrationFile);
    $this->migration->up();
    $this->clientHeaders = ['X-Client-ID' => $this->clientId, 'X-Client-Secret' => 'fixture-secret'];
    $this->sourceToken = $this->issueSsoToken($this->employee);
    $this->exchange = function (array $opt = ['desktop_delegation' => true]) {
        $payload = ['client_id' => $this->clientId, 'redirect_uri' => $this->callback];
        $code = $this->withToken($this->sourceToken)->postJson('/api/v1/sso/code', $payload)->assertOk()->json('code');

        return $this->postJson('/api/v1/sso/exchange', ['code' => $code, 'redirect_uri' => $payload['redirect_uri']] + $opt, $this->clientHeaders);
    };
    $this->lookup = fn (string $id) => DB::table($this->viewName)->where('grant_id', $id)->first();
});

afterEach(function () {
    if (isset($this->migration)) {
        $this->migration->down();
    }
});

it('only offers scoped delegation to the registered client at its exact issuer and callback', function () {
    ($this->exchange)([])->assertOk()->assertJsonMissingPath('desktop_delegation');
    ($this->exchange)(['desktop_delegation' => 'true'])->assertUnprocessable();
    config([$this->clientConfig => null]);
    ($this->exchange)()->assertForbidden();
    config([$this->clientConfig => 'other-app']);
    ($this->exchange)()->assertForbidden();
    config([$this->clientConfig => $this->clientId]);
    $this->app->instance('env', $this->production ? 'local' : 'production');
    ($this->exchange)()->assertForbidden();
    $this->app->instance('env', $this->environment);
    config(['app.url' => $this->production ? 'https://sso.lgu.lan' : 'https://api.sso.lguquezon.local']);
    ($this->exchange)()->assertForbidden();
    config(['app.url' => $this->issuer]);
    $otherUri = $this->production ? 'https://connect.lgu.lan/auth/sso/callback' : 'https://connect.lguquezon.local/auth/sso/callback';
    $this->application->update(['redirect_uris' => [$this->callback, $otherUri]]);
    $code = $this->withToken($this->sourceToken)->postJson('/api/v1/sso/code', ['client_id' => $this->clientId, 'redirect_uri' => $otherUri])->assertOk()->json('code');
    $this->postJson('/api/v1/sso/exchange', ['code' => $code, 'redirect_uri' => $otherUri, 'desktop_delegation' => true], $this->clientHeaders)->assertForbidden();
    expect(DB::table($this->grantsTable)->count())->toBe(0);
});

it('keeps the grant beyond ordinary JWT expiry and revokes only its device on explicit logout', function () {
    $result = ($this->exchange)()->assertOk();
    $first = $result->json('desktop_delegation.id');
    $result->assertJsonPath('desktop_delegation.expires_at', null)->assertHeader('Cache-Control', 'no-store, private');
    $second = ($this->exchange)()->assertOk()->json('desktop_delegation.id');
    $this->travel(2)->days();
    $this->postJson('/api/v1/sso/authorize', ['token' => $result->json('access_token')], $this->clientHeaders)->assertUnauthorized();
    $row = ($this->lookup)($first);
    expect(array_keys((array) $row))->toBe(['grant_id', 'client_id', 'employee_uuid', 'role', 'expires_at']);
    expect($row->employee_uuid)->toBe($this->employee->uuid);
    expect($row->role)->toBe('standard');
    Application::factory()->create(['client_id' => 'another-client', 'client_secret' => Hash::make('other-secret')]);
    $url = '/api/v1/sso/desktop-delegations/'.$first.'/revoke';
    $this->postJson($url, [], ['X-Client-ID' => 'another-client', 'X-Client-Secret' => 'other-secret'])->assertForbidden();
    $this->postJson($url, [], $this->clientHeaders)->assertNoContent();
    $this->postJson($url, [], $this->clientHeaders)->assertNoContent();
    expect(($this->lookup)($first))->toBeNull();
    expect(($this->lookup)($second))->not->toBeNull();
});

it('uses the authority clock for explicit expiry and fails closed if expired token rows are pruned', function () {
    config([$this->ttlConfig => 1]);
    $result = ($this->exchange)()->assertOk();
    $id = $result->json('desktop_delegation.id');
    expect($result->json('desktop_delegation.expires_at'))->toBeString();
    DB::table($this->grantsTable)->where('id', $id)->update(['expires_at' => DB::raw('UTC_TIMESTAMP()')]);
    expect(($this->lookup)($id))->toBeNull();
    config([$this->ttlConfig => null]);
    $more = ($this->exchange)()->assertOk();
    OAuthToken::where('access_token', hash('sha256', $more->json('access_token')))->delete();
    expect(($this->lookup)($more->json('desktop_delegation.id')))->toBeNull();
});

it('reads only one projected row and observes transactional role changes and rollback', function () {
    $id = ($this->exchange)()->assertOk()->json('desktop_delegation.id');
    $headers = DB::select("EXPLAIN SELECT * FROM {$this->viewName} WHERE grant_id=? AND client_id=? AND employee_uuid=?", [$id, $this->application->client_id, $this->employee->uuid]);
    expect($headers)->toHaveCount(1);
    expect($headers[0]->table)->toBe($this->grantsTable);
    expect($headers[0]->key)->toBe('PRIMARY');
    expect((int) $headers[0]->rows)->toBe(1);
    $pivot = DB::table('employee_application')->where('application_id', $this->application->id)->where('employee_id', $this->employee->id);
    DB::beginTransaction();
    $pivot->update(['role' => 'administrator']);
    expect(($this->lookup)($id)->role)->toBe('administrator');
    DB::rollBack();
    expect(($this->lookup)($id)->role)->toBe('standard');
    $pivot->update(['role' => 'administrator']);
    expect(($this->lookup)($id)->role)->toBe('administrator');
    $pivot->update(['role' => 'guest']);
    expect(($this->lookup)($id))->toBeNull();
    $pivot->update(['role' => 'super_administrator']);
    expect(($this->lookup)($id))->toBeNull();
});

it('invalidates permanently on direct updates, deletes, and global logout', function (string $reason) {
    $result = ($this->exchange)()->assertOk();
    $id = $result->json('desktop_delegation.id');
    $employee = DB::table('employees')->where('id', $this->employee->id);
    $app = DB::table('applications')->where('id', $this->application->id);
    $token = DB::table('oauth_tokens')->where('access_token', hash('sha256', $result->json('access_token')));
    switch ($reason) {
        case 'account':
            $employee->update(['is_active' => false]);
            $employee->update(['is_active' => true]);
            break;
        case 'password reset':
            $employee->update(['must_change_password' => true]);
            $employee->update(['must_change_password' => false]);
            break;
        case 'application':
            $app->update(['is_active' => false]);
            $app->update(['is_active' => true]);
            break;
        case 'credential rotation':
            $this->application->generateNewSecret();
            break;
        case 'unregistered callback':
            $app->update(['redirect_uris' => '[]']);
            break;
        case 'assignment':
            $this->employee->revokeApplicationAccess($this->application);
            $this->employee->applications()->attach($this->application->id, ['role' => 'standard']);
            break;
        case 'raw removal':
            $this->employee->applications()->detach($this->application->id);
            $this->employee->applications()->attach($this->application->id, ['role' => 'standard']);
            break;
        case 'token':
            $token->update(['revoked_at' => now()]);
            $token->update(['revoked_at' => null]);
            break;
        case 'global logout':
            $this->travel(2)->days();
            $freshPortal = $this->issueSsoToken($this->employee);
            $this->withToken($freshPortal)->postJson('/api/v1/auth/logout-all')->assertOk();
            break;
        case 'source deletion':
            $app->delete();
            break;
    }
    expect(($this->lookup)($id))->toBeNull();
})->with(['account', 'password reset', 'application', 'credential rotation', 'unregistered callback', 'assignment', 'raw removal', 'token', 'global logout', 'source deletion']);

it('can retry the same install but rejects a replacement application with the same client id', function () {
    $this->migration->up();
    $grant = ($this->exchange)()->assertOk()->json('desktop_delegation.id');
    $this->application->update(['client_id' => 'retired-client']);
    $replacement = Application::factory()->create([
        'client_id' => $this->clientId, 'client_secret' => Hash::make('fixture-secret'),
        'redirect_uris' => [$this->callback],
    ]);
    $this->employee->applications()->attach($replacement->id, ['role' => 'standard']);
    ($this->exchange)()->assertServerError();
    expect(($this->lookup)($grant))->toBeNull();
    expect(DB::table($this->grantsTable)->where('application_id', $replacement->id)->exists())->toBeFalse();
    expect(fn () => $this->migration->up())->toThrow(RuntimeException::class, 'installed desktop trigger differs');
});

it('lets the dedicated reader see only the published columns and observe committed revocation', function () {
    $id = ($this->exchange)()->assertOk()->json('desktop_delegation.id');
    [$database, $viewName] = explode('.', $this->viewName);
    $other = $this->production ? ConnectDesktopGrants::Developer : ConnectDesktopGrants::Production;
    $otherConfig = 'sso.'.$other->value.'_desktop_client_id';
    $otherClient = $other->value.'-client';
    $otherIssuer = $this->production ? 'https://sso.lgu.lan' : 'https://api.sso.lguquezon.local';
    $otherMigration = require database_path($this->production
        ? 'developer-desktop-migrations/2026_11_28_000001_create_connect_developer_desktop_grants.php'
        : 'production-desktop-migrations/2026_11_28_000002_create_connect_production_desktop_grants.php');
    $otherApplication = Application::factory()->create([
        'client_id' => $otherClient, 'client_secret' => Hash::make('other-secret'),
        'redirect_uris' => [$other->callback()],
    ]);
    $this->employee->applications()->attach($otherApplication->id, ['role' => 'standard']);
    config([$otherConfig => $otherClient]);
    expect(fn () => $otherMigration->up())->toThrow(RuntimeException::class);
    $this->app->instance('env', $this->production ? 'local' : 'production');
    config(['app.url' => $otherIssuer]);
    $otherMigration->up();
    $otherCode = $this->withToken($this->sourceToken)->postJson('/api/v1/sso/code', [
        'client_id' => $otherClient, 'redirect_uri' => $other->callback(),
    ])->assertOk()->json('code');
    $otherId = $this->postJson('/api/v1/sso/exchange', [
        'code' => $otherCode, 'redirect_uri' => $other->callback(), 'desktop_delegation' => true,
    ], ['X-Client-ID' => $otherClient, 'X-Client-Secret' => 'other-secret'])->assertOk()->json('desktop_delegation.id');
    $this->app->instance('env', $this->environment);
    config(['app.url' => $this->issuer]);
    expect(($this->lookup)($otherId))->toBeNull();
    $otherRows = DB::table($other->view())->where('grant_id', $otherId);
    $this->postJson('/api/v1/sso/desktop-delegations/'.$otherId.'/revoke', [], $this->clientHeaders)->assertNoContent();
    expect($otherRows->value('role'))->toBe('standard');
    $account = 'desktop_grant_test_reader';
    $password = bin2hex(random_bytes(24));
    // Only the opt-in disposable MySQL fixture reaches this test.
    DB::statement("CREATE USER '$account'@'%' IDENTIFIED BY '$password' REQUIRE SSL");
    try {
        DB::statement("GRANT SELECT ON {$this->viewName} TO '$account'@'%'");
        config(['database.connections.desktop_test_reader' => array_replace(config('database.connections.mysql'), [
            'database' => $database, 'username' => $account, 'password' => $password,
        ])]);
        $reader = DB::connection('desktop_test_reader');
        $view = $reader->table($viewName)->where('grant_id', $id);
        expect($reader->selectOne("SHOW SESSION STATUS LIKE 'Ssl_cipher'")->Value)->not->toBe('');
        expect(fn () => $reader->table($other->view())->get())->toThrow(\Illuminate\Database\QueryException::class);
        expect($reader->select('SHOW GRANTS'))->toHaveCount(2);
        $otherMigration->down();
        expect($view->value('role'))->toBe('standard');
        expect(fn () => $reader->table('desktop_authority_fixture.oauth_tokens')->limit(1)->get())->toThrow(\Illuminate\Database\QueryException::class);
        expect(fn () => (clone $view)->update(['role' => 'administrator']))->toThrow(\Illuminate\Database\QueryException::class);
        DB::beginTransaction();
        DB::table('employees')->where('id', $this->employee->id)->update(['is_active' => false]);
        expect($view->value('role'))->toBe('standard');
        DB::commit();
        expect($view->value('role'))->toBeNull();
    } finally {
        $otherMigration->down();
        DB::purge('desktop_test_reader');
        DB::statement("DROP USER '$account'@'%'");
    }
});
