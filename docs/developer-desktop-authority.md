# Connect desktop authorization

SSO issues a revocable desktop grant during a fresh authorization-code exchange. Each device receives its own grant. The existing portal and application bearer retain their normal lifetime. An existing bearer cannot be converted.

## Local installation

1. Use MySQL 8 on the SSO primary. Configure `SSO_CONNECT_DEVELOPER_CLIENT_ID` on the local SSO service with the registered client ID. Its allowed callbacks must include `https://connect.lgu.lan/auth/sso/callback`. The feature defaults off. `SSO_CONNECT_DEVELOPER_GRANT_TTL_MINUTES` optionally sets a positive lifetime from 1 to 525600 minutes. Leave it unset for a persistent grant.
2. The database operator creates the dedicated database `connect_developer_authority` and a dedicated reader account for Connect. The installation identity needs permission to create the projection table and triggers in the SSO schema, and to define the view in the separate authority schema.
3. On the SSO service run `php artisan migrate --path=database/developer-desktop-migrations`. This separate migration creates indexed grant rows in SSO-owned storage. It installs synchronous triggers before publishing the restricted view.
4. Grant the reader only `SELECT` on `connect_developer_authority.connect_developer_desktop_authorizations`. Connect uses this user on its separate primary-only authority connection. Store these credentials server-side.
5. Enable delegated desktop exchange on Connect. LGU Connect Developer 0.4.8 resumes sessions that already have a valid desktop grant. SSO cannot convert older sessions that lack a grant. Connect blocks those sessions until the employee signs in once more from the Developer app.

The installation binds an application primary key. If a registration is replaced, disable delegation in Connect, revoke existing grants, and reinstall the scoped migration for the new registration. Reverting the scoped migration drops the developer grants and view, ending all delegated sessions. Normal SSO migration and deployment commands do not install this local extension.

## Office installation

The production API origin is `https://api.sso.lguquezon.local`. Its portal is `https://sso.lguquezon.local`. The SSO service must use `APP_ENV=production` and the exact API origin in `APP_URL`. Developer grants require `APP_ENV=local` or `testing` and `APP_URL=https://sso.lgu.lan`.

1. Set `SSO_CONNECT_PRODUCTION_CLIENT_ID` to the existing production Connect registration's client ID. Confirm the application is active and its allowed callbacks include the exact `https://connect.lguquezon.local/auth/sso/callback`. `SSO_CONNECT_PRODUCTION_GRANT_TTL_MINUTES` optionally sets a lifetime between 1 and 525600 minutes. Unset means the device stays authorized until revocation. The default office Compose template leaves delegation disabled.
2. On the office SSO primary, create the dedicated database `connect_production_authority`. Use the normal backup and restore verification before this optional migration. Use a lasting database identity for the view and trigger definer. It needs permission to manage grants in the SSO schema and the published view in the authority database.
3. With the verified production SSO image and settings, run `php artisan migrate --force --path=database/production-desktop-migrations`. The ordinary startup migration does not install this extension. The installer first creates the SSO-owned `connect_production_desktop_grants` table and synchronous revocation triggers. It then publishes the view.
4. Give Connect a dedicated MySQL account on the office primary. Restrict its hosts to the private application network, enforce `REQUIRE SSL`, and grant only `SELECT` on `connect_production_authority.connect_desktop_authorizations`. Configure the Connect reader with the database's DNS name and trusted CA, and verify the server certificate. Use separate users, credentials, and certificates in each environment. Verify that the reader cannot read the SSO source tables, select the developer view, or change a grant.
5. Enable Connect's matching production registration and read view after these checks succeed. LGU Connect 0.4.8 resumes sessions that already have a valid office desktop grant. SSO cannot convert older sessions that lack a grant. Connect blocks those sessions until the employee signs in once more from the production desktop app.

To back out of an office rollout, first disable new delegated exchanges. Keep the SSO view available while existing devices move to a compatible release. Deliberately rolling back the scoped production migration drops its view and grants, so all remaining delegated office devices must sign in again. The developer grant table, view and triggers have distinct names.

## Session contract

- Connect verifies its one-time desktop handoff, then adds boolean `desktop_delegation: true` to the standard authenticated exchange. SSO returns the usual response plus `desktop_delegation` containing a UUID `id` and UTC `expires_at` or `null`. User, application, token and assignment are checked in the transaction that creates the grant.
- On each protected operation, Connect looks up the grant ID, client ID and employee UUID in the published view. SSO returns only active grants and current roles. Failure to reach this primary must fail closed. The UUID identifies a server-held grant and is insufficient to sign in.
- A mutation to the underlying SSO token, employee, application or assignment updates the grant in the same MySQL transaction. Allowed role changes take effect on commit. Removing an assignment, disabling an account, requiring a password change, disabling an app or revoking a token terminates the grant. Restoring eligibility requires a new handoff. Physical deletion of a token or assignment removes its linked grants through foreign keys.
- The normal bearer can expire before an explicitly persistent desktop grant. SSO retains the token row as the revocation anchor. This release has no age-based OAuth token pruning job. Any later pruning job must preserve active grant anchors if it intends to keep those devices signed in.
- Explicit desktop sign-out calls `POST /api/v1/sso/desktop-delegations/{id}/revoke` with the application's existing client headers. This returns 204 on success, including repeated sign-outs. A central logout-all revokes each affected device through the usual token mutation. Use the grant's own deadline for expiry.
- Connect and SSO are separate database servers. A committed revocation is visible to the next protected lookup on SSO. An operation already authorized on Connect may finish concurrently.

## Verification

Run `python3 tests/run-desktop-authority-mysql.py` after installing Composer dependencies. The runner uses a fresh MySQL 8 instance with mandatory TLS on a random loopback port. It exercises both editions with synthetic registrations. The suite checks index use, TLS, restricted reader privileges, role changes, rollback isolation, central revocation and device logout.
