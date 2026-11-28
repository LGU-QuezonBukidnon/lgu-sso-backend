"""Verify both desktop grant editions using an isolated MySQL 8 primary with verified TLS."""
import base64
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time


repo = Path(__file__).resolve().parents[1]
name = 'connect-grants-test-' + secrets.token_hex(5)
with tempfile.TemporaryDirectory() as state:
    directory = Path(state)
    tls = directory / 'tls'
    tls.mkdir()
    # The private fixture CA key stays outside the server's mounted directory.
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=Disposable desktop authority CA', '-keyout', directory / 'ca.key',
                    '-out', tls / 'ca.pem'], check=True, capture_output=True)
    subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                    '-subj', '/CN=localhost', '-keyout', tls / 'server-key.pem',
                    '-out', directory / 'server.csr'], check=True, capture_output=True)
    extensions = directory / 'server.extensions'
    extensions.write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
    subprocess.run(['openssl', 'x509', '-req', '-days', '1', '-in', directory / 'server.csr',
                    '-CA', tls / 'ca.pem', '-CAkey', directory / 'ca.key', '-CAcreateserial',
                    '-extfile', extensions, '-out', tls / 'server-cert.pem'], check=True, capture_output=True)
    # The per-run directory is owner-only; MySQL's container user must read its mounted test key.
    (tls / 'server-key.pem').chmod(0o444)
    secret_file = directory / 'root-password'
    secret_file.write_text(secrets.token_hex(32))
    secret_file.chmod(0o600)
    secret = secret_file.read_text()
    subprocess.run([
        'docker', 'run', '--detach', '--name', name, '--memory', '512m', '--cpus', '1',
        '--volume', '/var/lib/mysql', '--volume', f'{tls}:/run/desktop-tls:ro',
        '--publish', '127.0.0.1::3306', '--volume', f'{secret_file}:/run/secrets/db:ro',
        '--env', 'MYSQL_ROOT_PASSWORD_FILE=/run/secrets/db', '--env', 'MYSQL_ROOT_HOST=%',
        '--env', 'MYSQL_DATABASE=desktop_authority_fixture', 'mysql:8.0',
        '--require-secure-transport=ON', '--ssl-ca=/run/desktop-tls/ca.pem',
        '--ssl-cert=/run/desktop-tls/server-cert.pem', '--ssl-key=/run/desktop-tls/server-key.pem',
        '--innodb-buffer-pool-size=64M', '--max-connections=40', '--performance-schema=OFF',
    ], check=True, stdout=subprocess.DEVNULL)
    try:
        sql = ['docker', 'exec', '--interactive', '--env', 'MYSQL_PWD', name, 'mysql',
               '--protocol=tcp', '--host=127.0.0.1', '--user=root']
        client_env = {**os.environ, 'MYSQL_PWD': secret}
        for attempt in range(60):
            ready = subprocess.run(sql, input='SELECT 1', text=True, env=client_env, capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Disposable MySQL failed to start in 60 seconds.')
        subprocess.run(sql, input='CREATE DATABASE connect_developer_authority; CREATE DATABASE connect_production_authority;', text=True, env=client_env, check=True)
        port = subprocess.check_output(['docker', 'port', name, '3306/tcp'], text=True).strip().rsplit(':', 1)[1]
        env = {
            **os.environ, 'APP_ENV': 'testing', 'APP_KEY': 'base64:' + base64.b64encode(secrets.token_bytes(32)).decode(),
            'JWT_SECRET': secrets.token_hex(32), 'JWT_TTL': '1440', 'SSO_DESKTOP_AUTHORITY_DISPOSABLE_MYSQL': '1',
            'DB_CONNECTION': 'mysql', 'DB_DATABASE': 'desktop_authority_fixture', 'DB_HOST': '127.0.0.1',
            'MYSQL_ATTR_SSL_CA': str(tls / 'ca.pem'), 'DB_PORT': port, 'DB_USERNAME': 'root', 'DB_PASSWORD': secret, 'DB_URL': '',
        }
        for edition in ['developer', 'production']:
            print(f'Verifying {edition} desktop authority over TLS', flush=True)
            subprocess.run(['php', 'vendor/bin/pest', 'tests/Feature/ConnectDeveloperDesktopAuthorityTest.php'],
                           cwd=repo, env={**env, 'SSO_DESKTOP_AUTHORITY_FIXTURE_EDITION': edition}, check=True)
    finally:
        subprocess.run(['docker', 'rm', '--force', '--volumes', name], check=True, stdout=subprocess.DEVNULL)
