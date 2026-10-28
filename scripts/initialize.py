"""Initialize a new disposable lab. Refuses to overwrite an existing .env."""
import os
import base64
import re
import secrets
import subprocess
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    target = ROOT / '.env'
    if target.exists():
        raise SystemExit('Existing .env found. Preserve it; do not regenerate credentials for existing volumes.')
    env = {}
    for line in (ROOT / '.env.example').read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            if value == 'GENERATE_PASSWORD': value = 'Aa1!' + secrets.token_hex(18)
            elif value == 'GENERATE_UUID': value = str(uuid.uuid4())
            elif value == 'GENERATE_HEX': value = secrets.token_hex(32)
            elif value == 'GENERATE_BASE64': value = base64.b64encode(secrets.token_bytes(32)).decode()
            env[key] = value
    env['OPENCTI_API_TOKEN'] = env['OPENCTI_ADMIN_TOKEN']
    # The runnable configuration is intended only for brand-new lab volumes.
    config = ROOT / 'vendor/wazuh/single-node/config'
    users_path = config / 'wazuh_indexer/internal_users.yml'
    users = yaml.safe_load(users_path.read_text())
    image = yaml.safe_load((config.parents[0] / 'docker-compose.yml').read_text())['services']['wazuh.indexer']['image']
    # Keep only the two accounts needed by the laboratory.
    users = {k: v for k, v in users.items() if k in {'_meta', 'admin', 'kibanaserver'}}
    for username, key in [('admin', 'WAZUH_INDEXER_PASSWORD'), ('kibanaserver', 'WAZUH_DASHBOARD_PASSWORD')]:
        runenv = os.environ.copy()
        runenv['HASH_PASSWORD'] = env[key]
        command = ['docker', 'run', '--rm', '--entrypoint', 'bash', '-e', 'HASH_PASSWORD', image,
                   '-c', '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$HASH_PASSWORD"']
        result = subprocess.run(command, env=runenv, text=True, capture_output=True, check=True)
        hashes = re.findall(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}', result.stdout)
        if len(hashes) != 1:
            raise RuntimeError('Password hash generation failed; no credentials were written')
        users[username]['hash'] = hashes[0]
    users_path.write_text(yaml.safe_dump(users, sort_keys=False))
    dashboard_path = config / 'wazuh_dashboard/wazuh.yml'
    dashboard = yaml.safe_load(dashboard_path.read_text())
    for host in dashboard['hosts']:
        for value in host.values(): value['password'] = env['WAZUH_API_PASSWORD']
    dashboard_path.write_text(yaml.safe_dump(dashboard, sort_keys=False))
    # MISP keeps the upstream environment template, supplemented with lab overrides.
    base = (ROOT / 'vendor/misp/template.env').read_text()
    (ROOT / 'vendor/misp/.env').write_text(base + '\n' + '\n'.join(f'{k}={v}' for k,v in env.items()) + '\n')
    (ROOT / 'vendor/misp/.env').chmod(0o600)
    target.write_text('\n'.join(f'{k}={v}' for k,v in env.items()) + '\n')
    target.chmod(0o600)
    # Credentials and generated hashes are private local configuration.
    ROOT.chmod(0o700)
    for path in (users_path, dashboard_path): path.chmod(0o644)
    print('Initialized new lab credentials in .env. Review the README before starting services.')


if __name__ == '__main__':
    main()
