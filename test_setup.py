"""Offline regression tests. Docker output is simulated, not a live stack."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml
from dotenv import dotenv_values
from lab_env import load_lab_env
from scripts import initialize, wazuh_lab

ROOT = Path(__file__).resolve().parent


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ['.env.example', 'vendor/misp/template.env',
                     'vendor/wazuh/single-node/docker-compose.yml',
                     'vendor/wazuh/single-node/config/wazuh_indexer/internal_users.template.yml',
                     'vendor/wazuh/single-node/config/wazuh_dashboard/wazuh.template.yml']:
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)

    def test_clean_distribution_initializes_without_generated_inputs(self):
        result = subprocess.CompletedProcess([], 0, '$2y$12$' + 'a' * 53, '')
        with patch.object(initialize, 'ROOT', self.root), patch.object(initialize.subprocess, 'run', return_value=result):
            initialize.main()
            values = dotenv_values(self.root / '.env', interpolate=False)
            self.assertEqual(values['ADMIN_ORG'], 'CTI Lab')
            self.assertEqual(values['OPENCTI_API_TOKEN'], values['OPENCTI_ADMIN_TOKEN'])
            config = self.root / 'vendor/wazuh/single-node/config'
            users = yaml.safe_load((config / 'wazuh_indexer/internal_users.yml').read_text())
            self.assertEqual(set(users), {'_meta', 'admin', 'kibanaserver'})
            dashboard = yaml.safe_load((config / 'wazuh_dashboard/wazuh.yml').read_text())
            self.assertEqual(next(iter(dashboard['hosts'][0].values()))['password'], values['WAZUH_API_PASSWORD'])
            before = (self.root / '.env').read_bytes()
            with self.assertRaises(SystemExit): initialize.main()
            self.assertEqual(before, (self.root / '.env').read_bytes())

    def test_missing_dashboard_template_fails_before_docker_or_writes(self):
        (self.root / 'vendor/wazuh/single-node/config/wazuh_dashboard/wazuh.template.yml').unlink()
        with patch.object(initialize, 'ROOT', self.root), patch.object(initialize.subprocess, 'run') as run:
            with self.assertRaises(FileNotFoundError): initialize.main()
            run.assert_not_called()
            self.assertFalse((self.root / '.env').exists())

    def test_hash_failure_leaves_no_generated_configuration(self):
        with patch.object(initialize, 'ROOT', self.root), patch.object(initialize.subprocess, 'run', side_effect=RuntimeError('simulated hashing failure')):
            with self.assertRaises(RuntimeError): initialize.main()
            self.assertFalse((self.root / '.env').exists())
            self.assertFalse((self.root / 'vendor/wazuh/single-node/config/wazuh_indexer/internal_users.yml').exists())

    def test_environment_is_data_and_explicit_environment_wins(self):
        path = self.root / 'test.env'
        path.write_text("ADMIN_ORG=CTI Lab\nLITERAL='$(touch NEVER_EXECUTE) ${HOME} # text'\n")
        with patch.dict(os.environ, {}, clear=True):
            load_lab_env(path)
            self.assertEqual(os.environ['ADMIN_ORG'], 'CTI Lab')
            self.assertEqual(os.environ['LITERAL'], '$(touch NEVER_EXECUTE) ${HOME} # text')
            os.environ['ADMIN_ORG'] = 'Explicit choice'
            load_lab_env(path)
            self.assertEqual(os.environ['ADMIN_ORG'], 'Explicit choice')

    def test_replay_rejects_old_markers_and_wrong_rule_or_fields(self):
        data = json.loads((ROOT / 'fixtures/positive.json').read_text())
        data['win']['eventdata']['commandLine'] = 'cmd.exe /c echo CTI-LAB-new'
        alert = {'rule': {'id': '100200', 'level': 7}, 'data': data}
        self.assertTrue(wazuh_lab.replay_matches(alert, 'CTI-LAB-new'))
        self.assertFalse(wazuh_lab.replay_matches(alert, 'CTI-LAB-old'))
        for key, value in [('id', '61603'), ('level', 3)]:
            other = copy.deepcopy(alert); other['rule'][key] = value
            self.assertFalse(wazuh_lab.replay_matches(other, 'CTI-LAB-new'))
        other = copy.deepcopy(alert); other['data']['win']['eventdata']['parentImage'] = 'explorer.exe'
        self.assertFalse(wazuh_lab.replay_matches(other, 'CTI-LAB-new'))


if __name__ == '__main__': unittest.main()
