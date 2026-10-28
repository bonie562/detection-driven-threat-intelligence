"""Offline checks of translation semantics, rejection behavior, and intake controls."""
import copy
import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as Obj

import yaml

from translate import FIELD_MAP, load_rule, translate
from ingest import fetch_events, make_pattern, prepare, create_indicator

ROOT = Path(__file__).resolve().parent


class LabTests(unittest.TestCase):
    def test_translation_matches_independent_suffix_evaluation(self):
        rule = load_rule(ROOT / 'rules/powershell_child.yml')
        with tempfile.TemporaryDirectory() as temp:
            xml = translate(ROOT / 'rules/powershell_child.yml', Path(temp) / 'rules.xml')
        for name, expected in json.loads((ROOT / 'fixtures/expected.json').read_text()).items():
            event = json.loads((ROOT / f'fixtures/{name}.json').read_text())['win']
            sigma = event['system']['eventID'] == '1'
            for field, values in rule['detection']['selection'].items():
                values = values if isinstance(values, list) else [values]
                key = FIELD_MAP[field].rsplit('.', 1)[1]
                sigma &= any(event['eventdata'][key].lower().endswith(v.lower()) for v in values)
            native = event['system']['eventID'] == '1' and all(
                re.search(n.text, event['eventdata'][n.attrib['name'].rsplit('.', 1)[1]])
                for n in xml.findall('.//field'))
            self.assertEqual(bool(sigma), expected, name)
            self.assertEqual(bool(native), expected, name)

    def test_rejects_unsupported_semantics(self):
        original = yaml.safe_load((ROOT / 'rules/powershell_child.yml').read_text())
        for change in ['condition', 'filter', 'wildcard', 'logsource']:
            rule = copy.deepcopy(original)
            if change == 'condition': rule['detection']['condition'] = '1 of selection*'
            if change == 'filter': rule['detection']['filter'] = {'Image': 'x'}
            if change == 'wildcard': rule['detection']['selection']['Image|endswith'] = '\\*.exe'
            if change == 'logsource': rule['logsource']['product'] = 'linux'
            with tempfile.TemporaryDirectory() as temp:
                p = Path(temp)/'rule.yml'; p.write_text(yaml.safe_dump(rule))
                with self.assertRaises(ValueError, msg=change): load_rule(p)

    def test_patterns_escape_validate_and_handle_ipv6(self):
        for kind, value in [('ip-src', '2001:db8::1'), ('domain', 'EXAMPLE.ORG.'),
                            ('url', "https://example.org/a'b"), ('sha256', 'a'*64)]:
            _, pattern = make_pattern(kind, value)
            self.assertTrue(pattern.startswith('['))
        self.assertIn('ipv6-addr', make_pattern('ip-src','2001:db8::1')[1])
        with self.assertRaises(ValueError): make_pattern('ip-src','999.1.1.1')
        with self.assertRaises(ValueError): make_pattern('sha256','a'*63)
        with self.assertRaises(ValueError): make_pattern('domain','-invalid.example')

    def test_pagination_cap_is_not_silent_truncation(self):
        calls = []
        def search(**kwargs):
            calls.append(kwargs)
            return [Obj()] * kwargs['limit']
        with self.assertRaises(RuntimeError): fetch_events(Obj(search=search), 1, 'lab-approved', 2, 2)
        self.assertEqual(len(calls), 2)
        self.assertIn('publish_timestamp', calls[0])
        self.assertNotIn('date_from', calls[0])

    def test_expiry_deduplication_and_to_ids(self):
        now = datetime(2026,10,28,tzinfo=timezone.utc)
        def attr(value, age=1, to_ids=True):
            return Obj(type='domain',value=value,to_ids=to_ids,uuid='attribute-id',timestamp=now-timedelta(days=age))
        event = Obj(uuid='event-id',attributes=[attr('EXAMPLE.ORG'),attr('example.org'),attr('old.example',8),attr('skip.example',to_ids=False)])
        result = prepare([event],now)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['value'],'example.org')
        self.assertEqual(datetime.fromisoformat(result[0]['valid_until']),now+timedelta(days=6))

    def test_indicator_creation_carries_provenance_and_marking(self):
        captured = {}
        api = Obj(indicator=Obj(list=lambda **k: [], create=lambda **k: captured.update(k) or {'id':'indicator-id'}),
                  external_reference=Obj(create=lambda **k:{'id':'reference-id'}))
        record = {'pattern':"[domain-name:value = 'example.org']",'value':'example.org', 'event_uuid':'event-id','attribute_uuid':'attribute-id','valid_from':'2026-10-27T00:00:00Z','valid_until':'2026-11-03T00:00:00Z'}
        self.assertEqual(create_indicator(api,record,'https://misp.example','marking-id'),'created')
        self.assertEqual(captured['externalReferences'],['reference-id'])
        self.assertEqual(captured['objectMarking'],['marking-id'])
        self.assertEqual(captured['x_opencti_main_observable_type'],'Domain-Name')


if __name__ == '__main__': unittest.main(verbosity=2)
