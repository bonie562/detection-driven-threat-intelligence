"""Create one synthetic lab event; requires a separate lab write key and --apply."""
import argparse
import os
from datetime import date
from pymisp import PyMISP, MISPEvent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if not args.apply:
        raise SystemExit('No changes made. Run with --apply on the disposable lab MISP instance.')
    client = PyMISP(os.environ['MISP_URL'], os.environ['MISP_LAB_WRITE_KEY'],
                    ssl=os.getenv('MISP_CA_BUNDLE', True), timeout=30)
    event = MISPEvent()
    event.info = 'Synthetic CTI lab event - not observed malicious activity'
    event.date = date.today()
    event.distribution = 0
    event.threat_level_id = 4
    event.analysis = 2
    event.add_tag(os.environ['MISP_EXPORT_TAG'])
    event.add_attribute('domain', 'cti-lab.example', to_ids=True,
                        comment='Reserved .example namespace, synthetic fixture only')
    result = client.add_event(event, pythonify=True)
    if not isinstance(result, MISPEvent): raise RuntimeError('MISP event creation failed')
    client.publish(result.uuid)
    published = client.get_event(result.uuid, pythonify=True)
    if not isinstance(published, MISPEvent) or not published.published:
        raise RuntimeError('The created event was not published; check lab write-key permissions')
    print('Created and published synthetic event:', result.uuid)


if __name__ == '__main__':
    main()
