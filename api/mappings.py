from abc import ABCMeta, abstractmethod
from datetime import datetime
from uuid import uuid4

from api.utils import all_subclasses

CTIM_DEFAULTS = {
    'schema_version': '1.0.17',
}

RESOLVED_TO = 'Resolved_To'


class Mapping(metaclass=ABCMeta):

    def __init__(self, observable):
        self.observable = observable

    @classmethod
    def for_(cls, observable):
        """Return an instance of `Mapping` for the specified type."""

        for subcls in all_subclasses(Mapping):
            if subcls.type() == observable['type']:
                return subcls(observable)

        return None

    @classmethod
    @abstractmethod
    def type(cls):
        """Return the observable type that the mapping is able to process."""

    @staticmethod
    @abstractmethod
    def _aggregate(data):
        """Extract unique related observables and sightings count."""

    @abstractmethod
    def _resolved_to(self, related):
        """
        Return TR resolved_to relation
        depending on an observable and related types.

        """

    @abstractmethod
    def _description(self, *args):
        """Return description field depending on observable type."""

    def _sighting(self, count, description, refer_link):
        now = f'{datetime.now().isoformat(timespec="seconds")}Z'

        return {
            **CTIM_DEFAULTS,
            'id': f'transient:sighting-{uuid4()}',
            'type': 'sighting',
            'source': 'SecurityTrails',
            'title': 'Found in SecurityTrails',
            'confidence': 'High',
            'internal': False,
            'count': count,
            'observables': [self.observable],
            'observed_time': {
                'start_time': now,
                'end_time': now,
            },
            'description': description,
            'source_uri': refer_link
        }

    def extract_sighting(self, st_data, refer_link):
        if not st_data.get('records'):
            return

        related, count = self._aggregate(st_data)

        if related:
            related = sorted(related)
            description = self._description(st_data.get('type'))
            sighting = self._sighting(count, description, refer_link)
            sighting['relations'] = [self._resolved_to(r) for r in related]
            return sighting

    @staticmethod
    def observable_relation(relation_type, source, related):
        return {
            "origin": "SecurityTrails Enrichment Module",
            "relation": relation_type,
            "source": source,
            "related": related
        }


class Domain(Mapping):
    @classmethod
    def type(cls):
        return 'domain'

    def _description(self, related_type):
        related_type = f'IP{related_type[-2:]}'
        return (f'{related_type} addresses that '
                f'{self.observable["value"]} resolves to')

    @staticmethod
    def _aggregate(st_data):
        related = []
        for r in st_data['records']:
            related.extend(
                v.get('ip') or v.get('ipv6') or 0 for v in r['values']
            )

        related = set(related)
        return related, len(related)

    def _resolved_to(self, ip):
        return self.observable_relation(
            RESOLVED_TO,
            source=self.observable,
            related={
                'value': ip,
                'type': 'ipv6' if ':' in ip else 'ip'
            }
        )


class IP(Mapping):
    @classmethod
    def type(cls):
        return 'ip'

    def _description(self, *args):
        return f'Domains that have resolved to {self.observable["value"]}'

    @staticmethod
    def _aggregate(st_data):
        related = [r['hostname'] for r in st_data['records']]
        count = st_data['record_count']
        return set(related), count

    def _resolved_to(self, domain):
        return self.observable_relation(
            RESOLVED_TO,
            source={'value': domain, 'type': 'domain'},
            related=self.observable
        )


class IPV6(IP):
    @classmethod
    def type(cls):
        return 'ipv6'
