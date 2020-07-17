import json
from collections import namedtuple
from datetime import datetime

from pytest import fixture

from api.mappings import (
    Domain, Mapping,
    IP, IPV6
)


def input_sets():
    TestData = namedtuple('TestData', 'file mapping')
    yield TestData('domain-a.json',
                   Domain({'type': 'domain', 'value': 'google.com'}))
    yield TestData('domain-aaaa.json',
                   Domain({'type': 'domain', 'value': 'google.com'}))
    yield TestData('ip.json', IP({'type': 'ip', 'value': '1.1.1.1'}))
    yield TestData('ipv6.json',
                   IPV6({'type': 'ipv6',
                         'value': '2001:0db8:85a3:0000:0000:8a2e:0370:7334'}))


@fixture(scope='module', params=input_sets(), ids=lambda d: d.file)
def input_data(request):
    return request.param


def test_map(input_data):
    with open('tests/unit/data/' + input_data.file) as file:
        data = json.load(file)

        result = getattr(input_data.mapping, 'extract_sighting')(
            data['input'], 'ui_url')

        time = datetime.now().isoformat(timespec="minutes")
        assert result.pop('id').startswith('transient:sighting-')
        assert result.pop('observed_time').pop(
            'start_time').startswith(time)

        assert result == data['output']


def test_no_data(input_data):
    result = getattr(input_data.mapping, 'extract_sighting')(
        {'a': 'b'}, 'ui_url')
    assert result is None


def test_mapping_for_():
    assert isinstance(Mapping.for_({'type': 'domain'}), Domain)
    assert isinstance(Mapping.for_({'type': 'ip'}), IP)
    assert isinstance(Mapping.for_({'type': 'ipv6'}), IPV6)
    assert Mapping.for_({'type': 'whatever'}) is None
