import copy
from collections import namedtuple
from unittest.mock import MagicMock, patch

from pytest import fixture

from api.client import SecurityTrailsClient
from api.errors import UnprocessedPagesWarning

OBSERVABLE = {'value': '1.1.1.1'}

HISTORY_META = {
    "type": "a/ipv4",
    "pages": 20,
    "endpoint": "/v1/HISTORY/google.com/dns/a"
}
HISTORY_RECORDS = [
    {
        "values": [
            {
                "ip_count": 3299,
                "ip": "172.217.5.238"
            }
        ],
    },
    {
        "values": [
            {
                "ip_count": 3299,
                "ip": "172.217.5.238"
            }
        ],
    }
]
HISTORY = {**HISTORY_META, 'records': HISTORY_RECORDS}

DOMAIN_LIST_META = {
    "record_count": 40741,
    "meta": {
        "total_pages": 408,
        "query": "ipv4 = '1.1.1.1'",
        "page": 1,
        "max_page": 5
    },
    "endpoint": "/v1/domains/list"
}
DOMAIN_LIST_RECORDS = [
    {
        "whois": {
            "registrar": "SafeNames Ltd",
            "expiresDate": 1565728665000,
            "createdDate": 1250195865000
        },
        "mail_provider": [
            "Google LLC"
        ],
        "hostname": "udemy.com",
        "host_provider": [
            "Cloudflare, Inc."
        ],
        "computed": {
            "company_name": "Udemy Inc."
        },
        "alexa_rank": 83
    }
]
DOMAIN_LIST = {**DOMAIN_LIST_META, 'records': DOMAIN_LIST_RECORDS}


def history():
    return copy.deepcopy(HISTORY)


def data_sets():
    TestData = namedtuple(
        'TestData', 'test_name endpoint_mock number_of_pages '
                    'expected_records_len'
    )
    yield TestData('one_page', lambda *args, **kwargs: history(), 1, 2)
    yield TestData(
        'less_pages_than_available', lambda *args, **kwargs: history(), 2, 4
    )
    yield TestData('all_pages', lambda *args, **kwargs: history(), 0, 40)
    yield TestData(
        'no_records',
        MagicMock(side_effect=[history(), history(),
                               HISTORY_META, history()]),
        4, 4
    )


@fixture(scope='module', params=data_sets(), ids=lambda d: d.test_name)
def test_data(request):
    return request.param


def test_get_pages(test_data):
    client = SecurityTrailsClient('base_url', 'api_key',
                                  'user_agent',
                                  number_of_pages=test_data.number_of_pages)

    with patch("api.client.add_error") as add_error_mock:
        result = client._get_pages(OBSERVABLE, test_data.endpoint_mock)

        assert len(result.pop('records')) == test_data.expected_records_len
        assert result == HISTORY_META
        add_error_mock.assert_not_called()


def test_get_pages_with_unprocessed_pages_left():
    def endpoint(*args, **kwargs):
        return copy.deepcopy(DOMAIN_LIST)

    client = SecurityTrailsClient('base_url', 'api_key',
                                  'user_agent', number_of_pages=10)

    with patch("api.client.add_error") as add_error_mock:
        result = client._get_pages(OBSERVABLE, endpoint)

        assert len(result.pop('records')) == 5
        assert result == DOMAIN_LIST_META

        add_error_mock.assert_called_once()
        args, kwargs = add_error_mock.call_args
        assert isinstance(args[0], UnprocessedPagesWarning)
