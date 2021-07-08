import jwt

from pytest import fixture
from http import HTTPStatus
from unittest.mock import MagicMock, patch

from api.errors import (
    INVALID_ARGUMENT,
    UNKNOWN,
    AUTH_ERROR
)

from app import app

from tests.unit.mock_for_tests import PRIVATE_KEY


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='some_key',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False,
            wrong_jwks_host=False,
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_jwks_host:
            payload.pop('jwks_host')

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='function')
def mock_request():
    with patch('requests.get') as mock_request:
        yield mock_request


def securitytrails_api_response_mock(status_code=HTTPStatus.OK, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload

    return mock_response


def securitytrails_api_error_mock(status_code, text=None, json=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text
    mock_response.json.return_value = json

    return mock_response


@fixture(scope='module')
def securitytrails_ping_ok():
    return securitytrails_api_response_mock(
        HTTPStatus.OK, payload=[{"success": True}]
    )


@fixture(scope='module')
def securitytrails_history_a_ok():
    return securitytrails_api_response_mock(
        HTTPStatus.OK, payload={
            "type": "a/ipv4",
            "records": [
                {
                    "values": [
                        {
                            "ip_count": 3299,
                            "ip": "172.217.5.238"
                        }
                    ],
                    "type": "a"
                }
            ],
            "pages": 20,
            "endpoint": "/v1/history/cisco.com/dns/a"
        },
    )


@fixture(scope='module')
def securitytrails_history_aaaa_ok():
    return securitytrails_api_response_mock(
        HTTPStatus.OK, payload={
            "type": "a/ipv6",
            "records": [
                {
                    "values": [
                        {
                            "ipv6_count": 3189,
                            "ipv6": "2607:f8b0:4004:807::200e"
                        }
                    ],
                    "type": "aaaa",
                    "organizations": [
                        "Google LLC"
                    ],
                    "last_seen": "2020-07-15",
                    "first_seen": "2020-07-13"
                }
            ],
            "pages": 23,
            "endpoint": "/v1/history/google.com/dns/aaaa"
        },
    )


@fixture(scope='module')
def securitytrails_domain_list_ok():
    return securitytrails_api_response_mock(
        HTTPStatus.OK, payload={
            "records": [
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
                },
            ],
            "record_count": 40741,
            "meta": {
                "total_pages": 408,
                "query": "ipv4 = '1.1.1.1'",
                "page": 1,
                "max_page": 100
            },
            "endpoint": "/v1/domains/list"
        }
    )


@fixture(scope='session')
def securitytrails_response_unauthorized_creds():
    return securitytrails_api_error_mock(
        status_code=HTTPStatus.FORBIDDEN,
        text='{"message":"Invalid authentication credentials"}\n',
        json={"message": "Invalid authentication credentials"}
    )


@fixture(scope='session')
def securitytrails_response_bad_request():
    return securitytrails_api_error_mock(
        HTTPStatus.BAD_REQUEST,
        "The requested domain is invalid",
    )


def expected_payload(r, observe_body, refer_body=None):
    if r.endswith('/deliberate/observables'):
        return {'data': {}}

    if r.endswith('/refer/observables') and refer_body is not None:
        return refer_body

    return observe_body


@fixture(scope='module')
def authorization_errors_expected_payload(route,
                                          success_enrich_refer_domain_body):
    def _make_payload_message(message):
        return expected_payload(
            route,
            {
                'errors': [
                    {
                        'code': AUTH_ERROR,
                        'message': f'Authorization failed: '
                                   f'{message}',
                        'type': 'fatal'}
                ]
            },
            success_enrich_refer_domain_body
        )
    return _make_payload_message


@fixture(scope='module')
def invalid_json_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {
                    'code': INVALID_ARGUMENT,
                    'message':
                        'Invalid JSON payload received. {"0": {"value": '
                        '["Missing data for required field."]}}',
                    'type': 'fatal'}]
        }
    )


@fixture(scope='module')
def unauthorized_creds_body():
    return {
        'errors': [
            {
                'code': AUTH_ERROR,
                'message':
                    'Authorization failed: '
                    'Invalid authentication credentials',
                'type': 'fatal'}
        ],
        'data': {}
    }


@fixture(scope='module')
def sslerror_expected_payload():
    return {
        'errors': [
            {
                'code': UNKNOWN,
                'message': 'Unable to verify SSL certificate:'
                           ' Self signed certificate',
                'type': 'fatal'
            }
        ]
    }


@fixture(scope='module')
def key_error_body():
    return {
        'errors': [
            {
                'type': 'fatal',
                'code': 'key error',
                'message': 'The data structure of SecurityTrails '
                           'has changed. The module is broken.'
            }
        ]
    }


@fixture(scope='module')
def success_enrich_observe_domain_body():
    return {'data': {
        'sightings': {
            'count': 2,
            'docs': [
                {
                    'confidence': 'High',
                    'count': 1,
                    'description':
                        'IPv4 addresses that cisco.com resolves to',
                    'internal': False,
                    'observables': [
                        {
                            'type': 'domain',
                            'value': 'cisco.com'
                        }
                    ],
                    'relations': [
                        {
                            'origin': 'SecurityTrails Enrichment Module',
                            'related': {
                                'type': 'ip',
                                'value': '172.217.5.238'
                            },
                            'relation': 'Resolved_To',
                            'source': {
                                'type': 'domain',
                                'value': 'cisco.com'
                            }
                        }
                    ],
                    'schema_version': '1.0.17',
                    'source': 'SecurityTrails',
                    'source_uri': (
                        'https://securitytrails.com/domain/cisco.com/dns'
                    ),
                    'title': 'Found in SecurityTrails',
                    'type': 'sighting'
                },
                {
                    'confidence': 'High',
                    'count': 1,
                    'description':
                        'IPv6 addresses that cisco.com resolves to',
                    'internal': False,
                    'observables': [
                        {
                            'type': 'domain',
                            'value': 'cisco.com'
                        }
                    ],
                    'relations': [
                        {
                            'origin': 'SecurityTrails Enrichment Module',
                            'related': {
                                'type': 'ipv6',
                                'value': '2607:f8b0:4004:807::200e'
                            },
                            'relation': 'Resolved_To',
                            'source': {
                                'type': 'domain',
                                'value': 'cisco.com'
                            }
                        }
                    ],
                    'schema_version': '1.0.17',
                    'source': 'SecurityTrails',
                    'source_uri':
                        'https://securitytrails.com/domain/cisco.com/dns',
                    'title': 'Found in SecurityTrails',
                    'type': 'sighting'
                }
            ]
        }
    }
    }


@fixture(scope='module')
def success_enrich_observe_ip_body():
    return {
        'data': {
            'sightings': {
                'count': 1,
                'docs': [
                    {
                        'confidence': 'High',
                        'count': 40741,
                        'description': 'Domains that have resolved to 1.1.1.1',
                        'internal': False,
                        'observables': [
                            {
                                'type': 'ip',
                                'value': '1.1.1.1'
                            }
                        ],
                        'relations': [
                            {
                                'origin': 'SecurityTrails Enrichment Module',
                                'related': {
                                    'type': 'ip',
                                    'value': '1.1.1.1'
                                },
                                'relation': 'Resolved_To',
                                'source': {
                                    'type': 'domain',
                                    'value': 'udemy.com'
                                }
                            }
                        ],
                        'schema_version': '1.0.17',
                        'source': 'SecurityTrails',
                        'source_uri':
                            'https://securitytrails.com/list/ip/1.1.1.1',
                        'title': 'Found in SecurityTrails',
                        'type': 'sighting'
                    }
                ]
            }
        }
    }


@fixture(scope='module')
def success_enrich_refer_domain_body():
    return {
        'data': [
            {
                'categories': ['Search', 'SecurityTrails'],
                'description': 'Lookup this domain on SecurityTrails',
                'id': 'ref-securitytrails-search-domain-cisco.com',
                'title': 'Search for this domain',
                'url': 'https://securitytrails.com/domain/cisco.com/dns'
            }
        ]
    }


@fixture(scope='module')
def success_enrich_refer_ip_body():
    return {
        'data': [
            {
                'categories': ['Search', 'SecurityTrails'],
                'description': 'Lookup this IP on SecurityTrails',
                'id': 'ref-securitytrails-search-ip-1.1.1.1',
                'title': 'Search for this IP',
                'url': 'https://securitytrails.com/list/ip/1.1.1.1'
            }
        ]
    }


@fixture(scope='module')
def success_enrich_client_data(
        observable, securitytrails_history_a_ok,
        securitytrails_history_aaaa_ok, securitytrails_domain_list_ok
):
    if observable['type'] == 'domain':
        return [securitytrails_history_a_ok,
                securitytrails_history_aaaa_ok]
    if observable['type'] == 'ip':
        return [securitytrails_domain_list_ok]


@fixture(scope='module')
def success_enrich_expected_payload(
        route, observable,
        success_enrich_observe_ip_body, success_enrich_refer_ip_body,
        success_enrich_observe_domain_body, success_enrich_refer_domain_body
):
    if observable['type'] == 'domain':
        return expected_payload(
            route, success_enrich_observe_domain_body,
            success_enrich_refer_domain_body
        )
    if observable['type'] == 'ip':
        return expected_payload(
            route, success_enrich_observe_ip_body,
            success_enrich_refer_ip_body
        )
