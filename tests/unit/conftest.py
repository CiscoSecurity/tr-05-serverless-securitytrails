from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import PERMISSION_DENIED, INVALID_ARGUMENT
from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {'username': 'gdavoian', 'superuser': False}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='session')
def invalid_jwt(valid_jwt):
    header, payload, signature = valid_jwt.split('.')

    def jwt_decode(s: str) -> dict:
        from authlib.common.encoding import urlsafe_b64decode, json_loads
        return json_loads(urlsafe_b64decode(s.encode('ascii')))

    def jwt_encode(d: dict) -> str:
        from authlib.common.encoding import json_dumps, urlsafe_b64encode
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode('ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['superuser'] = True

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


def securitytrails_api_response_mock(status_code, payload=None):
    mock_response = MagicMock()

    mock_response.status = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    payload = payload or {}
    mock_response.json = lambda: payload

    return mock_response


def securitytrails_api_error_mock(status_code, text=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text

    return mock_response


@fixture(scope='function')
def securitytrails_ping_ok():
    return securitytrails_api_response_mock(
        HTTPStatus.OK, payload=[{"success": True}]
    )


@fixture(scope='function')
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


@fixture(scope='function')
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


@fixture(scope='function')
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
def securitytrails_response_unauthorized_creds(secret_key):
    return securitytrails_api_error_mock(
        HTTPStatus.FORBIDDEN,
        'Error: Bad API key'
    )


@fixture(scope='session')
def securitytrails_response_bad_request(secret_key):
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
def invalid_jwt_expected_payload(route, success_enrich_refer_domain_body):
    return expected_payload(
        route,
        {
            'errors': [
                {
                    'code': PERMISSION_DENIED,
                    'message': 'Invalid Authorization Bearer JWT.',
                    'type': 'fatal'}
            ],
            'data': {}
        },
        success_enrich_refer_domain_body
    )


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
                    'type': 'fatal'}],
            'data': {}
        }
    )


@fixture(scope='module')
def unauthorized_creds_body():
    return {
        'errors': [
            {
                'code': PERMISSION_DENIED,
                'message': ("Unexpected response from SecurityTrails: "
                            "Error: Bad API key"),
                'type': 'fatal'}
        ],
        'data': {}
    }


@fixture(scope='module')
def unauthorized_creds_expected_payload(
        route, unauthorized_creds_body, success_enrich_refer_domain_body
):
    return expected_payload(
        route, unauthorized_creds_body, success_enrich_refer_domain_body
    )


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
def success_enrich_expected_payload_domain(
        route, success_enrich_observe_domain_body,
        success_enrich_refer_domain_body
):
    return expected_payload(
        route, success_enrich_observe_domain_body,
        success_enrich_refer_domain_body
    )


@fixture(scope='module')
def success_enrich_expected_payload_ip(
        route, success_enrich_observe_ip_body, success_enrich_refer_ip_body
):
    return expected_payload(
        route, success_enrich_observe_ip_body, success_enrich_refer_ip_body
    )
