import json
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
    def iter_lines():
        for r in payload:
            yield r

    mock_response = MagicMock()

    mock_response.status = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    payload = payload or []
    payload = (json.dumps(r) for r in payload)

    mock_response.iter_lines = iter_lines

    return mock_response


def securitytrails_api_error_mock(status_code, text=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text

    return mock_response


def expected_payload(r, body):
    if r.endswith('/deliberate/observables'):
        return {'data': {}}

    if r.endswith('/refer/observables'):
        return {'data': []}

    return body


@fixture(scope='function')
def securitytrails_ping_ok():
    return securitytrails_api_response_mock(
        HTTPStatus.OK, payload=[{"success": True}]
    )


@fixture(scope='session')
def securitytrails_response_unauthorized_creds(secret_key):
    return securitytrails_api_error_mock(
        HTTPStatus.FORBIDDEN,
        'Error: Bad API key'
    )


@fixture(scope='module')
def invalid_jwt_expected_payload(route):
    return expected_payload(route, {
        'errors': [
            {'code': PERMISSION_DENIED,
             'message': 'Invalid Authorization Bearer JWT.',
             'type': 'fatal'}
        ],
        'data': {}
    })


@fixture(scope='module')
def invalid_json_expected_payload(route):
    return expected_payload(
        route,
        {'errors': [
            {'code': INVALID_ARGUMENT,
             'message':
                 'Invalid JSON payload received. '
                 '{"0": {"value": ["Missing data for required field."]}}',
             'type': 'fatal'}],
            'data': {}}
    )


@fixture(scope='module')
def unauthorized_creds_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {'code': PERMISSION_DENIED,
                 'message': ("Unexpected response from SecurityTrails: "
                             "Error: Bad API key"),
                 'type': 'fatal'}
            ],
            'data': {}
        }
    )
