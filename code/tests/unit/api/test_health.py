from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests.exceptions import SSLError

from .utils import headers
from ..conftest import securitytrails_api_response_mock
from ..mock_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_authorization_header_failure(
        route, client,
        authorization_errors_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Authorization header is missing'
    )


def test_health_call_with_wrong_authorization_type(
        route, client, valid_jwt,
        authorization_errors_expected_payload,
        mock_request
):
    mock_request.return_value = \
        securitytrails_api_response_mock(
            payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
        )
    response = client.post(
        route, headers=headers(valid_jwt(), auth_type='wrong_type')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong authorization type'
    )


def test_health_call_with_wrong_jwt_structure(
        route, client, valid_jwt,
        authorization_errors_expected_payload,
        mock_request
):
    mock_request.return_value = \
        securitytrails_api_response_mock(
            payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
        )
    header = {
        'Authorization': 'Bearer bad_jwt_token'
    }
    response = client.post(route, headers=header)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT structure'
    )


def test_health_call_with_wrong_jwt_payload_structure(
        route, client, valid_jwt,
        authorization_errors_expected_payload,
        mock_request
):
    mock_request.return_value = \
        securitytrails_api_response_mock(
            payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
        )
    response = client.post(route,
                           headers=headers(valid_jwt(wrong_structure=True)))

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT payload structure'
    )


def test_health_call_with_unauthorized_creds_failure(
        route, client, valid_jwt,
        securitytrails_response_unauthorized_creds,
        authorization_errors_expected_payload,
        mock_request
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = securitytrails_response_unauthorized_creds
        mock_request.return_value = \
            securitytrails_api_response_mock(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            )
        response = client.post(
            route, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            'Invalid authentication credentials'
        )


def test_health_call_with_ssl_error_failure(
        route, client, valid_jwt,
        sslerror_expected_payload,
        mock_request
):
    with patch('requests.request') as get_mock:
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        get_mock.side_effect = SSLError(mock_exception)
        mock_request.return_value = \
            securitytrails_api_response_mock(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            )
        response = client.post(
            route, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload


def test_health_call_success(route, client, valid_jwt,
                             securitytrails_ping_ok, mock_request):
    with patch('requests.request') as get_mock:
        get_mock.return_value = securitytrails_ping_ok
        mock_request.return_value = \
            securitytrails_api_response_mock(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            )
        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
