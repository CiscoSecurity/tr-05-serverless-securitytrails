from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_without_jwt_failure(
        route, client, invalid_jwt_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_health_call_with_invalid_jwt_failure(
        route, client, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_health_call_with_unauthorized_creds_failure(
        route, client, valid_jwt,
        securitytrails_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = securitytrails_response_unauthorized_creds
        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload


def test_health_call_success(route, client, valid_jwt, securitytrails_ping_ok):
    with patch('requests.request') as get_mock:
        get_mock.return_value = securitytrails_ping_ok
        response = client.post(route, headers=headers(valid_jwt))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
