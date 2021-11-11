from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from .utils import headers
from ..conftest import securitytrails_api_response_mock
from ..mock_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT


def routes():
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


IP_OBSERVABLE = {'type': 'ip', 'value': '1.1.1.1'}
DOMAIN_OBSERVABLE = {'type': 'domain', 'value': 'cisco.com'}


def test_enrich_call_with_authorization_header_failure(
        route, client, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Authorization header is missing'
    )


def test_enrich_call_with_wrong_authorization_type(
        route, client, valid_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(), auth_type='wrong_type')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong authorization type'
    )


def test_enrich_call_with_wrong_jwt_structure(
        route, client, valid_jwt, valid_json,
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
    response = client.post(
        route, json=valid_json,
        headers=header)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT structure'
    )


def test_enrich_call_with_wrong_jwt_payload_structure(
        route, client, valid_jwt, valid_json,
        authorization_errors_expected_payload,
        mock_request
):
    mock_request.return_value = \
        securitytrails_api_response_mock(
            payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
        )
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(wrong_structure=True))
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        'Wrong JWT payload structure'
    )


@fixture(scope='module')
def invalid_json():
    return [{'type': 'domain'}]


def test_enrich_call_with_valid_jwt_but_invalid_json_failure(
        route, client, valid_jwt,
        invalid_json, invalid_json_expected_payload,
        mock_request
):
    mock_request.return_value = \
        securitytrails_api_response_mock(
            payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
        )
    response = client.post(route,
                           headers=headers(valid_jwt()),
                           json=invalid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


@fixture(scope='module')
def valid_json():
    return [DOMAIN_OBSERVABLE]


def test_enrich_call_with_unauthorized_creds_failure(
        route, client, valid_jwt,
        securitytrails_response_unauthorized_creds,
        authorization_errors_expected_payload, valid_json,
        mock_request
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = securitytrails_response_unauthorized_creds
        mock_request.return_value = \
            securitytrails_api_response_mock(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            )
        response = client.post(
            route, headers=headers(valid_jwt()), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            'Invalid authentication credentials'
        )


def observables():
    yield DOMAIN_OBSERVABLE
    yield IP_OBSERVABLE


@fixture(scope='module', params=observables(), ids=lambda ob: f'{ob["type"]}')
def observable(request):
    return request.param


def test_enrich_call_success(
        route, client, valid_jwt, observable,
        success_enrich_client_data,
        success_enrich_expected_payload,
        mock_request
):
    with patch('requests.request') as get_mock:
        get_mock.side_effect = success_enrich_client_data
        mock_request.return_value = \
            securitytrails_api_response_mock(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            )
        response = client.post(
            route, headers=headers(valid_jwt()), json=[observable]
        )

        assert response.status_code == HTTPStatus.OK

        response = response.get_json()
        assert response.get('errors') is None

        if response.get('data') and isinstance(response['data'], dict):
            for s in response['data'].get('sightings', {}).get('docs', []):
                assert s.pop('id')
                assert s.pop('observed_time')

        assert response == success_enrich_expected_payload


def test_enrich_success_with_bad_request(
        client, valid_jwt, valid_json,
        securitytrails_response_bad_request,
        mock_request
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = securitytrails_response_bad_request
        mock_request.return_value = \
            securitytrails_api_response_mock(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            )
        response = client.post(
            '/observe/observables', headers=headers(valid_jwt()),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {}}


def test_enrich_call_success_with_extended_error_handling(
        client, valid_jwt,
        securitytrails_domain_list_ok, securitytrails_response_bad_request,
        securitytrails_response_unauthorized_creds,
        success_enrich_observe_ip_body, unauthorized_creds_body,
        mock_request
):
    with patch('requests.request') as get_mock:
        get_mock.side_effect = [securitytrails_domain_list_ok,
                                securitytrails_response_bad_request,
                                securitytrails_response_unauthorized_creds,
                                securitytrails_domain_list_ok]
        mock_request.return_value = \
            securitytrails_api_response_mock(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            )
        response = client.post(
            '/observe/observables', headers=headers(valid_jwt()),
            json=[IP_OBSERVABLE,
                  {'type': 'domain', 'value': '1'},
                  DOMAIN_OBSERVABLE,
                  {'type': 'ip', 'value': '2.2.2.2'}]
        )

        assert response.status_code == HTTPStatus.OK

        response = response.get_json()

        assert response['data']['sightings']['docs'][0].pop('id')
        assert response['data']['sightings']['docs'][0].pop('observed_time')

        assert response['data'] == success_enrich_observe_ip_body['data']
        assert response['errors'] == unauthorized_creds_body['errors']


def test_enrich_call_with_key_error(
        client, valid_jwt, valid_json, key_error_body, mock_request
):
    with patch('api.enrich.SecurityTrailsClient.get_data') as get_mock, \
            patch('api.enrich.Mapping.extract_sighting') as extract_mock:
        get_mock.side_effect = ['some_record']
        extract_mock.side_effect = [KeyError('foo')]
        mock_request.return_value = \
            securitytrails_api_response_mock(
                payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
            )

        response = client.post(
            '/observe/observables', headers=headers(valid_jwt()),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == key_error_body
