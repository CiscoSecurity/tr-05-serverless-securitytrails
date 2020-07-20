from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from .utils import headers


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


IP_OBSERVABLE = {'type': 'ip', 'value': '1.1.1.1'}
DOMAIN_OBSERVABLE = {'type': 'domain', 'value': 'cisco.com'}


def test_enrich_call_with_invalid_jwt_failure(
        route, client, invalid_jwt, invalid_jwt_expected_payload, valid_json
):
    response = client.post(
        route, headers=headers(invalid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


@fixture(scope='module')
def invalid_json():
    return [{'type': 'domain'}]


def test_enrich_call_with_valid_jwt_but_invalid_json_failure(
        route, client, valid_jwt,
        invalid_json, invalid_json_expected_payload
):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


@fixture(scope='module')
def valid_json():
    return [DOMAIN_OBSERVABLE]


def test_enrich_call_with_unauthorized_creds_failure(
        route, client, valid_jwt,
        securitytrails_response_unauthorized_creds,
        unauthorized_creds_expected_payload, valid_json
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = securitytrails_response_unauthorized_creds
        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_payload


def observables():
    yield DOMAIN_OBSERVABLE
    yield IP_OBSERVABLE


@fixture(scope='module', params=observables(), ids=lambda ob: f'{ob["type"]}')
def observable(request):
    return request.param


def test_enrich_call_success(
        route, client, valid_jwt, observable,
        success_enrich_client_data,
        success_enrich_expected_payload
):
    with patch('requests.request') as get_mock:
        get_mock.side_effect = success_enrich_client_data

        response = client.post(
            route, headers=headers(valid_jwt), json=[observable]
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
        securitytrails_response_bad_request
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = securitytrails_response_bad_request

        response = client.post(
            '/observe/observables', headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {}}


def test_enrich_call_success_with_extended_error_handling(
        client, valid_jwt,
        securitytrails_domain_list_ok, securitytrails_response_bad_request,
        securitytrails_response_unauthorized_creds,
        success_enrich_observe_ip_body, unauthorized_creds_body
):
    with patch('requests.request') as get_mock:
        get_mock.side_effect = [securitytrails_domain_list_ok,
                                securitytrails_response_bad_request,
                                securitytrails_response_unauthorized_creds,
                                securitytrails_domain_list_ok]
        response = client.post(
            '/observe/observables', headers=headers(valid_jwt),
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
        client, valid_jwt, valid_json, kee_error_body
):
    with patch('api.enrich.SecurityTrailsClient.get_data') as get_mock, \
            patch('api.enrich.Mapping.extract_sighting') as extract_mock:
        get_mock.side_effect = ['some_record']
        extract_mock.side_effect = [KeyError('foo')]

        response = client.post(
            '/observe/observables', headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == kee_error_body
