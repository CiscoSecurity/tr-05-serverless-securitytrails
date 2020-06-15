from http import HTTPStatus

import requests

from api.errors import (
    UnexpectedSecurityTrailsResponseError
)
from api.utils import join_url

NOT_CRITICAL_ERRORS = (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND)


class SecurityTrailsClient:
    def __init__(self, base_url, api_key, user_agent):
        self.base_url = base_url
        self.headers = {
            'Accept': 'application/json',
            'APIKEY': api_key,
            'User-Agent': user_agent
        }

    def _request(self, path, method='GET', body=None):
        url = join_url(self.base_url, path)

        response = requests.request(
            method, url, headers=self.headers, json=body
        )

        if response.ok:
            return response.json()

        if response.status_code in NOT_CRITICAL_ERRORS:
            return []

        raise UnexpectedSecurityTrailsResponseError(response)

    def ping(self):
        return self._request('ping')

    def _history(self, observable, type_):  # type 'a', 'aaaa'
        return self._request(f'history/{observable["value"]}/dns/{type_}')

    def _domain_search(self, observable):
        type_ = {'ip': 'ipv4', 'ipv6': 'ipv6'}.get(observable['type'])
        body = {
            "filter": {
                type_: observable['value']
            }
        }
        return self._request('domains/list', 'POST', body)

    def get_data(self, observable):
        type_ = observable['type']

        if type_ == 'domain':
            result = []
            for ip_type in ('a', 'aaaa'):
                history = self._history(observable, ip_type)
                if history:
                    result.append(history)
            return result

        if type_ in ('ip', 'ipv6'):
            return self._domain_search(observable)

        return []
