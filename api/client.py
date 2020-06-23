from http import HTTPStatus

import requests

from api.errors import CriticalSecurityTrailsResponseError
from api.utils import join_url

NOT_CRITICAL_ERRORS = (
    HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.NOT_ACCEPTABLE
)

IP = 'ip'
IPV6 = 'ipv6'
DOMAIN = 'domain'


class SecurityTrailsClient:
    OBSERVABLE_TO_FILTER_TYPE = {IP: 'ipv4', IPV6: 'ipv6'}

    def __init__(self, base_url, api_key, user_agent, number_of_pages=1):
        self.base_url = base_url
        self.headers = {
            'Accept': 'application/json',
            'APIKEY': api_key,
            'User-Agent': user_agent
        }
        self.number_of_pages = number_of_pages

    def ping(self):
        """
        https://docs.securitytrails.com/reference#ping
        """
        return self._request('ping')

    def get_data(self, observable):
        observable_type = observable['type']

        if observable_type == DOMAIN:
            return (self._get_pages(observable, self._history, type_='a'),
                    self._get_pages(observable, self._history, type_='aaaa'))

        if observable_type in (IP, IPV6):
            return self._get_pages(observable, self._domain_list)

        else:
            return {}

    def _history(self, observable, type_, page=1):
        """
        https://docs.securitytrails.com/reference#history-dns
        type must be one of 'a', 'aaaa'
        """
        return self._request(
            f'history/{observable["value"]}/dns/{type_}',
            page=page
        )

    def _domain_list(self, observable, page=1):
        """
        https://docs.securitytrails.com/reference#domain-search
        """

        filter_type = self.OBSERVABLE_TO_FILTER_TYPE.get(observable['type'])

        body = {
            "filter": {
                filter_type: observable['value']
            }
        }
        return self._request('domains/list', 'POST', body, page=page)

    def _need_all_pages(self):
        return self.number_of_pages == 0

    def _get_pages(self, observable, endpoint, *args, **kwargs):
        def max_possible_page(data):
            return (data.get('pages')
                    or data.get('meta', {}).get('max_page')
                    or 0)

        data = endpoint(observable, *args, **kwargs)

        if data and self.number_of_pages != 1:

            max_page = max_possible_page(data)
            if self.number_of_pages < max_page and not self._need_all_pages():
                max_page = self.number_of_pages

            for page in range(2, max_page + 1):
                r = endpoint(observable, *args, page=page, **kwargs)
                if r and r.get('records'):
                    data['records'].extend(r['records'])
                else:
                    break

        return data

    def _request(self, path, method='GET', body=None, page=1):
        params = {'page': page}
        url = join_url(self.base_url, path)

        response = requests.request(
            method, url, headers=self.headers, json=body, params=params
        )

        if response.ok:
            return response.json()

        if response.status_code in NOT_CRITICAL_ERRORS:
            return []

        raise CriticalSecurityTrailsResponseError(response)
