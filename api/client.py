import sys
from http import HTTPStatus

import requests

from api.errors import (
    CriticalSecurityTrailsResponseError,
    UnprocessedPagesWarning
)
from api.utils import join_url, add_error

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

        # Value 0 means that user need all pages.
        self.number_of_pages = (
            sys.maxsize if number_of_pages == 0 else number_of_pages
        )

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
            return self._get_pages(observable, self._domain_list),

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

    def _get_pages(self, observable, endpoint, *args, **kwargs):
        def extract(response, meta_field):
            return (response.get('pages')
                    or response.get('meta', {}).get(meta_field)
                    or 0)

        data = endpoint(observable, *args, **kwargs)

        if data and self.number_of_pages > 1:
            max_page = extract(data, 'max_page')
            total_pages = extract(data, 'total_pages')

            pages_left = 0
            if self.number_of_pages < max_page:
                max_page = self.number_of_pages
            elif max_page < total_pages:
                pages_left = total_pages - max_page

            for page in range(2, max_page + 1):
                r = endpoint(observable, *args, page=page, **kwargs)
                if r and r.get('records'):
                    data['records'].extend(r['records'])
                else:
                    break

            if pages_left:
                add_error(
                    UnprocessedPagesWarning(observable['value'], pages_left)
                )

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
            return {}

        raise CriticalSecurityTrailsResponseError(response)
