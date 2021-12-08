import sys
import time
import requests

from os import cpu_count
from http import HTTPStatus
from requests.exceptions import SSLError, InvalidHeader
from api.utils import join_url, add_error
from concurrent.futures.thread import ThreadPoolExecutor

from api.errors import (
    CriticalSecurityTrailsResponseError,
    UnprocessedPagesWarning,
    SecurityTrailsSSLError,
    AuthorizationError
)

NOT_CRITICAL_ERRORS = (
    HTTPStatus.BAD_REQUEST,
    HTTPStatus.NOT_FOUND,
    HTTPStatus.NOT_ACCEPTABLE
)

IP = 'ip'
IPV6 = 'ipv6'
DOMAIN = 'domain'

ST_OBSERVABLE_TYPES = {
    IP: 'IP',
    IPV6: 'IPv6',
    DOMAIN: 'domain',
}

INVALID_CREDENTIALS = 'Invalid authentication credentials'


def add_pause(func, *args, min_execution_time=1.1, **kwargs):
    # Add delay to func execution to prevent rate limit errors
    start = time.time()
    result = func(*args, **kwargs)
    pause_time = min_execution_time - (time.time() - start)
    if pause_time > 0:
        time.sleep(pause_time)
    return result


class SecurityTrailsClient:
    OBSERVABLE_TO_FILTER_TYPE = {IP: 'ipv4', IPV6: 'ipv6'}

    def __init__(self, base_url, api_key, user_agent,
                 number_of_pages=1, all_pages=False):
        self.base_url = base_url
        self.headers = {
            'Accept': 'application/json',
            'APIKEY': api_key,
            'User-Agent': user_agent
        }

        # Value 0 in number_of_pages or True in all_pages
        # parameter means that user need all pages.
        self.number_of_pages = (
            sys.maxsize if number_of_pages == 0 or all_pages
            else number_of_pages
        )

    def ping(self):
        """
        https://docs.securitytrails.com/reference#ping
        """
        return self._request('ping')

    @staticmethod
    def refer_link(ui_url, observable):
        observable_type = observable['type']

        if observable_type == DOMAIN:
            return join_url(ui_url, f'/domain/{observable["value"]}/dns')

        if observable_type in (IP, IPV6):
            return join_url(ui_url, f'/list/ip/{observable["value"]}')

    def get_data(self, observable):
        observable_type = observable['type']

        if observable_type == DOMAIN:
            return (self._get_pages(observable, self._history, type_='a'),
                    self._get_pages(observable, self._history, type_='aaaa'))

        if observable_type in (IP, IPV6):
            return (self._get_pages(observable, self._domain_list),)

        else:
            return ()

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

        def get_page(p):
            return add_pause(endpoint, observable, *args, page=p, **kwargs)

        data = get_page(1)

        if data and data.get('records') and self.number_of_pages > 1:
            rate_limit = self._rate_limit()
            max_page = extract(data, 'max_page')
            total_pages = extract(data, 'total_pages')
            pages_left = 0

            if self.number_of_pages < max_page:
                max_page = self.number_of_pages
            elif max_page < total_pages:
                pages_left = total_pages - max_page

            with ThreadPoolExecutor(
                    max_workers=min(rate_limit, (cpu_count() or 1) * 5)
            ) as executor:
                iterator = executor.map(
                    get_page, [page for page in range(2, max_page + 1)]
                )

            for r in iterator:
                if r and r.get('records'):
                    data['records'].extend(r['records'])
                else:
                    break

            if pages_left:
                add_error(
                    UnprocessedPagesWarning(observable['value'], pages_left)
                )

        return data

    def _request(
            self, path, method='GET', body=None, page=1,
            data_extractor=lambda r: r.json()
    ):
        params = {'page': page}
        url = join_url(self.base_url, path)

        try:
            response = requests.request(
                method, url, headers=self.headers, json=body, params=params
            )
        except SSLError as error:
            raise SecurityTrailsSSLError(error)
        except (UnicodeEncodeError, InvalidHeader):
            raise AuthorizationError(INVALID_CREDENTIALS)

        # catch wrong API key
        if response.status_code == HTTPStatus.FORBIDDEN:
            raise AuthorizationError(
                response.json().get('message') or response.text
            )

        if response.ok:
            return data_extractor(response)

        if response.status_code in NOT_CRITICAL_ERRORS:
            return {}

        raise CriticalSecurityTrailsResponseError(response)

    def _rate_limit(self):
        response_headers = add_pause(
            self._request, 'ping', data_extractor=lambda r: r.headers
        )
        if response_headers:
            return int(
                response_headers.get('X-RateLimit-Limit-second', sys.maxsize)
            )
