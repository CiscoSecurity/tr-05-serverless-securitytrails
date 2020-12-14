import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)

    API_URL = 'https://api.securitytrails.com/v1/'
    UI_URL = 'https://securitytrails.com/'

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    NUMBER_OF_PAGES_DEFAULT = 1
    try:
        NUMBER_OF_PAGES = int(os.environ['NUMBER_OF_PAGES'])
        assert NUMBER_OF_PAGES >= 0
    except (KeyError, ValueError, AssertionError):
        NUMBER_OF_PAGES = NUMBER_OF_PAGES_DEFAULT
