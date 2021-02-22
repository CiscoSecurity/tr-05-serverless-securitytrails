import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]

    API_URL = 'https://api.securitytrails.com/v1/'
    UI_URL = 'https://securitytrails.com/'

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    NUMBER_OF_PAGES_DEFAULT = 1
