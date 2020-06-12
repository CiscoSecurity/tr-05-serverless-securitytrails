import requests
from flask import Blueprint, current_app

from api.errors import UnexpectedSecurityTrailsResponseError
from api.utils import jsonify_data, get_key

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_key()

    url = join_url(current_app.config['API_URL'], 'ping')

    headers = {
        'Accept': 'application/json',
        'APIKEY': key,
        'User-Agent': current_app.config['USER_AGENT']

    }

    response = requests.get(url, headers=headers)

    if response.ok:
        return jsonify_data({'status': 'ok'})

    raise UnexpectedSecurityTrailsResponseError(response)


def join_url(base, *parts):
    return '/'.join(
        [base.rstrip('/')] +
        [part.strip('/') for part in parts]
    )
