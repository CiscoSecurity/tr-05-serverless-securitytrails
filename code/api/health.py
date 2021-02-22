from flask import Blueprint, current_app

from api.client import SecurityTrailsClient
from api.utils import jsonify_data, get_key

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_key()

    client = SecurityTrailsClient(current_app.config['API_URL'],
                                  key,
                                  current_app.config['USER_AGENT'])

    _ = client.ping()

    return jsonify_data({'status': 'ok'})
