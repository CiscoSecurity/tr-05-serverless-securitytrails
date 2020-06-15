from functools import partial

from flask import Blueprint, current_app

from api.client import SecurityTrailsClient
from api.schemas import ObservableSchema
from api.utils import get_json, jsonify_data, get_key

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    key = get_key()
    observables = get_observables()

    client = SecurityTrailsClient(current_app.config['API_URL'],
                                  key,
                                  current_app.config['USER_AGENT'])

    data = []
    for x in observables:
        x_data = client.get_data(x)
        if x_data:
            data.append(x_data)

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    return jsonify_data([])
