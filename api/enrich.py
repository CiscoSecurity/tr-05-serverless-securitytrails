from functools import partial

from flask import Blueprint, current_app, g

from api.client import SecurityTrailsClient
from api.mappings import Mapping
from api.schemas import ObservableSchema
from api.utils import get_json, jsonify_data, get_key, jsonify_result

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
                                  current_app.config['USER_AGENT'],
                                  current_app.config['NUMBER_OF_PAGES'])
    g.sightings = []

    for x in observables:
        mapping = Mapping.for_(x)

        if mapping:
            client_data = client.get_data(x)
            for record in client_data:
                g.sightings.extend(
                    mapping.extract_sightings(record)
                )

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    return jsonify_data([])
