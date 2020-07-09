from functools import partial

from flask import Blueprint, current_app, g

from api.client import SecurityTrailsClient, ST_OBSERVABLE_TYPES
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

    for observable in observables:
        mapping = Mapping.for_(observable)

        if mapping:
            client_data = client.get_data(observable)

            for record in client_data:
                refer_link = client.refer_link(current_app.config['UI_URL'],
                                               observable)
                sighting = mapping.extract_sighting(record, refer_link)
                if sighting:
                    g.sightings.append(sighting)

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    observables = get_observables()

    ui_url = current_app.config['UI_URL']

    def type_of(observable):
        return ST_OBSERVABLE_TYPES[observable['type']]

    data = [
        {
            'id': 'ref-securitytrails-search-{type}-{value}'.format(
                **observable),
            'title': f'Search for this {type_of(observable)}',
            'description': (
                f'Lookup this {type_of(observable)} '
                'on SecurityTrails'
            ),
            'url': SecurityTrailsClient.refer_link(ui_url, observable),
            'categories': ['Search', 'SecurityTrails'],
        }
        for observable in observables
    ]

    return jsonify_data(data)
