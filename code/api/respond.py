from flask import Blueprint

from api.utils import jsonify_data

respond_api = Blueprint('respond', __name__)


@respond_api.route('/respond/observables', methods=['POST'])
def respond_observables():
    return jsonify_data([])


@respond_api.route('/respond/trigger', methods=['POST'])
def respond_trigger():
    # There are no actions to trigger.
    return jsonify_data({'status': 'failure'})
