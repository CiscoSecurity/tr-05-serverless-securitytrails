import json
from typing import Union

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError
from flask import request, current_app, jsonify, g

from api.errors import InvalidArgumentError, AuthorizationError


def get_auth_token() -> Union[str, Exception]:
    """Parse the incoming request's Authorization header and Validate it."""
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt() -> Union[dict, Exception]:
    """
    Get Authorization payload and validate its signature
    according the application's secret key .
    """
    expected_errors = {
        AssertionError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    try:
        payload = jwt.decode(get_auth_token(), current_app.config['SECRET_KEY'])
        assert tuple(payload) == ('key',)
        return payload
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_key() -> Union[str, Exception]:
    """Get key from authorization payload."""
    return get_jwt()['key']


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    Note. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(
            f'Invalid JSON payload received. {json.dumps(message)}'
        )

    return data


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_result():
    result = {'data': {}}

    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)

    if g.get('errors'):
        result['errors'] = g.errors

    return jsonify(result)


def add_error(error):
    g.errors = [*g.get('errors', []), error.json]


def join_url(base, *parts):
    return '/'.join(
        [base.rstrip('/')] +
        [part.strip('/') for part in parts]
    )


def all_subclasses(cls):
    """
    Retrieve set of class subclasses recursively.

    """
    subclasses = set(cls.__subclasses__())
    return subclasses.union(s for c in subclasses for s in all_subclasses(c))
