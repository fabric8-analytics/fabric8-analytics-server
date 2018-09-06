"""Authorization token handling."""
from flask import current_app, request
from requests import get

from .default_config import AUTH_URL


def get_access_token(service_name):
    """Return the access token for service."""
    services = {'github': 'https://github.com'}
    url = '{auth_url}/api/token?for={service}'.format(
        auth_url=AUTH_URL, service=services.get(service_name))
    token = request.headers.get('Authorization')
    headers = {"Authorization": token}
    try:
        _response = get(url, headers=headers)
        if _response.status_code == 200:
            response = _response.json()
            return {"access_token": response.get('access_token')}
        else:
            return {"access_token": None}

    except Exception:
        current_app.logger.error("Unable to connect to Auth service")
