import ast
import json
import logging

from django.conf import settings
from django.utils.module_loading import import_string
from oauth2_provider import views
from oauth2_provider.models import get_access_token_model

from .utils import generate_payload, encode_jwt

logger = logging.getLogger(__name__)


class WrongUsername(Exception):
    pass


class TokenView(views.TokenView):
    def _get_access_token_jwt(self, request, content):
        extra_data = {}
        issuer = settings.JWT_ISSUER
        payload_enricher = getattr(settings, 'JWT_PAYLOAD_ENRICHER', None)
        if payload_enricher:
            fn = import_string(payload_enricher)
            extra_data = fn(request)

        if 'scope' in content:
            extra_data['scope'] = content['scope']

        username = request.POST.get('username')
        if username:
            # HACK: The only way to verify the username is to check the token.
            #       This means an extra wasted database call
            token = get_access_token_model().objects.get(
                token=content['access_token']
            )
            if token.user.get_username() != username:
                raise WrongUsername()
            extra_data['username'] = username

        payload = generate_payload(issuer, content['expires_in'], **extra_data)
        token = encode_jwt(payload)
        return token

    @staticmethod
    def _is_jwt_config_set():
        issuer = getattr(settings, 'JWT_ISSUER', '')
        private_key_name = 'JWT_PRIVATE_KEY_RSA_{}'.format(issuer.upper())
        private_key = getattr(settings, private_key_name, None)
        if issuer and private_key:
            return True
        else:
            return False

    def post(self, request, *args, **kwargs):
        response = super(TokenView, self).post(request, *args, **kwargs)

        content = ast.literal_eval(response.content.decode("utf-8"))
        if response.status_code == 200 and 'access_token' in content:
            if not TokenView._is_jwt_config_set():
                logger.warning(
                    'Missing JWT configuration, skipping token build')
            else:
                try:
                    content['access_token_jwt'] = self._get_access_token_jwt(
                        request, content)
                    try:
                        content = bytes(json.dumps(content), 'utf-8')
                    except TypeError:
                        content = bytes(json.dumps(content).encode("utf-8"))
                    response.content = content
                except WrongUsername:
                    response.status_code = 400
                    response.content = json.dumps({
                        "error": "invalid_request",
                        "error_description": "Request username doesn't match"
                                             "username in original authorize",
                    })
        return response
