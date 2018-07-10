import ast
import json
import logging

from django.conf import settings
from django.utils.module_loading import import_string
from oauth2_provider import views

from .utils import generate_payload, encode_jwt

logger = logging.getLogger(__name__)


class TokenView(views.TokenView):
    def _get_access_token_jwt(self, request, expires_in):
        extra_data = {}
        issuer = settings.JWT_ISSUER
        payload_enricher = getattr(settings, 'JWT_PAYLOAD_ENRICHER', None)
        if payload_enricher:
            fn = import_string(payload_enricher)
            extra_data = fn(request)
        if request.POST.get('username'):
            extra_data['username'] = request.POST.get('username')
        payload = generate_payload(issuer, expires_in, **extra_data)
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
                content['access_token_jwt'] = self._get_access_token_jwt(
                    request, content['expires_in'])
                try:
                    content = bytes(json.dumps(content), 'utf-8')
                except TypeError:
                    content = bytes(json.dumps(content).encode("utf-8"))
                response.content = content
        return response
