import ast
import json
import logging

from urllib.parse import urlencode, urlparse, parse_qs  # noqa

from django.conf import settings
from django.utils.module_loading import import_string
from oauth2_provider import views
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_access_token_model

from .utils import generate_payload, encode_jwt

logger = logging.getLogger(__name__)


class MissingIdAttribute(Exception):
    pass


class JWTAuthorizationView(views.AuthorizationView):

    def get(self, request, *args, **kwargs):
        response = super(JWTAuthorizationView, self).get(request, *args,
                                                         **kwargs)
        if request.GET.get('response_type', None) == 'token' \
                and response.status_code == 302:
            url = urlparse(response.url)
            params = parse_qs(url.fragment)
            if params:
                content = {
                    'access_token': params['access_token'][0],
                    'expires_in': int(params['expires_in'][0]),
                    'scope': params['scope'][0]
                }
                jwt = TokenView()._get_access_token_jwt(request, content)
                response = OAuth2ResponseRedirect(
                    '{}&access_token_jwt={}'.format(response.url, jwt),
                    response.allowed_schemes)
        return response


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

        id_attribute = getattr(settings, 'JWT_ID_ATTRIBUTE', None)
        if id_attribute:
            token = get_access_token_model().objects.get(
                token=content['access_token']
            )
            id_value = getattr(token.user, id_attribute, None)
            if not id_value:
                raise MissingIdAttribute()
            extra_data[id_attribute] = str(id_value)

        payload = generate_payload(issuer, content['expires_in'], **extra_data)
        token = encode_jwt(payload)
        return token

    @staticmethod
    def _is_jwt_config_set():
        issuer = getattr(settings, 'JWT_ISSUER', '')
        private_key_name = 'JWT_PRIVATE_KEY_{}'.format(issuer.upper())
        private_key = getattr(settings, private_key_name, None)
        id_attribute = getattr(settings, 'JWT_ID_ATTRIBUTE', None)
        if issuer and private_key and id_attribute:
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
                except MissingIdAttribute:
                    response.status_code = 400
                    response.content = json.dumps({
                        "error": "invalid_request",
                        "error_description": "App not configured correctly. "
                                             "Please set JWT_ID_ATTRIBUTE.",
                    })
        return response
