from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from django.utils.encoding import smart_str
import jwt
from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)

from .utils import decode_jwt


class JwtToken(dict):
    """
    Mimics the structure of `AbstractAccessToken` so you can use standard
    Django Oauth Toolkit permissions like `TokenHasScope`.
    """
    def __init__(self, payload):
        super(JwtToken, self).__init__(**payload)

    def __getattr__(self, item):
        return self[item]

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.

        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        # Token expiration is already checked
        return False

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes

        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)


class JWTAuthentication(BaseAuthentication):
    """
    Token based authentication using the JSON Web Token standard.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self._get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = decode_jwt(jwt_value)
        except jwt.ExpiredSignatureError:
            msg = 'Signature has expired.'
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = 'Error decoding signature.'
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        self._add_session_details(request, payload)

        user = self.authenticate_credentials(payload)
        return user, JwtToken(payload)

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        if getattr(settings, 'JWT_AUTH_DISABLED', False):
            return AnonymousUser()

        User = get_user_model()
        username = payload.get(getattr(settings, 'JWT_ID_ATTRIBUTE'))

        if not username:
            msg = 'Invalid payload.'
            raise exceptions.AuthenticationFailed(msg)

        try:
            kwargs = {
                getattr(settings, 'JWT_ID_ATTRIBUTE'): username
            }
            user = User.objects.get(**kwargs)
        except User.DoesNotExist:
            msg = 'Invalid signature.'
            raise exceptions.AuthenticationFailed(msg)

        if not user.is_active:
            msg = 'User account is disabled.'
            raise exceptions.AuthenticationFailed(msg)

        return user

    def _get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = getattr(settings, 'JWT_AUTH_HEADER_PREFIX', 'JWT')

        if not auth:
            if getattr(settings, 'JWT_AUTH_COOKIE', None):
                return request.COOKIES.get(settings.JWT_AUTH_COOKIE)
            return None

        if smart_str(auth[0]) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = 'Invalid Authorization header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = ('Invalid Authorization header. Credentials string '
                   'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        jwt_value = auth[1]
        if type(jwt_value) is bytes:
            jwt_value = jwt_value.decode('utf-8')
        return jwt_value

    def _add_session_details(self, request, payload):
        """
        Adds to the session payload details so they can be used anytime.
        """
        try:
            items = payload.iteritems()
        except AttributeError:  # python 3.6
            items = payload.items()
        for k, v in items:
            if k not in ('iat', 'exp'):
                request.session['jwt_{}'.format(k)] = v

    def authenticate_header(self, _request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        auth_header_prefix = getattr(settings, 'JWT_AUTH_HEADER_PREFIX', 'JWT')
        return '{0} realm="{1}"'.format(auth_header_prefix,
                                        self.www_authenticate_realm)
