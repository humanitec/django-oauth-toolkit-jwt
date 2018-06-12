import base64
import datetime
import json
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode  # noqa
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import (
    get_application_model, get_access_token_model, get_refresh_token_model)
from oauth2_provider.settings import oauth2_settings
from oauth2_provider_jwt.views import TokenView

Application = get_application_model()
UserModel = get_user_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()


def get_basic_auth_header(user, password):
    """
    Return a dict containg the correct headers to set to make HTTP Basic Auth
    request.
    """
    user_pass = "{0}:{1}".format(user, password)
    auth_string = base64.b64encode(user_pass.encode("utf-8"))
    auth_headers = {
        "HTTP_AUTHORIZATION": "Basic " + auth_string.decode("utf-8"),
    }

    return auth_headers


def payload_enricher(request):
    return {
        'sub': 'unique-user',
    }


class PasswordTokenViewTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.test_user = UserModel.objects.create_user(
            "test_user", "test@example.com", "123456")
        self.dev_user = UserModel.objects.create_user(
            "dev_user", "dev@example.com", "123456")

        self.application = Application(
            name="Test Password Application",
            user=self.dev_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        self.application.save()

        oauth2_settings._SCOPES = ["read", "write"]
        oauth2_settings._DEFAULT_SCOPES = ["read", "write"]

    def tearDown(self):
        self.application.delete()
        self.test_user.delete()
        self.dev_user.delete()

    @override_settings(JWT_ISSUER='api')
    @override_settings(JWT_PRIVATE_KEY_RSA_API='somevalue')
    def test_is_jwt_config_set(self):
        self.assertTrue(TokenView._is_jwt_config_set())

    @override_settings(JWT_ISSUER='')
    @override_settings(JWT_PRIVATE_KEY_RSA_API='somevalue')
    def test_is_jwt_config_not_set_missing_issuer(self):
        self.assertFalse(TokenView._is_jwt_config_set())

    @override_settings()
    @override_settings(JWT_PRIVATE_KEY_RSA_API='somevalue')
    def test_is_jwt_config_not_set_none_issuer(self):
        del settings.JWT_ISSUER
        self.assertFalse(TokenView._is_jwt_config_set())

    @override_settings(JWT_ISSUER='api')
    @override_settings(JWT_PRIVATE_KEY_RSA_API='')
    def test_is_jwt_config_not_set_missing_private_key(self):
        self.assertFalse(TokenView._is_jwt_config_set())

    def test_get_token(self):
        """
        Request an access token using Resource Owner Password Flow
        """
        token_request_data = {
            "grant_type": "password",
            "username": "test_user",
            "password": "123456",
        }
        auth_headers = get_basic_auth_header(self.application.client_id,
                                             self.application.client_secret)

        response = self.client.post(
            reverse("oauth2_provider_jwt:token"), data=token_request_data,
            **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertIn(type(content["access_token_jwt"]).__name__,
                      ('unicode', 'str'))
        self.assertEqual(content["scope"], "read write")
        self.assertEqual(content["expires_in"],
                         oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    @patch('oauth2_provider_jwt.views.TokenView._is_jwt_config_set')
    def test_do_not_get_token_missing_conf(self, mock_is_jwt_config_set):
        """
        Request an access token using Resource Owner Password Flow
        """
        mock_is_jwt_config_set.return_value = False

        token_request_data = {
            "grant_type": "password",
            "username": "test_user",
            "password": "123456",
        }
        auth_headers = get_basic_auth_header(self.application.client_id,
                                             self.application.client_secret)

        response = self.client.post(
            reverse("oauth2_provider_jwt:token"), data=token_request_data,
            **auth_headers)
        self.assertEqual(response.status_code, 200)

        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["token_type"], "Bearer")
        self.assertNotIn("access_token_jwt", content)
        self.assertEqual(content["scope"], "read write")
        self.assertEqual(content["expires_in"],
                         oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    @override_settings(
        JWT_PAYLOAD_ENRICHER='tests.test_views.payload_enricher')
    def test_get_enriched_jwt(self):
        token_request_data = {
            "grant_type": "password",
            "username": "test_user",
            "password": "123456",
        }
        auth_headers = get_basic_auth_header(self.application.client_id,
                                             self.application.client_secret)

        response = self.client.post(
            reverse("oauth2_provider_jwt:token"), data=token_request_data,
            **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        access_token_jwt = content["access_token_jwt"]
        headers, payload, verify_signature = access_token_jwt.split(".")
        payload += '=' * (-len(payload) % 4)  # add padding
        payload_dict = json.loads(base64.b64decode(payload).decode("utf-8"))
        self.assertDictContainsSubset({'sub': 'unique-user'}, payload_dict)

    def test_refresh_token(self):
        access_token = AccessToken.objects.create(
            user=self.test_user, token="1234567890",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read write"
        )
        refresh_token = RefreshToken.objects.create(
            access_token=access_token,
            user=self.test_user,
            application=self.application
        )

        request_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token.token,
        }
        auth_headers = get_basic_auth_header(self.application.client_id,
                                             self.application.client_secret)
        response = self.client.post(
            reverse("oauth2_provider_jwt:token"), data=request_data,
            **auth_headers)
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        self.assertIn(type(content["access_token_jwt"]).__name__,
                      ('unicode', 'str'))
