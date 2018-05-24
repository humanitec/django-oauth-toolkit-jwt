import base64
import json

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse
from oauth2_provider.models import get_application_model
from oauth2_provider.settings import oauth2_settings

Application = get_application_model()
UserModel = get_user_model()


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


class BaseTest(TestCase):
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


class TestPasswordTokenView(BaseTest):
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
        self.assertEqual(content["scope"], "read write")
        self.assertEqual(content["expires_in"],
                         oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
