import base64
from datetime import datetime, timedelta
import json
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch
from unittest import TestCase as PythonTestCase

from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from oauth2_provider_jwt import utils


class GeneratePayloadTest(PythonTestCase):
    def _get_payload_args(self):
        issuer = 'activityapi'
        expires_in = 36000
        return issuer, expires_in

    @patch('oauth2_provider_jwt.utils.datetime')
    def test_generate_payload_no_extra_data(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now
        issuer, expires_in = self._get_payload_args()
        expiration = now + timedelta(seconds=expires_in)

        self.assertEqual(
            utils.generate_payload(issuer, expires_in),
            {
                'iss': issuer,
                'exp': expiration,
                'iat': now,
            }
        )

    @patch('oauth2_provider_jwt.utils.datetime')
    def test_generate_payload_with_extra_data(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now

        issuer, expires_in = self._get_payload_args()
        expiration = now + timedelta(seconds=expires_in)

        extra_data = {
            'usr': 'some_usr',
            'org': 'some_org',
            'sub': 'subject',
        }

        self.assertEqual(
            utils.generate_payload(issuer, expires_in, **extra_data),
            {
                'iss': issuer,
                'exp': expiration,
                'iat': now,
                'sub': 'subject',
                'usr': 'some_usr',
                'org': 'some_org',
            }
        )


class EncodePayloadTest(PythonTestCase):
    def _get_payload(self):
        now = datetime.utcnow()
        return {
            'iss': 'issuer',
            'exp': now + timedelta(seconds=10),
            'iat': now,
            'sub': 'subject',
            'usr': 'some_usr',
            'org': 'some_org',
        }

    @override_settings(JWT_PRIVATE_KEY_RSA_ISSUER='')
    def test_encode_payload_no_private_key_in_setting(self):
        payload = self._get_payload()
        self.assertRaises(ImproperlyConfigured,
                          utils.encode_payload, payload)

    def test_encode_payload(self):
        payload_in = self._get_payload()
        encoded = utils.encode_payload(payload_in)
        self.assertIn(type(encoded).__name__, ('unicode', 'str'))
        headers, payload, verify_signature = encoded.split(".")
        self.assertDictEqual(
            json.loads(base64.b64decode(headers)),
            {"typ": "JWT", "alg": "RS256"})
        payload += '=' * (-len(payload) % 4)  # add padding
        self.assertEqual(
            json.loads(base64.b64decode(payload).decode("utf-8")),
            payload_in)
