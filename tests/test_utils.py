import base64
from datetime import datetime, timedelta
import json
from unittest.mock import patch
from unittest import TestCase as PythonTestCase

from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
import jwt
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


class EncodeJWTTest(PythonTestCase):
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

    @override_settings(JWT_PRIVATE_KEY_ISSUER='')
    def test_encode_jwt_no_private_key_in_setting(self):
        payload = self._get_payload()
        self.assertRaises(ImproperlyConfigured,
                          utils.encode_jwt, payload)

    def test_encode_jwt_rs256(self):
        payload_in = self._get_payload()
        encoded = utils.encode_jwt(payload_in)
        self.assertIn(type(encoded).__name__, ('unicode', 'str'))
        headers, payload, verify_signature = encoded.split(".")
        self.assertDictEqual(
            json.loads(base64.b64decode(headers)),
            {"typ": "JWT", "alg": "RS256"})
        payload += '=' * (-len(payload) % 4)  # add padding
        self.assertEqual(
            json.loads(base64.b64decode(payload).decode("utf-8")),
            payload_in)

    @override_settings(JWT_PRIVATE_KEY_ISSUER='test')
    @override_settings(JWT_ENC_ALGORITHM='HS256')
    def test_encode_jwt_hs256(self):
        payload_in = self._get_payload()
        encoded = utils.encode_jwt(payload_in)
        self.assertIn(type(encoded).__name__, ('unicode', 'str'))
        headers, payload, verify_signature = encoded.split('.')
        self.assertDictEqual(
            json.loads(base64.b64decode(headers)),
            {'typ': 'JWT', 'alg': 'HS256'})
        payload += '=' * (-len(payload) % 4)
        self.assertEqual(
            json.loads(base64.b64decode(payload).decode('utf-8')),
            payload_in)


class DecodeJWTTest(PythonTestCase):
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

    def test_decode_jwt_invalid(self):
        self.assertRaises(jwt.InvalidTokenError, utils.decode_jwt, 'abc')

    @override_settings(JWT_PUBLIC_KEY_ISSUER='')
    def test_decode_jwt_public_key_not_found(self):
        payload = self._get_payload()
        jwt_value = utils.encode_jwt(payload)
        self.assertRaises(ImproperlyConfigured, utils.decode_jwt,
                          jwt_value)

    def test_decode_jwt_expired(self):
        payload = self._get_payload()
        now = datetime.utcnow()
        payload['exp'] = now - timedelta(seconds=1)
        payload['iat'] = now
        jwt_value = utils.encode_jwt(payload)
        self.assertRaises(jwt.ExpiredSignatureError, utils.decode_jwt,
                          jwt_value)

    def test_decode_jwt_rs256(self):
        payload = self._get_payload()
        jwt_value = utils.encode_jwt(payload)
        payload_out = utils.decode_jwt(jwt_value)
        self.assertDictEqual(payload, payload_out)

    @override_settings(JWT_PRIVATE_KEY_ISSUER='test')
    @override_settings(JWT_PUBLIC_KEY_ISSUER='test')
    @override_settings(JWT_ENC_ALGORITHM='HS256')
    def test_decode_jwt_hs256(self):
        payload = self._get_payload()
        jwt_value = utils.encode_jwt(payload)
        payload_out = utils.decode_jwt(jwt_value)
        self.assertDictEqual(payload, payload_out)
