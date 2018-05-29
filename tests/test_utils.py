import base64
from datetime import datetime, timedelta
import json
from unittest.mock import patch
from unittest import TestCase as PythonTestCase

from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from oauth2_provider_jwt import utils

PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIBOAIBAAJAbCmbRUsLrsv0/Cq7DVDpUooPS1V2sr0EhTZAZmJhid2o/+ya/28m
uuoQgknEoJz32bKeWuYZrFkRKUrGFnlxHwIDAQABAkBILcO2DAxxyx1jIcjNbA8n
y4XFSfT59fUMSFXVfRWGAAyk4N2bSByMDmdeO+6iNMzuj0RChh++ArnN2OkRFiFR
AiEAtQLajsU47rWR1/5eCvYEF022ABAeRM1AXGJYzwU6j60CIQCY+Mne04S3WMOd
HGwNyAhAj5FpSI3SM5KOHebQhwktewIgEoNzNS0I0KlzfEMA/WACNRv2pHUBk4nm
rkxExw/C2JUCIHy5/f9Nf9zu5zBnSENEYlYhuXKa0egeXNS71MMaF4WZAiAPk2kb
6D0+csaGDlZ9GbrTpTJUObNENNHqfrHGfqzDxQ==
-----END RSA PRIVATE KEY-----
"""

PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAbCmbRUsLrsv0/Cq7DVDpUooPS1V2sr0E
hTZAZmJhid2o/+ya/28muuoQgknEoJz32bKeWuYZrFkRKUrGFnlxHwIDAQAB
-----END PUBLIC KEY-----
"""


class GeneratePayloadTest(PythonTestCase):
    def _get_payload_args(self):
        issuer = 'activityapi'
        subject = 'APIUser'
        expires_in = 36000
        return issuer, expires_in, subject

    @patch('oauth2_provider_jwt.utils.datetime')
    def test_generate_payload_no_extra_data(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now
        issuer, expires_in, subject = self._get_payload_args()
        expiration = now + timedelta(seconds=expires_in)

        self.assertEqual(
            utils.generate_payload(issuer, expires_in, subject),
            {
                'iss': issuer,
                'exp': expiration,
                'iat': now,
                'sub': subject,
            }
        )

    @patch('oauth2_provider_jwt.utils.datetime')
    def test_generate_payload_with_extra_data(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now

        issuer, expires_in, subject = self._get_payload_args()
        expiration = now + timedelta(seconds=expires_in)

        extra_data = {
            'usr': 'some_usr',
            'org': 'some_org',
        }

        self.assertEqual(
            utils.generate_payload(issuer, expires_in, subject, **extra_data),
            {
                'iss': issuer,
                'exp': expiration,
                'iat': now,
                'sub': subject,
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

    def test_encode_payload_no_private_key_in_setting(self):
        payload = self._get_payload()
        self.assertRaises(ImproperlyConfigured,
                          utils.encode_payload, payload)

    @override_settings(JWT_PRIVATE_KEY_RSA_ISSUER=PRIVATE_KEY)
    def test_encode_payload(self):
        payload = self._get_payload()
        encoded = utils.encode_payload(payload)
        self.assertIs(type(encoded), bytes)
        encoded_str = encoded.decode("utf-8")
        headers_enc, payload_enc, verify_signature_enc = encoded_str.split(".")
        self.assertEqual(base64.b64decode(headers_enc),
                         b'{"typ":"JWT","alg":"RS256"}')
        payload_enc += '=' * (-len(payload_enc) % 4)  # add padding
        self.assertEqual(
            json.loads(base64.b64decode(payload_enc).decode("utf-8")),
            payload)
