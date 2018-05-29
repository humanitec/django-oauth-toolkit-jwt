from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import jwt


def generate_payload(issuer, expires_in, subject, **extra_data):
    """
    :param issuer: identifies the principal that issued the token.
    :type issuer: str
    :param expires_in: number of seconds that the token will be valid.
    :type expires_in: int
    :param subject: identifies the user who uses this token.
    :type subject: str
    :param extra_data: extra data to be added to the payload.
    :type extra_data: dict
    :rtype: dict
    """
    now = datetime.utcnow()
    issued_at = now
    expiration = now + timedelta(seconds=expires_in)
    payload = {
        'iss': issuer,
        'exp': expiration,
        'iat': issued_at,
        'sub': subject,
    }

    if extra_data:
        payload.update(**extra_data)

    return payload


def encode_payload(payload, headers=None):
    """
    :type payload: dict
    :type headers: dict, None
    :rtype: bytes
    """
    private_key_name = 'JWT_PRIVATE_KEY_RSA_{}'.format(payload['iss'].upper())
    private_key = getattr(settings, private_key_name, None)
    if not private_key:
        raise ImproperlyConfigured('Missing setting {}'.format(
            private_key_name))
    encoded = jwt.encode(payload, private_key, algorithm='RS256',
                         headers=headers)
    return encoded
