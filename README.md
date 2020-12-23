django-oauth-toolkit-jwt
========================

This is an extension of django-oauth-toolkit that solves the
[lack of support for JWT](https://github.com/jazzband/django-oauth-toolkit/issues/397).

JWT support for:

* Token request.
* Token refresh.

Unsupported:

* Token revoke.


Installation
============

Add to your pip requirements:

```
git+https://github.com/Humanitec/django-oauth-toolkit-jwt#egg=django-oauth-toolkit-jwt
```

Generate keys
-------------

### RSA ###

In order to generate a RS[256, 384, 512] (RSA Signature with SHA-[256, 384, 512]) public and private
keys, execute the following:

```shell script
ssh-keygen -t rsa -b 4096 -f jwtRS256.key # don't add passphrase
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
cat jwtRS256.key
cat jwtRS256.key.pub
```

The bit-length in this JWT-algorithm setting specifies only the bit-length of the used hash-algorithm (SHA),
thus the used bit-length of the RSA-keys is not relevant from the key-generation point of view.
Recommended is the highest value your platform supports.

These keys are also used if you configure PS[256, 384, 512] as your algorithm.

### ECDSA ###

Creating ECDSA-keys ('ES[256, 384, 512]') is similar to creating RSA-keys,
but the bit-length has to be consider also on creation.

```shell script
ssh-keygen -t ecdsa -b 256 -f jwtECDSA256.key # don't add passphrase
openssl ec -in jwtECDSA256.key -pubout -outform PEM -out jwtECDSA256.key.pub
cat jwtECDSA256.key
cat jwtECDSA256.key.pub
```

Producer configuration
----------------------

To use this library to issue a token, configure the project as it follows:

Add oauth2_provider and oauth2_provider_jwt to your INSTALLED_APPS:

```python
# settings.py

INSTALLED_APPS = (
    ...
    'oauth2_provider',
    'oauth2_provider_jwt',
)
```

Include the new oauth URLs:

```python
# urls.py

urlpatterns = [
    ...
    url(r'^oauth/', include('oauth2_provider_jwt.urls', namespace='oauth2_provider_jwt')),
]
```

Add to your MIDDLEWARE the following:

```python
# settings.py

MIDDLEWARE = [
    ...
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
]
```

And finally add a custom backend authentication:

```python
# settings.py

AUTHENTICATION_BACKENDS = (
    ...
    'oauth2_provider.backends.OAuth2Backend',
)
```

Now we need to set up a `JWT_ISSUER` variable in our config, which will be the
name of the issuer. Take the private key that we generated before
and store it in a `JWT_PRIVATE_KEY_<JWT_ISSUER>` variable. Finally, define the
ID attribute you wish to use in `JWT_ID_ATTRIBUTE`. While this can be any
attribute on your user model it should be unique.

Also you have to set your JWT-encoding Algorithm if it's different than
`RS256`.

For example:

```python
# settings.py

JWT_ISSUER = 'OneIssuer'
JWT_ID_ATTRIBUTE = 'email'
JWT_PRIVATE_KEY_ONEISSUER = """
-----BEGIN RSA PRIVATE KEY-----
MIIBOAIBAAJAbCmbRUsLrsv0/Cq7DVDpUooPS1V2sr0EhTZAZmJhid2o/+ya/28m
...
6D0+csaGDlZ9GbrTpTJUObNENNHqfrHGfqzDxQ==
-----END RSA PRIVATE KEY-----
"""
```

\* *Note that storing hardcoded secrets in the settings is a bad practice and
can lead to severe security breaches in your code. We recommend using
environment variables for this purpose.*

\** *Note that you can configure only **one** JWT-Encoding Algorithm in
`JWT_ENC_ALGORITHM`. But you can set multiple allowed decoding(verifying)
Algorithms in `JWT_JWS_ALGORITHMS` as an array of Strings. It is only useful
if the JWT is from a 3rd Party and you don't know which Algorithm is used.*

The payload of messages will be by default something like:

```json
{
    "iss": "OneIssuer",
    "exp": 1234567890,
    "iat": 1234567789,
    "email": "user@domain.com",
    "scope": "read write"
}
```

But there is the possibility to add extra data to it. Just create a
function that will enrich the payload and set the location to it in the
`JWT_PAYLOAD_ENRICHER` variable:

```python
# settings.py

# Define the function to be called when creating a new JWT
JWT_PAYLOAD_ENRICHER = 'myapp.jwt_utils.payload_enricher'

# Ovewrite all of the toolkit's default JWT claims with those provided by the function
# Useful if you want to design your own token payload (Default: False which
# performs a `dict().update(payload_enricher(...))`)
JWT_PAYLOAD_ENRICHER_OVERWRITE = False
```

```python
# myproject/myapp/jwt_utils.py

def payload_enricher(**kwargs):
    # Keyword Args: request, token_content, token_obj, current_claims

    # The Django HTTPRequest object
    request = kwargs.pop('request', None)

    # Dictionary of the content of the Oauth response. Includes values like
    # access_token, expires_in, token_type, refresh_token, scope
    content = kwargs.pop('token_content', None)

    # The oauth2_provider access token (by default:
    # oauth2_provider.models.AccessToken)
    token = kwargs.pop('token_obj', None)

    # The automatically generated claims. This usually includes your
    # JWT_ID_ATTRIBUTE and scope. This can be useful if you want to use
    # JWT_PAYLOAD_ENRICHER_OVERWRITE mode.
    current_claims = kwargs.pop('current_claims', None)

    # Values returned here must be serializable by json.dumps
    return {
        'sub': token.user.pk,
        'preferred_username': token.user.username,
        ...
    }
```


Consumer configuration
----------------------

In order to let users authenticate using JWT header and token we need to
add the following configuration:

```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        ...
        'oauth2_provider_jwt.authentication.JWTAuthentication',
    )
}
```

Also, you will need to add to the settings every public key of all the
possible token issuers, if configured, using a variable `JWT_PUBLIC_KEY_<JWT_ISSUER>`:

```python
# settings.py
JWT_PUBLIC_KEY_ONEISSUER = """
-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAbCmbRUsLrsv0/Cq7DVDpUooPS1V2sr0E
hTZAZmJhid2o/+ya/28muuoQgknEoJz32bKeWuYZrFkRKUrGFnlxHwIDAQAB
-----END PUBLIC KEY-----
"""
```

By default authentication will be enabled, use `JWT_AUTH_DISABLED` setting
variable to disable that feature:

```python
# settings.py
JWT_AUTH_DISABLED = True
```


Local development
=================

Have [Docker](https://www.docker.com/) and [docker-compose](https://docs.docker.com/compose/install/) installed as a first step.

```shell script
docker-compose build
```

To run the tests on latest Python-version:

```shell script
docker-compose run dot_jwt
```

----------
To run the tests only for Python 3.6:

```shell script
docker-compose run dot_jwt_36
```

There are tests configured for all currently supported Python-Versions.
Just exchange the suffix of the docker-compose service tag with your major-minor combination.
