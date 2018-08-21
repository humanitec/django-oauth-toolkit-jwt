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

In order to generate a RS256 (RSA Signature with SHA-256) public and private
keys, execute the following:

```
$ ssh-keygen -t rsa -b 4096 -f jwtRS256.key # don't add passphrase
$ openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
$ cat jwtRS256.key
$ cat jwtRS256.key.pub
```


Producer configuration
----------------------

To use this library to issue a token, configure the project as it follows:

Add oauth2_provider and oauth2_provider_jwt to your INSTALLED_APPS:

```
# settings.py

INSTALLED_APPS = (
    ...
    'oauth2_provider',
    'oauth2_provider_jwt',
)
```

Include the new oauth URLs:

```
# urls.py

urlpatterns = [
    ...
    url(r'^oauth/', include('oauth2_provider_jwt.urls', namespace='oauth2_provider_jwt')),
]
```

Add to your MIDDLEWARE the following:

```
# settings.py

MIDDLEWARE = [
    ...
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
]
```

And finally add a custom backend authentication:

```
# settings.py

AUTHENTICATION_BACKENDS = (
    ...
    'oauth2_provider.backends.OAuth2Backend',
)
```

Now we need to set up a `JWT_ISSUER` variable in our config, which will be the
name of the issuer. Take the RSA256 private key that we genreated before
and store it in a `JWT_PRIVATE_KEY_RSA_<JWT_ISSUER>` variable \*. For example:


```
# settings.py

JWT_ISSUER = 'OneIssuer'
JWT_PRIVATE_KEY_RSA_ONEISSUER = """
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

The payload of messages will be by default something like:

```
{
    'iss': 'OneIssuer',
    'exp': 1234567890,
    'iat': 1234567789,
}
```

But there is the possibility to add extra data to it. Just create a
function that will enrich the payload and set the location to it in the
`JWT_PAYLOAD_ENRICHER` variable:

```
# settings.py

JWT_PAYLOAD_ENRICHER = 'myapp.jwt_utils.payload_enricher'


# myproject/myapp/jwt_utils.py

def payload_enricher(request):
    return {
        'sub': 'mysubject',
        ...
    }
```


Consumer configuration
----------------------

In order to let users authenticate using JWT header and token we need to
add the following configuration:

```
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        ...
        'oauth2_provider_jwt.authentication.JWTAuthentication',
    )
}
```

Also, you will need to add to the settings every public RSA256 key of all the
possible token issuers using a variable `JWT_PUBLIC_KEY_RSA_<JWT_ISSUER>`:

```
# settings.py
JWT_PUBLIC_KEY_RSA_ONEISSUER = """
-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAbCmbRUsLrsv0/Cq7DVDpUooPS1V2sr0E
hTZAZmJhid2o/+ya/28muuoQgknEoJz32bKeWuYZrFkRKUrGFnlxHwIDAQAB
-----END PUBLIC KEY-----
"""
```

By default authentication will be enabled, use `JWT_AUTH_DISABLED` setting
variable to disable that feature:

```
# settings.py
JWT_AUTH_DISABLED = True
```


Local development
=================

Have [Docker](https://www.docker.com/) installed as a first step.

```bash
docker-compose -f docker-compose-dev.yml build
```

To run all the tests:

```bash
docker-compose -f docker-compose-dev.yml run --entrypoint '/usr/bin/env' --rm dot_jwt tox
```

To run the tests only for Python 2.7:

```bash
docker-compose -f docker-compose-dev.yml run --entrypoint '/usr/bin/env' --rm dot_jwt tox -e py27
```

Or to run just one test:

```bash
docker-compose -f docker-compose-dev.yml run --entrypoint '/usr/bin/env' --rm dot_jwt tox -- -x tests/test_views.py::PasswordTokenViewTest::test_get_enriched_jwt
```
