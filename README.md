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

Add oauth2_provider to your INSTALLED_APPS:

```
# settings.py

INSTALLED_APPS = (
    ...
    'oauth2_provider',
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

MIDDLEWARE_THIRD_PARTIES = [
    ...
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
    'oauth2_provider_jwt.middleware.OAuth2JWTMiddleware',

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


Producer configuration
______________________

If you wish to use this library to issue a token then we need to set up a
`JWT_ISSUER` variable in our config, which will be the name of the issuer.
Also you will create a RSA private key for it and will store it in a
`JWT_PRIVATE_KEY_RSA_<JWT_ISSUER>` variable. For example:


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
