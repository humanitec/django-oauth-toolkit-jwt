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
INSTALLED_APPS = (
    ...
    'oauth2_provider',
)
```

Include the new oauth URLs:

```
urlpatterns = [
    ...
    url(r'^oauth/', include('oauth2_provider_jwt.urls', namespace='oauth2_provider_jwt')),
]
```

Add to your MIDDLEWARE the following:

```
MIDDLEWARE_THIRD_PARTIES = [
    ...
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
    'oauth2_provider_jwt.middleware.OAuth2JWTMiddleware',

]
```

And finally add a custom backend authentication:

```
AUTHENTICATION_BACKENDS = (
    ...
    'oauth2_provider.backends.OAuth2Backend',
)
```


Local development
=================

Have [Docker](https://www.docker.com/) installed as a first step.

```bash
docker-compose -f docker-compose-dev.yml build
```

To run the tests:

```bash
docker-compose -f docker-compose-dev.yml run --entrypoint '/usr/bin/env' --rm dot_jwt tox
```
