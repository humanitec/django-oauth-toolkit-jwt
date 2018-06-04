ADMINS = ()

MANAGERS = ADMINS

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "example.sqlite",
    }
}

ALLOWED_HOSTS = []

TIME_ZONE = "UTC"

LANGUAGE_CODE = "en-us"

SITE_ID = 1

USE_I18N = True
USE_L10N = True
USE_TZ = True

MEDIA_ROOT = ""
MEDIA_URL = ""

STATIC_ROOT = ""
STATIC_URL = "/static/"

STATICFILES_DIRS = ()

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
)

# Make this unique, and don"t share it with anybody.
SECRET_KEY = "1234567890humanitec"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": True,
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

MIDDLEWARE = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
)

ROOT_URLCONF = "tests.urls"

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    "oauth2_provider",
    'rest_framework',

    "oauth2_provider_jwt",
    "tests",
)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s"
        },
        "simple": {
            "format": "%(levelname)s %(message)s"
        },
    },
    "filters": {
        "require_debug_false": {
            "()": "django.utils.log.RequireDebugFalse"
        }
    },
    "handlers": {
        "mail_admins": {
            "level": "ERROR",
            "filters": ["require_debug_false"],
            "class": "django.utils.log.AdminEmailHandler"
        },
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "simple"
        },
        "null": {
            "level": "DEBUG",
            "class": "logging.NullHandler",
        },
    },
    "loggers": {
        "django.request": {
            "handlers": ["mail_admins"],
            "level": "ERROR",
            "propagate": True,
        },
    }
}

# Library minimal configuration

JWT_ISSUER = 'issuer'

JWT_PRIVATE_KEY_RSA_ISSUER = """
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

JWT_PUBLIC_KEY_RSA_ISSUER = """
-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAbCmbRUsLrsv0/Cq7DVDpUooPS1V2sr0E
hTZAZmJhid2o/+ya/28muuoQgknEoJz32bKeWuYZrFkRKUrGFnlxHwIDAQAB
-----END PUBLIC KEY-----
"""

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider_jwt.authentication.JWTAuthentication',
    ),
}
