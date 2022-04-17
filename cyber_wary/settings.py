#
# GNU General Public License v3.0
# CyberWary - <https://github.com/metallicgloss/CyberWary>
# Copyright (C) 2022 - William P - <hello@metallicgloss.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

# Module/Library Import
from dotenv import load_dotenv
from pathlib import Path
import os

# Load .env contents.
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('CYBERWARY_SECRET')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Registration Status
REGISTRATION_OPEN = False

# Authorised URLS.
ALLOWED_HOSTS = ['*']


# Application definition
INSTALLED_APPS = [
    # Django Core
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.sites',
    'django.contrib.staticfiles',

    # Custom Apps
    'cyber_wary_portal',
    'cyber_wary_site',

    # Django REST Framework Authentication
    'rest_framework',
    'rest_framework.authtoken',

    # Social Media Auth
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.github',
    'allauth.socialaccount.providers.microsoft',

    # Django Form Wizard
    'formtools',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'cyber_wary.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'cyber_wary.wsgi.application'


# MySQL Database Configuration
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.environ.get('CYBERWARY_MYSQL_DB'),
        'USER': os.environ.get('CYBERWARY_MYSQL_USER'),
        'PASSWORD': os.environ.get('CYBERWARY_MYSQL_PASSWORD'),
        'HOST': os.environ.get('CYBERWARY_MYSQL_HOST'),
        'PORT': os.environ.get('CYBERWARY_MYSQL_PORT'),
        'OPTIONS': {
            'init_command': 'SET default_storage_engine=INNODB',
        }
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Django REST Framework
REST_FRAMEWORK = {
    # Restrict API to authenticated users only.
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated'
    ],

    # Restrict authentication method to API Key/Token only.
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],

    # Default the format for reading all request data as JSON.
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ]
}


# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/
LANGUAGE_CODE = 'en-gb'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.1/howto/static-files/
STATIC_URL = '/static/'
STATIC_ROOT = '/static/'

TEMPLATE_DIRS = [
    os.path.join(
        os.path.abspath(
            os.path.dirname(__name__)
        ),
        'cyber_wary_portal',
        'templates'
    ),
]


# Authentication Settings
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth
AUTH_USER_MODEL = 'cyber_wary_portal.CyberWaryUser'
LOGIN_URL = '/portal/account/login'
LOGIN_REDIRECT_URL = 'portal'
LOGOUT_REDIRECT_URL = 'index'


# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# Authentication Enabled Backends
SITE_ID = 1
AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
)


# Django AllAuth Configuration
# Reference - https://ref.cyberwary.com/fujti
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "http"
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGIN_ON_PASSWORD_RESET = True
ACCOUNT_LOGOUT_ON_GET = True
ACCOUNT_MAX_EMAIL_ADDRESSES = 1
ACCOUNT_USERNAME_REQUIRED = True
SOCIALACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_REGISTRATION_OPEN = True

ACCOUNT_ADAPTER = 'cyber_wary_portal.adapters.account_adapter.UserRegistrationControlAdapter'

ACCOUNT_FORMS = {
    'signup': 'cyber_wary_portal.forms.AccountDetailsForm'
}

# Django AllAuth Providers
# Reference - https://ref.cyberwary.com/8gmr6
SOCIALACCOUNT_PROVIDERS = {
    'github': {
        'SCOPE': [
            'read:user'
        ],
        'APP': {
            'client_id': os.environ.get('CYBERWARY_GITHUB_CLIENT_ID'),
            'secret': os.environ.get('CYBERWARY_GITHUB_SECRET'),
            'key': ''
        }
    },
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        },
        'APP': {
            'client_id': os.environ.get('CYBERWARY_GOOGLE_CLIENT_ID'),
            'secret': os.environ.get('CYBERWARY_GOOGLE_SECRET'),
            'key': ''
        }
    },
    'microsoft': {
        'APP': {
            'client_id': os.environ.get('CYBERWARY_MICROSOFT_CLIENT_ID'),
            'secret': os.environ.get('CYBERWARY_MICROSOFT_SECRET'),
            'key': ''
        }
    }
}

# Django Mail Configuration (SendGrid)
# Reference - https://ref.cyberwary.com/3mwv4
EMAIL_BACKEND = "sendgrid_backend.SendgridBackend"
SENDGRID_API_KEY = os.environ.get('CYBERWARY_SENDGRID_API_KEY')
SENDGRID_SANDBOX_MODE_IN_DEBUG = False
DEFAULT_FROM_EMAIL = os.environ.get('CYBERWARY_SENDGRID_EMAIL')

# MaxMind GeoIP Setting
GEOIP_PATH = os.environ.get('CYBERWARY_GEOIP_DIRECTORY')

# Google Maps JavaScript API Key
MAPS_KEY = os.environ.get('CYBERWARY_GOOGLE_MAPS_API_KEY')
