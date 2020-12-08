from DjangoBlog.settings import *

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'clare',
        'USER': 'root',
        'PASSWORD': '1111',
        'HOST': '127.0.0.1',
        'PORT': 3306,
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': 'django_cache',
    }
}
