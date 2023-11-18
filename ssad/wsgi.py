
import os

from django.core.wsgi import get_wsgi_application

settings_module = "ssad.deployement" if 'WEBSITE_HOSTNAME' in os.environ else 'ssad.settings'

os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)

application = get_wsgi_application()
