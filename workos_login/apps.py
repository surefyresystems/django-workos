from django.apps import AppConfig
from workos_login.conf import conf


class WorkosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'workos_login'

    def ready(self):
        import workos
        # If settings do not exist they must be set in env variables
        if(conf.WORKOS_CLIENT_ID):
            workos.client_id = conf.WORKOS_CLIENT_ID
        if(conf.WORKOS_API_KEY):
            workos.api_key = conf.WORKOS_API_KEY
