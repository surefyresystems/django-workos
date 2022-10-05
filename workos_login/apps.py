from django.apps import AppConfig
from workos_login.conf import conf
from django.core.checks import register, Error, Tags


def check_settings(app_configs, **kwargs):
    errors = []
    if conf.WORKOS_JIT_USERNAME not in ["email", "id", "idp_id"]:
        errors.append(
            Error(
                'Invalid settings WORKOS_JIT_USERNAME unknown value: {}'.format(conf.WORKOS_JIT_USERNAME),
                hint='You must set this setting to either "email", "id" or "idp_id"',
                obj=conf,
                id='workos_login.E001',
            )
        )
    return errors

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

        register(check_settings, Tags.compatibility)

