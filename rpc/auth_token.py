from pylon.core.tools import web, log
from tools import VaultClient


class RPC:
    @web.rpc('secrets_add_token')
    def add_token(self, token: str):
        vault_client = VaultClient()
        secrets = vault_client.get_all_secrets()
        secrets['auth_token'] = token
        vault_client.set_secrets(secrets)
