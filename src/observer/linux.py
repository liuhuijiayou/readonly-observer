"""Linux profile extension. The stable macOS Store is inherited unchanged."""
import hashlib
from .profile import Store
from . import nodes
from .security import Refusal


class LinuxStore(Store):
    def initialize(self):
        result = super().initialize()
        with self.mutation():
            nodes.initialize(self)
        return result

    def configuration(self, active=False):
        node = nodes.identity(self, active)
        if node['status'] == 'retired':
            raise Refusal('node_retired; explicit_local_activation_required')
        config = super().configuration(active)
        config.node = node
        return config

    def namespace(self):
        return hashlib.sha256(str(self.home).encode()).hexdigest()[:24]

    def credential_name(self, kind='runtime'):
        if kind not in {'runtime', 'proxy'}:
            raise Refusal('invalid_credential_kind')
        return 'observer-' + self.namespace() + '-' + kind

    def credential(self, kind='runtime'):
        from .linux_credentials import SystemdCredentials, validate_key, validate_proxy
        return SystemdCredentials(self.credential_name(kind), validate_key if kind == 'runtime' else validate_proxy)

    def linux_settings(self, active=False):
        value = (self.state if active else self.config).read_file('linux-active.json' if active else 'linux.json',
                                                                {'format': 1, 'proxy': False})
        if (not isinstance(value, dict) or set(value) != {'format', 'proxy'}
                or type(value['format']) is not int or value['format'] != 1 or type(value['proxy']) is not bool):
            raise Refusal('invalid_linux_settings')
        return value

    def set_proxy(self, enabled):
        with self.mutation():
            self.config.write_file('linux.json', {'format': 1, 'proxy': enabled})
        return {'proxy_enabled': enabled, 'activation': 'next_explicit_start'}

    def revoke_all(self, retire=False):
        from .registry import APPROVALS
        with self.mutation():
            backup = self.backup('retire_node' if retire else 'revoke_all_local_sources')
            entries = self.config.entries()
            self.config.write_file(APPROVALS, {**entries, 'revision': entries['revision'] + 1, 'entries': []})
            if retire:
                self.config.write_file('node.json', {**nodes.identity(self), 'status': 'retired'})
        return {'local_grants_removed': len(entries['entries']), 'retired': retire, 'backup': backup,
                'runtime_key': 'not_revoked', 'platform_permissions': 'not_revoked', 'chatgpt_connection': 'unchanged'}
