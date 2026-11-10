"""Operator-only Linux credential input. No stdin/env/argv secret fallback."""
import getpass
import sys
import warnings
from .security import Refusal
from .linux_credentials import stage


def credentials(store, args, confirm):
    if args.key_registry and not args.unique_node_key:
        raise Refusal('key_registry_requires_unique_node_key')
    if args.unique_node_key and args.kind != 'runtime':
        raise Refusal('unique_node_key_only_applies_to_runtime')
    meta = {'provider': 'systemd', 'credential_id': store.credential_name(args.kind),
            'source': str(store.home / 'credentials' / args.kind), 'value_read': False,
            'runtime_source': 'CREDENTIALS_DIRECTORY_only; no_environment_key_or_disk_fallback'}
    if args.action == 'info':
        return {'ok': True, **meta}
    if confirm({'action': 'stage_or_rotate_local_LoadCredential_source', **meta}) is not True:
        raise Refusal('local_approval_required')
    if not sys.stdin.isatty():
        raise Refusal('secure_tty_required; no_stdin_or_environment_key_input')
    value = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass('Existing runtime key or HTTP(S) proxy URL (hidden, local only): ')
        if args.unique_node_key:
            from .linux_keyclaims import save_unique
            save_unique(store, value, args.key_registry)
        else:
            stage(store, args.kind, value)
    except getpass.GetPassWarning:
        raise Refusal('secure_tty_required') from None
    finally:
        value = None
    return {'ok': True, 'credential_staged': True, 'activation': 'restart_systemd_unit_to_reload',
            'remote_key_rotation': 'not_performed; revoke_old_key_in_Platform', 'service_started': False}
