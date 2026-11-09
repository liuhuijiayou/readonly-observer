"""Optional public identity; existing Mac settings and Keychain stay untouched."""
import hashlib
import re
import secrets
from .security import Refusal


def validate(node):
    if (not isinstance(node, dict) or set(node) != {'format', 'id', 'name', 'status'} or type(node['format']) is not int or node['format'] != 1
            or not isinstance(node['id'], str) or not re.fullmatch(r'node_[a-f0-9]{32}', node['id'])
            or not isinstance(node['name'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}', node['name'])
            or node['status'] not in {'active', 'retired'}):
        raise Refusal('invalid_node_identity; use_public_name_only')
    return node


def identity(store, active=False):
    node = store.state.read_file('node-active.json') if active else store.config.read_file('node.json')
    if node is None:
        # Legacy instances need no initialization, permission or Keychain migration.
        digest = hashlib.sha256(str(store.home).encode()).hexdigest()[:32]
        node = {'format': 1, 'id': 'node_' + digest, 'name': 'observer-' + digest[-8:], 'status': 'active'}
    return validate(node)


def initialize(store):
    if store.config.read_file('node.json') is None:
        identifier = secrets.token_hex(16)
        store.config.write_file('node.json', {'format': 1, 'id': 'node_' + identifier,
                                             'name': 'observer-' + identifier[-8:], 'status': 'active'})


def configure(store, name=None, identifier=None, status=None):
    with store.mutation():
        node = dict(identity(store))
        if name is not None:
            node['name'] = name
        if identifier is not None:
            node['id'] = identifier
        if status is not None:
            node['status'] = status
        validate(node)
        store.config.write_file('node.json', node)
    return {'node': node, 'activation': 'next_explicit_start', 'credentials_changed': False}
