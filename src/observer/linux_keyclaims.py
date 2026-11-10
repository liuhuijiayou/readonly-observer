"""Optional root-local runtime key reuse guard; never stores or emits key values."""
import fcntl
import hashlib
import os
from pathlib import Path
import stat
from .profile import private_directory
from .registry import ApprovalRegistry
from .credentials import validate_key
from .linux_credentials import stage
from .security import Refusal

DEFAULT = Path('/var/lib/readonly-observer-deployments/key-claims')


def save_unique(store, value, registry=None):
    if os.geteuid()!=0: raise Refusal('unique_node_key_registry_requires_root')
    validate_key(value)
    folder=Path(registry) if registry else DEFAULT
    if not folder.is_absolute(): raise Refusal('absolute_key_registry_required')
    private_directory(folder)
    records=ApprovalRegistry(folder.parent,folder.name)
    owner=hashlib.sha256(str(store.home).encode()).hexdigest()[:24]
    name=hashlib.sha256(value.encode('ascii')).hexdigest()+'.json'
    with records.directory() as directory:
        fd=os.open('registry.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
        try:
            records.regular(fd);fcntl.flock(fd,fcntl.LOCK_EX)
            previous=records.read_file(name)
            if previous is not None and previous!={'format':1,'owner':owner}:
                raise Refusal('runtime_key_already_assigned_to_another_instance')
            if previous is None: records.write_file(name,{'format':1,'owner':owner})
            # An interrupted reservation remains bound to its original home;
            # it can never silently make that key available to another node.
            stage(store,'runtime',value)
            st=os.lstat(store.home/'credentials/runtime')
            identity=[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns]
            store.state.write_file('runtime-key-claim.json',{'format':1,'source_identity':identity})
        finally: os.close(fd)
