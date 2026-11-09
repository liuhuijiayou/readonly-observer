"""Linux directory rename checks complement the shared no-follow descriptors."""
import os
from .fs import signature
from .security import Refusal


def revalidate_selection(root, selection, expected):
    try:
        fd = root.directory(selection)
        try:
            if signature(os.fstat(fd)) != expected:
                raise Refusal('source_changed')
        finally:
            os.close(fd)
    except OSError:
        raise Refusal('source_changed') from None
