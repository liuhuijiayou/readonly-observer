"""Opt-in macOS Keychain adapter. Construction does not read any credential."""
import ctypes
import sys
from .security import Refusal

SERVICE = b"local-readonly-observer.tunnel-runtime"
ACCOUNT = b"runtime"

def validate_key(value):
    if not isinstance(value, str) or not value or len(value) > 8192 or any(not 33 <= ord(c) <= 126 for c in value):
        raise Refusal("invalid_runtime_key")
    return value

class Keychain:
    def __init__(self, service=SERVICE, account=ACCOUNT):
        self.service, self.account = service, account

    def _libraries(self):
        if sys.platform != "darwin":
            raise Refusal("macos_keychain_required")
        sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        ptr, uint = ctypes.c_void_p, ctypes.c_uint32
        sec.SecKeychainFindGenericPassword.argtypes = [ptr, uint, ctypes.c_char_p, uint, ctypes.c_char_p,
                                                      ctypes.POINTER(uint), ctypes.POINTER(ptr), ctypes.POINTER(ptr)]
        sec.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        sec.SecKeychainAddGenericPassword.argtypes = [ptr, uint, ctypes.c_char_p, uint, ctypes.c_char_p,
                                                     uint, ptr, ctypes.POINTER(ptr)]
        sec.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        sec.SecKeychainItemModifyAttributesAndData.argtypes = [ptr, ptr, uint, ptr]
        sec.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
        sec.SecKeychainItemFreeContent.argtypes = [ptr, ptr]
        sec.SecKeychainItemFreeContent.restype = ctypes.c_int32
        cf.CFRelease.argtypes = [ptr]
        cf.CFRelease.restype = None
        return sec, cf

    def get(self):
        sec, _ = self._libraries()
        size, data = ctypes.c_uint32(), ctypes.c_void_p()
        status = sec.SecKeychainFindGenericPassword(None, len(self.service), self.service, len(self.account), self.account,
                                                   ctypes.byref(size), ctypes.byref(data), None)
        if status != 0:
            raise Refusal("runtime_key_not_available; open_local_settings")
        try:
            if not 0 < size.value <= 8192:
                raise Refusal("invalid_runtime_key")
            return validate_key(ctypes.string_at(data, size.value).decode("ascii"))
        finally:
            sec.SecKeychainItemFreeContent(None, data)

    def save_from_local_settings(self, value, confirmed=False):
        if confirmed is not True:
            raise Refusal("explicit_local_credential_save_required")
        value = validate_key(value)
        sec, cf = self._libraries()
        item = ctypes.c_void_p()
        # Locate the item without reading an existing password.
        status = sec.SecKeychainFindGenericPassword(None, len(self.service), self.service, len(self.account), self.account,
                                                   None, None, ctypes.byref(item))
        raw = value.encode("ascii")
        if status == -25300:  # errSecItemNotFound
            status = sec.SecKeychainAddGenericPassword(None, len(self.service), self.service, len(self.account), self.account,
                                                       len(raw), ctypes.c_char_p(raw), None)
        elif status == 0:
            try:
                status = sec.SecKeychainItemModifyAttributesAndData(item, None, len(raw), ctypes.c_char_p(raw))
            finally:
                cf.CFRelease(item)
        if status != 0:
            raise Refusal("keychain_save_failed")
