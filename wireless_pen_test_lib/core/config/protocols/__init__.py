from wireless_pen_test_lib.core.config.protocols.base_protocol import BaseProtocol
from wireless_pen_test_lib.core.config.protocols.bluetooth import BluetoothProtocol
from wireless_pen_test_lib.core.config.protocols.wifi import WiFiProtocol
from wireless_pen_test_lib.scanners import AuthBypassScanner
from wireless_pen_test_lib.scanners import EncryptionWeaknessScanner
from wireless_pen_test_lib.scanners import DosScanner
from wireless_pen_test_lib.scanners.wep_scanner import WEPScanner
from wireless_pen_test_lib.scanners import LocalScanner
from wireless_pen_test_lib.exploits import SessionHijacking
from wireless_pen_test_lib.exploits import PayloadDelivery
from wireless_pen_test_lib.exploits import CredentialExtraction
# core/configs/protocols/__init__.py

# Optionally, register multiple scanners/exploits or keep it empty
# Avoid relative imports unless absolutely necessary

def register_scanners():
    return {
        'wifi': WiFiProtocol,
        'bluetooth': BluetoothProtocol,
        'auth_bypass': AuthBypassScanner,
        'encryption_weakness': EncryptionWeaknessScanner,
        'dos': DosScanner,
        'local': LocalScanner,
        'wep_scanner': WEPScanner,
    }
def register_exploits():
    return {
        'session_hijacking': SessionHijacking,
        'payload_delivery': PayloadDelivery,
        'credential_extraction': CredentialExtraction
    }

