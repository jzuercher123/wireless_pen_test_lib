from core.config.protocols.base_protocol import BaseProtocol
from core.config.protocols.bluetooth import BluetoothProtocol
from core.config.protocols.wifi import WiFiProtocol
from scanners.auth_bypass_scanner import AuthBypassScanner
from scanners.encryption_scanner import EncryptionWeaknessScanner
from scanners.dos_scanner import DosScanner
from scanners.local_scanner import LocalScanner
from exploits.session_hijacking import SessionHijacking
from exploits.payload_delivery import PayloadDelivery
from exploits.credential_extraction import CredentialExtraction

# core/config/protocols/__init__.py

# Optionally, register multiple scanners/exploits or keep it empty
# Avoid relative imports unless absolutely necessary

def register_scanners():
    return {
        'wifi': WiFiProtocol,
        'bluetooth': BluetoothProtocol,
        'auth_bypass': AuthBypassScanner,
        'encryption_weakness': EncryptionWeaknessScanner,
        'dos': DosScanner,
        'local': LocalScanner
    }
def register_exploits():
    return {
        'session_hijacking': SessionHijacking,
        'payload_delivery': PayloadDelivery,
        'credential_extraction': CredentialExtraction
    }

