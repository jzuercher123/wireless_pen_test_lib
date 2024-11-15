# tests/tests_round_two.py

import os
import json
import pytest
import yaml
from click.testing import CliRunner
from pydantic import ValidationError

# Import your modules here
from core.config_manager import ConfigManager, ConfigModel
from utils.network_interface_manager import NetworkInterfaceManager

import os
import json
import pytest
import yaml
from click.testing import CliRunner

from utils.network_interface_manager import NetworkInterfaceManager
from utils.data_storage_manager import DataStorageManager
from utils.authentication_tools import AuthenticationTools
from core import CoreFramework
from scanners.encryption_scanner import EncryptionWeaknessScanner
from scanners.auth_bypass_scanner import AuthBypassScanner
from scanners.dos_scanner import DosScanner
from scanners.local_scanner import LocalScanner
from exploits.session_hijacking import SessionHijacking
from exploits.credential_extraction import CredentialExtraction
from exploits.payload_delivery import PayloadDelivery
from ui.cli import cli

# =========================================
# Fixtures
# =========================================

@pytest.fixture
def sample_config(tmp_path):
    config_content = {
        'general': {
            'interface': 'wlan0mon',
            'report_directory': 'reports',
            'log_level': 'INFO',
        },
        'scanners': {
            'encryption_scanner': {'scan_duration': 10},
            'auth_bypass_scanner': {'scan_duration': 15},
            'dos_scanner': {'scan_duration': 5},
            'local_scanner': {
                'scan_duration': 8,
                'interface': 'wlan0mon',
                'vendor_lookup': True
            },
        },
        'exploits': {
            'session_hijacking': {'max_packets': 100},
            'credential_extraction': {},
            'payload_delivery': {
                'payload_types': ['type1', 'type2'],
                'default_duration': 30
            },
        },
        'ui': {
            'theme': 'dark'
        }
    }

    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "config.yaml"

    with open(config_file, 'w') as f:
        yaml.dump(config_content, f)

    return config_dir

@pytest.fixture
def mock_vulnerabilities(tmp_path):
    vulnerabilities_dir = tmp_path / "vulnerabilities"
    vulnerabilities_dir.mkdir(parents=True, exist_ok=True)
    vulnerabilities_file = vulnerabilities_dir / "vulnerabilities.json"
    vulnerabilities_content = {
        "Vuln1": ["Issue1", "Issue2"],
        "Vuln2": ["Issue3"]
    }
    with open(vulnerabilities_file, 'w') as f:
        json.dump(vulnerabilities_content, f)
    return vulnerabilities_file

@pytest.fixture
def core_framework(sample_config, mock_vulnerabilities):
    config_dir = sample_config
    modules_path = config_dir / "modules"  # Adjust this path as needed

    # Create dummy modules directory
    modules_path.mkdir(parents=True, exist_ok=True)

    core = CoreFramework(
        modules_path=str(modules_path),
        config_dir=str(config_dir),
        vulnerabilities_path=str(mock_vulnerabilities)
    )
    return core

@pytest.fixture
def runner():
    return CliRunner()

# =========================================
# Tests
# =========================================

def test_config_manager_loads_config(sample_config):
    from core.config_manager import ConfigManager
    config_manager = ConfigManager(config_dir=str(sample_config))
    config = config_manager.get_config()

    assert config.general.interface == 'wlan0mon'
    assert config.general.report_directory == 'reports'
    assert config.general.log_level == 'INFO'
    assert config.scanners.encryption_scanner.scan_duration == 10
    assert config.exploits.session_hijacking.max_packets == 100
    # Update other assertions as needed


def test_network_interface_invalid_interface():
    with pytest.raises(ValueError):
        NetworkInterfaceManager(interface='invalid_interface')

def test_data_storage_manager_initialization(tmp_path):
    report_dir = tmp_path / "reports"
    manager = DataStorageManager(report_directory=str(report_dir))
    assert manager.report_directory == str(report_dir)
    assert os.path.exists(manager.report_directory)

def test_generate_report(tmp_path):
    report_dir = tmp_path / "reports"
    manager = DataStorageManager(report_directory=str(report_dir))
    vulnerability_db = {"Vuln1": ["Issue1", "Issue2"], "Vuln2": ["Issue3"]}
    manager.generate_report(vulnerability_db)
    report_file = os.path.join(manager.report_directory, "report.json")
    assert os.path.exists(report_file)

    # Verify content of the report
    with open(report_file, 'r') as f:
        data = json.load(f)
        assert data == vulnerability_db

def test_authentication_process(mocker):
    auth = AuthenticationTools()
    # Ensure the 'authenticate' method exists
    assert hasattr(auth, 'authenticate')

    # Mock the 'authenticate' method
    mocker.patch.object(auth, 'authenticate', return_value=True)
    result = auth.authenticate()
    assert result == True

def test_auth_bypass_scanner(core_framework):
    scanner = AuthBypassScanner(core_framework=core_framework, scan_duration=15)
    target_info = {'ssid': 'TestSSID', 'bssid': 'AA:BB:CC:DD:EE:FF'}
    vulnerabilities = scanner.scan(target_info)
    assert isinstance(vulnerabilities, dict)
    # Add further assertions as needed

def test_dos_scanner(core_framework):
    scanner = DosScanner(core_framework=core_framework, scan_duration=5)
    target_info = {'ssid': 'TestSSID', 'bssid': 'AA:BB:CC:DD:EE:FF'}
    vulnerabilities = scanner.scan(target_info)
    assert isinstance(vulnerabilities, dict)
    # Add further assertions as needed

def test_local_scanner(core_framework):
    scanner = LocalScanner(
        core_framework=core_framework,
        scan_duration=8,
        interface='wlan0mon',
        vendor_lookup=True
    )
    target_info = {'ssid': 'TestSSID', 'bssid': 'AA:BB:CC:DD:EE:FF'}
    vulnerabilities = scanner.scan(target_info)
    assert isinstance(vulnerabilities, dict)
    # Add further assertions as needed

def test_credential_extraction(core_framework):
    vulnerability = {'Vuln2': ['Issue3']}
    exploit = CredentialExtraction(core_framework=core_framework, vulnerability=vulnerability)
    result = exploit.execute()
    assert isinstance(result, dict)
    # Add further assertions as needed

def test_payload_delivery(core_framework):
    vulnerability = {'Vuln3': ['Issue4']}
    exploit = PayloadDelivery(core_framework=core_framework, vulnerability=vulnerability)
    result = exploit.execute()
    assert isinstance(result, dict)
    # Add further assertions as needed

def test_cli_list_command(runner, sample_config, mock_vulnerabilities, tmp_path, monkeypatch):
    config_dir = sample_config

    # Initialize CoreFramework within the CLI context
    def mock_initialize_coreframework(*args, **kwargs):
        return CoreFramework(
            modules_path=str(config_dir / "modules"),
            config_dir=str(config_dir),
            vulnerabilities_path=str(mock_vulnerabilities)
        )

    # Monkeypatch the 'initialize_coreframework' function in 'cli' module
    monkeypatch.setattr('ui.cli.initialize_coreframework', mock_initialize_coreframework)

    result = runner.invoke(cli, ['list'])

    assert result.exit_code == 0
    assert "Available Scanners:" in result.output
    # Add further assertions based on expected output

def test_cli_report_command(runner, sample_config, mock_vulnerabilities, tmp_path, monkeypatch):
    config_dir = sample_config

    # Initialize CoreFramework within the CLI context
    def mock_initialize_coreframework(*args, **kwargs):
        return CoreFramework(
            modules_path=str(config_dir / "modules"),
            config_dir=str(config_dir),
            vulnerabilities_path=str(mock_vulnerabilities)
        )

    # Monkeypatch the 'initialize_coreframework' function in 'cli' module
    monkeypatch.setattr('ui.cli.initialize_coreframework', mock_initialize_coreframework)

    result = runner.invoke(cli, ['report'])

    assert result.exit_code == 0
    assert "Generating report..." in result.output
    # Verify that the report file exists
    report_dir = config_dir / "reports"
    report_file = report_dir / "report.json"
    assert os.path.exists(report_file)
    # Add further assertions based on expected output
