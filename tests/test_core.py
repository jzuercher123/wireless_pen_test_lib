# tests/test_core.py
import time

import pytest
from unittest import mock
from unittest.mock import MagicMock, mock_open, call
import json
from core import CoreFramework
import os
import threading


# Fixture to mock ConfigManager
@pytest.fixture
def mock_config_manager(mocker):
    mock_config = mocker.Mock()
    mock_config.general.interface = 'wlan0mon'
    mock_config.general.report_directory = '/tmp/reports'
    mock_config.scanners.encryption_scanner.scan_duration = 5
    mock_config.scanners.auth_bypass_scanner.scan_duration = 5
    mock_config.scanners.local_scanner.scan_duration = 5
    mock_config.exploits.session_hijacking.max_packets = 100
    return mock_config


# Fixture to mock vulnerabilities.json
@pytest.fixture
def mock_vulnerabilities(mocker):
    mock_vuln_data = {
        "vuln1": [{"detail": "Sample vulnerability 1"}],
        "vuln2": [{"detail": "Sample vulnerability 2"}]
    }
    mocked_open = mocker.patch("builtins.open", mock_open(read_data=json.dumps(mock_vuln_data)))
    return mock_vuln_data


# Fixture to mock external utilities
@pytest.fixture
def mock_utilities(mocker):
    mock_network_manager = mocker.Mock()
    mock_network_manager.interface = 'wlan0mon'

    mock_data_storage_manager = mocker.Mock()
    mock_data_storage_manager.generate_report = mocker.Mock()

    mock_auth_tools = mocker.Mock()

    return {
        "network_manager": mock_network_manager,
        "data_storage_manager": mock_data_storage_manager,
        "auth_tools": mock_auth_tools
    }


# Fixture to mock scanners
@pytest.fixture
def mock_scanners(mocker):
    mock_encryption_scanner = mocker.Mock()
    mock_auth_bypass_scanner = mocker.Mock()
    mock_dos_scanner = mocker.Mock()
    mock_local_scanner = mocker.Mock()

    scanners = {
        'encryption_scanner': mock_encryption_scanner,
        'auth_bypass_scanner': mock_auth_bypass_scanner,
        'dos_scanner': mock_dos_scanner,
        'local_scanner': mock_local_scanner
    }
    return scanners


# Fixture to mock exploits
@pytest.fixture
def mock_exploits(mocker):
    mock_session_hijacking = mocker.Mock()
    mock_credential_extraction = mocker.Mock()
    mock_payload_delivery = mocker.Mock()

    exploits = {
        'session_hijacking': mock_session_hijacking,
        'credential_extraction': mock_credential_extraction,
        'payload_delivery': mock_payload_delivery
    }
    return exploits


# Fixture to create a CoreFramework instance with all dependencies mocked
@pytest.fixture
def core_framework(mocker, mock_config_manager, mock_vulnerabilities, mock_utilities, mock_scanners, mock_exploits):
    # Mock ConfigManager
    mock_config_manager_instance = mocker.Mock()
    mock_config_manager_instance.get_config.return_value = mock_config_manager
    mocker.patch('core.config_manager.ConfigManager', return_value=mock_config_manager_instance)

    # Mock external utilities
    mocker.patch('core.NetworkInterfaceManager', return_value=mock_utilities['network_manager'])
    mocker.patch('core.DataStorageManager', return_value=mock_utilities['data_storage_manager'])
    mocker.patch('core.AuthenticationTools', return_value=mock_utilities['auth_tools'])

    # Mock scanners
    mocker.patch('core.scanners.encryption_scanner.EncryptionWeaknessScanner',
                 return_value=mock_scanners['encryption_scanner'])
    mocker.patch('core.scanners.auth_bypass_scanner.AuthBypassScanner',
                 return_value=mock_scanners['auth_bypass_scanner'])
    mocker.patch('core.scanners.dos_scanner.DosScanner', return_value=mock_scanners['dos_scanner'])
    mocker.patch('core.scanners.local_scanner.LocalScanner', return_value=mock_scanners['local_scanner'])

    # Mock exploits
    mocker.patch('core.exploits.session_hijacking.SessionHijacking', return_value=mock_exploits['session_hijacking'])
    mocker.patch('core.exploits.credential_extraction.CredentialExtraction',
                 return_value=mock_exploits['credential_extraction'])
    mocker.patch('core.exploits.payload_delivery.PayloadDelivery', return_value=mock_exploits['payload_delivery'])

    # Initialize CoreFramework
    core = CoreFramework(modules_path='/path/to/modules', config_dir='/path/to/config')

    return core


# Test CoreFramework Initialization
def test_coreframework_initialization(core_framework, mock_config_manager, mock_vulnerabilities, mock_utilities,
                                      mock_scanners, mock_exploits):
    # Assert that ConfigManager was initialized with correct config_dir
    core_framework.config_manager.get_config.assert_called_once()

    # Assert that vulnerabilities were loaded correctly
    assert core_framework.vulnerability_db == mock_vulnerabilities

    # Assert that utilities were initialized correctly
    assert core_framework.network_manager.interface == 'wlan0mon'
    assert core_framework.data_storage_manager == mock_utilities['data_storage_manager']
    assert core_framework.auth_tools == mock_utilities['auth_tools']

    # Assert that scanners were initialized correctly
    assert core_framework.scanners['encryption_scanner'] == mock_scanners['encryption_scanner']
    assert core_framework.scanners['auth_bypass_scanner'] == mock_scanners['auth_bypass_scanner']
    assert core_framework.scanners['dos_scanner'] == mock_scanners['dos_scanner']
    assert core_framework.scanners['local_scanner'] == mock_scanners['local_scanner']

    # Assert that exploits were initialized correctly
    assert core_framework.exploits['session_hijacking'] == mock_exploits['session_hijacking']
    assert core_framework.exploits['credential_extraction'] == mock_exploits['credential_extraction']
    assert core_framework.exploits['payload_delivery'] == mock_exploits['payload_delivery']


# Test load_protocol_modules is called during initialization
def test_load_protocol_modules_called(core_framework, mocker):
    mock_load = mocker.spy(core_framework, 'load_protocol_modules')
    # Re-initialize CoreFramework to trigger load_protocol_modules
    core = CoreFramework(modules_path='/path/to/modules', config_dir='/path/to/config')
    core.load_protocol_modules()
    mock_load.assert_called_once()


# Test run_scanner with valid scanner
def test_run_scanner_valid(core_framework, mock_scanners):
    target_info = {'ssid': 'TestSSID', 'bssid': 'AA:BB:CC:DD:EE:FF'}
    mock_scanners['encryption_scanner'].scan.return_value = {'vuln3': [{'detail': 'Sample vulnerability 3'}]}

    core_framework.run_scanner('encryption_scanner', target_info)

    mock_scanners['encryption_scanner'].scan.assert_called_once_with(target_info)
    assert core_framework.vulnerability_db['vuln3'] == [{'detail': 'Sample vulnerability 3'}]


# Test run_scanner with invalid scanner
def test_run_scanner_invalid(core_framework, mocker):
    with mocker.patch.object(core_framework.logger, 'error') as mock_logger_error:
        core_framework.run_scanner('invalid_scanner', {})
        mock_logger_error.assert_called_once_with("Scanner 'invalid_scanner' not found.")


# Test run_exploit with valid exploit
def test_run_exploit_valid(core_framework, mock_exploits):
    vuln_info = {'key': 'value'}
    mock_exploits['session_hijacking'].execute.return_value = {'vuln4': [{'detail': 'Sample vulnerability 4'}]}

    core_framework.run_exploit('session_hijacking', vuln_info)

    mock_exploits['session_hijacking'].execute.assert_called_once_with(vuln_info)
    assert core_framework.vulnerability_db['vuln4'] == [{'detail': 'Sample vulnerability 4'}]


# Test run_exploit with invalid exploit
def test_run_exploit_invalid(core_framework, mocker):
    with mocker.patch.object(core_framework.logger, 'error') as mock_logger_error:
        core_framework.run_exploit('invalid_exploit', {})
        mock_logger_error.assert_called_once_with("Exploit 'invalid_exploit' not found.")


# Test send_continuous_packets and stop_continuous_packets
def test_send_continuous_packets(core_framework, mocker):
    packet = mocker.Mock()
    interval = 0.1  # 100ms for testing

    # Mock sendp and time.sleep
    mock_sendp = mocker.patch('core.sendp')
    mock_sleep = mocker.patch('core.time.sleep', return_value=None)

    # Start sending packets in a separate thread
    send_thread = threading.Thread(target=core_framework.send_continuous_packets, args=(packet, interval))
    send_thread.start()

    # Allow some time for packets to be sent
    time_to_send = 0.35  # Approximately 3 packets
    time.sleep(time_to_send)

    # Stop sending packets
    core_framework.stop_continuous_packets()
    send_thread.join()

    # Assert that sendp was called approximately 3 times
    assert mock_sendp.call_count >= 3


# Test finalize method
def test_finalize(core_framework, mocker):
    # Mock generate_report
    mock_generate_report = mocker.patch.object(core_framework.data_storage_manager, 'generate_report')

    # Call finalize
    core_framework.finalize()

    # Assert that generate_report was called with vulnerability_db
    mock_generate_report.assert_called_once_with(core_framework.vulnerability_db)


# Test load_protocol_modules method (even though it's a placeholder)
def test_load_protocol_modules(core_framework, mocker):
    with mocker.patch.object(core_framework.logger, 'info') as mock_logger_info:
        core_framework.load_protocol_modules()
        mock_logger_info.assert_called_with(
            f"Loading protocol modules from {core_framework.config_manager.config_dir}/protocols...")


# Test that finalize handles exceptions gracefully
def test_finalize_exception(core_framework, mocker):
    # Mock generate_report to raise an exception
    mock_generate_report = mocker.patch.object(core_framework.data_storage_manager, 'generate_report',
                                               side_effect=Exception("Report generation failed"))
    with mocker.patch.object(core_framework.logger, 'error') as mock_logger_error:
        with mocker.patch('core.click.echo') as mock_click_echo:
            core_framework.finalize()
            mock_logger_error.assert_not_called()  # Because finalize doesn't log errors
            mock_click_echo.assert_called_with("Error during finalization: Report generation failed")
