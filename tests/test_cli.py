# tests/test_cli.py

import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock
import os
import json


@pytest.fixture
def mock_coreframework(mocker):
    """
    Fixture to mock the CoreFramework class used in cli.py.
    Returns the mock instance to allow test functions to configure it as needed.
    """
    # Step 1: Patch 'core.CoreFramework' to return a mock instance
    mock_coreframework_class = mocker.patch('core.CoreFramework')

    # Step 2: Create a mock instance of CoreFramework
    mock_coreframework_instance = MagicMock()

    # Step 3: Assign the mock instance to be returned when CoreFramework() is called
    mock_coreframework_class.return_value = mock_coreframework_instance

    return mock_coreframework_instance


def test_scan_command_runs_scanner(mocker, mock_coreframework):
    """
    Test that the 'scan' command successfully runs the specified scanner
    and outputs the expected messages.
    """
    # Configure the mock scanners
    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = {'vuln1': [{'detail': 'Sample vulnerability'}]}
    mock_coreframework.scanners = {'encryption_scanner': mock_scanner}

    # Initialize vulnerability_db
    mock_coreframework.vulnerability_db = {}

    # Mock the run_scanner method to simulate scanner behavior
    def mock_run_scanner(scanner_name, target_info):
        vulnerabilities = {'vuln1': [{'detail': 'Sample vulnerability'}]}
        mock_coreframework.vulnerability_db.update(vulnerabilities)
        return vulnerabilities

    mock_coreframework.run_scanner.side_effect = mock_run_scanner

    # Ensure load_protocol_modules is called during initialization
    mock_coreframework.load_protocol_modules = MagicMock()

    # Import the CLI after setting up mocks
    from wireless_pen_test_lib.ui import cli

    runner = CliRunner()
    result = runner.invoke(cli, [
        'scan',
        '--target-ssid', 'TestSSID',
        '--target-bssid', 'AA:BB:CC:DD:EE:FF',
        '--scanner', 'encryption_scanner'
    ])

    # Assert exit code
    assert result.exit_code == 0

    # Assert output contains expected messages
    assert "Running scanner: encryption_scanner" in result.output
    assert "All specified scans have been executed." in result.output

    # Assert that run_scanner was called with correct arguments
    mock_coreframework.run_scanner.assert_called_once_with(
        'encryption_scanner',
        {'ssid': 'TestSSID', 'bssid': 'AA:BB:CC:DD:EE:FF'}
    )

    # Assert that vulnerabilities were added to vulnerability_db
    assert mock_coreframework.vulnerability_db == {
        'vuln1': [{'detail': 'Sample vulnerability'}]
    }


def test_scan_command_without_scanners_shows_available_scanners(mocker, mock_coreframework):
    """
    Test that the 'scan' command without specifying scanners
    lists available scanners and exits with code 1.
    """
    # Configure the mock scanners
    mock_coreframework.scanners = {
        'encryption_scanner': MagicMock(),
        'auth_bypass_scanner': MagicMock()
    }

    # Import the CLI after setting up mocks
    from wireless_pen_test_lib.ui import cli

    runner = CliRunner()
    result = runner.invoke(cli, [
        'scan',
        '--target-ssid', 'TestSSID',
        '--target-bssid', 'AA:BB:CC:DD:EE:FF'
    ])

    # Assert exit code
    assert result.exit_code == 1

    # Assert output contains expected messages
    assert "No scanners specified. Available scanners are:" in result.output
    assert "- encryption_scanner" in result.output
    assert "- auth_bypass_scanner" in result.output


def test_exploit_command_without_exploits_shows_available_exploits(mocker, mock_coreframework):
    """
    Test that the 'exploit' command without specifying exploits
    lists available exploits and exits with code 1.
    """
    # Configure the mock exploits
    mock_coreframework.exploits = {
        'session_hijacking': MagicMock(),
        'credential_extraction': MagicMock()
    }

    # Import the CLI after setting up mocks
    from wireless_pen_test_lib.ui import cli

    runner = CliRunner()
    result = runner.invoke(cli, [
        'exploit',
        '--target-ssid', 'TestSSID',
        '--target-bssid', 'AA:BB:CC:DD:EE:FF'
    ])

    # Assert exit code
    assert result.exit_code == 1

    # Assert output contains expected messages
    assert "No exploits specified. Available exploits are:" in result.output
    assert "- session_hijacking" in result.output
    assert "- credential_extraction" in result.output


def test_configure_command_shows_current_configuration(mocker, mock_coreframework):
    """
    Test that the 'configure' command without settings
    displays the current configuration.
    """
    # Mock the config_manager and its get_config method
    mock_config = MagicMock()
    mock_config.general.interface = 'wlan0mon'
    mock_config.general.report_directory = '/path/to/reports'
    mock_coreframework.config_manager.config_dir = '/path/to/configs'
    mock_coreframework.config_manager.get_config.return_value = mock_config

    # Mock os.path.exists to simulate that configs.yaml exists
    mocker.patch('os.path.exists', return_value=True)

    # Mock the open function to return a sample configuration
    mocker.patch('builtins.open', mocker.mock_open(read_data="general:\n  interface: wlan0mon\n"))

    # Import the CLI after setting up mocks
    from wireless_pen_test_lib.ui import cli

    runner = CliRunner()
    result = runner.invoke(cli, ['configure'])

    # Assert exit code
    assert result.exit_code == 0

    # Assert output contains expected configuration
    assert "Current Configuration:" in result.output
    assert "[general]" in result.output
    assert "interface: wlan0mon" in result.output


def test_report_command_generates_json_report(mocker, mock_coreframework):
    """
    Test that the 'report' command with '--format json'
    generates a JSON report at the specified location.
    """
    # Configure the mock report_directory
    mock_coreframework.config_manager.config.report_directory = '/path/to/reports'

    # Mock the vulnerability_db
    mock_coreframework.vulnerability_db = {
        'scan1': [{
            'ssid': 'TestSSID',
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'protocol': 'WPA2',
            'description': 'Weak encryption'
        }]
    }

    # Mock os.makedirs to prevent actual directory creation
    mocker.patch('os.makedirs')

    # Mock the open function for writing the JSON report
    mock_open_write = mocker.mock_open()
    mocker.patch('builtins.open', mock_open_write)

    # Import the CLI after setting up mocks
    from wireless_pen_test_lib.ui import cli

    runner = CliRunner()
    result = runner.invoke(cli, ['report', '--format', 'json'])

    # Assert exit code
    assert result.exit_code == 0

    # Construct expected path with os.path.normpath
    expected_path = os.path.normpath('/path/to/reports/json/report.json')

    # Assert output contains expected message
    expected_message = f"JSON report exported to {expected_path}"
    assert expected_message in result.output

    # Assert that the report was written correctly
    mock_open_write.assert_called_once_with(expected_path, 'w')
    handle = mock_open_write()
    expected_report = {
        'scans': {
            'scan1': [{
                'ssid': 'TestSSID',
                'bssid': 'AA:BB:CC:DD:EE:FF',
                'protocol': 'WPA2',
                'description': 'Weak encryption'
            }]
        },
        'exploits': {}
    }
    handle.write.assert_called_once_with(json.dumps(expected_report, indent=4))


def test_report_command_generates_txt_report(mocker, mock_coreframework):
    """
    Test that the 'report' command with '--format txt'
    generates a TXT report at the specified location.
    """
    # Configure the mock report_directory
    mock_coreframework.config_manager.config.report_directory = '/path/to/reports'

    # Mock the vulnerability_db
    mock_coreframework.vulnerability_db = {
        'scan1': [{
            'ssid': 'TestSSID',
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'protocol': 'WPA2',
            'description': 'Weak encryption'
        }],
        'exploit1': [{
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'description': 'Credential extraction successful',
            'action': 'Extracted credentials'
        }]
    }

    # Mock os.makedirs to prevent actual directory creation
    mocker.patch('os.makedirs')

    # Mock the open function for writing the TXT report
    mock_open_write = mocker.mock_open()
    mocker.patch('builtins.open', mock_open_write)

    # Import the CLI after setting up mocks
    from wireless_pen_test_lib.ui import cli

    runner = CliRunner()
    result = runner.invoke(cli, ['report', '--format', 'txt'])

    # Assert exit code
    assert result.exit_code == 0

    # Construct expected path with os.path.normpath
    expected_path = os.path.normpath('/path/to/reports/txt/report.txt')

    # Assert output contains expected message
    expected_message = f"TXT report exported to {expected_path}"
    assert expected_message in result.output

    # Assert that the report was written correctly
    mock_open_write.assert_called_once_with(expected_path, 'w')
    handle = mock_open_write()

    # Construct expected report with OS-specific line separators
    expected_report = (
        f"Scanner: scan1{os.linesep}"
        f"  - SSID: TestSSID{os.linesep}"
        f"    BSSID: AA:BB:CC:DD:EE:FF{os.linesep}"
        f"    Protocol: WPA2{os.linesep}"
        f"    Description: Weak encryption{os.linesep}"
        f"Exploit: exploit1{os.linesep}"
        f"  - BSSID: AA:BB:CC:DD:EE:FF{os.linesep}"
        f"    Description: Credential extraction successful{os.linesep}"
        f"    Action: Extracted credentials{os.linesep}"
    )

    handle.write.assert_called_once_with(expected_report)


def test_list_command_shows_available_scanners_and_exploits(mocker, mock_coreframework):
    """
    Test that the 'list' command displays all available scanners and exploits.
    """
    # Configure the mock scanners and exploits
    mock_coreframework.scanners = {
        'encryption_scanner': MagicMock(),
        'auth_bypass_scanner': MagicMock()
    }
    mock_coreframework.exploits = {
        'session_hijacking': MagicMock(),
        'credential_extraction': MagicMock()
    }

    # Import the CLI after setting up mocks
    from wireless_pen_test_lib.ui import cli

    runner = CliRunner()
    result = runner.invoke(cli, ['list'])

    # Assert exit code
    assert result.exit_code == 0

    # Assert output contains available scanners
    assert "\nAvailable Scanners:" in result.output
    assert "- encryption_scanner" in result.output
    assert "- auth_bypass_scanner" in result.output

    # Assert output contains available exploits
    assert "\nAvailable Exploits:" in result.output
    assert "- session_hijacking" in result.output
    assert "- credential_extraction" in result.output


if __name__ == '__main__':
    import pytest

    pytest.main()
