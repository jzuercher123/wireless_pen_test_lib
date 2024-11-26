# tests/test_all.py

import pytest
from unittest.mock import MagicMock, patch
from click.testing import CliRunner
import os
import json
import logging


# ============================
# Fixtures for Mocking
# ============================

@pytest.fixture
def mock_coreframework(mocker):
    """
    Fixture to mock the CoreFramework class used in cli.py.
    Returns the mock instance to allow test functions to configure it as needed.
    """
    # Patch 'core.CoreFramework' to return a mock instance
    mock_coreframework_class = mocker.patch('core.CoreFramework', autospec=True)

    # Create a mock instance of CoreFramework
    mock_coreframework_instance = MagicMock()

    # Assign the mock instance to be returned when CoreFramework() is called
    mock_coreframework_class.return_value = mock_coreframework_instance

    # Initialize vulnerability_db as a real dict
    mock_coreframework_instance.vulnerability_db = {}

    # Initialize scanners and exploits
    mock_coreframework_instance.scanners = {}
    mock_coreframework_instance.exploits = {}

    # Initialize config_manager
    mock_coreframework_instance.config_manager = MagicMock()
    mock_coreframework_instance.config_manager.config_dir = '/path/to/configs'
    mock_coreframework_instance.config_manager.get_config.return_value = MagicMock()

    return mock_coreframework_instance


@pytest.fixture
def mock_cli_main(mocker):
    """
    Fixture to mock the cli object from ui.cli for main.py tests.
    """
    return mocker.patch('main.cli')


@pytest.fixture
def mock_sys_exit(mocker):
    """
    Fixture to mock sys.exit to prevent the test runner from exiting.
    """
    return mocker.patch('sys.exit')


# ============================
# Tests for cli.py
# ============================

def test_scan_command_runs_scanner(mocker, mock_coreframework, caplog):
    """
    Test that the 'scan' command successfully runs the specified scanner
    and outputs the expected messages.
    """
    # Configure the mock scanners
    mock_scanner = MagicMock()

    # Mock the run_scanner method to simulate scanner behavior
    def mock_run_scanner(scanner_name, target_info):
        vulnerabilities = {'vuln1': [{'detail': 'Sample vulnerability'}]}
        # Do NOT update vulnerability_db here to prevent duplication
        return vulnerabilities

    mock_coreframework.run_scanner.side_effect = mock_run_scanner

    # Mock 'scanners' dictionary
    mock_coreframework.scanners = {
        'encryption_scanner': mock_scanner
    }

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
    expected_message_1 = "Running scanner: encryption_scanner"
    expected_message_2 = "All specified scans have been executed."

    # Check if the messages are in the output or in the captured logs
    assert expected_message_1 in result.output or expected_message_1 in caplog.text
    assert expected_message_2 in result.output or expected_message_2 in caplog.text

    # Assert that run_scanner was called with correct arguments
    mock_coreframework.run_scanner.assert_called_once_with(
        'encryption_scanner',
        {'ssid': 'TestSSID', 'bssid': 'AA:BB:CC:DD:EE:FF'}
    )

    # Assert that vulnerabilities were added to vulnerability_db
    assert mock_coreframework.vulnerability_db == {
        'vuln1': [{'detail': 'Sample vulnerability'}]
    }


def test_scan_command_without_scanners_shows_available_scanners(mocker, mock_coreframework, caplog):
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
    expected_output_start = "No scanners specified. Available scanners are:"
    expected_scanner_1 = "- encryption_scanner"
    expected_scanner_2 = "- auth_bypass_scanner"

    assert expected_output_start in result.output or expected_output_start in caplog.text
    assert expected_scanner_1 in result.output or expected_scanner_1 in caplog.text
    assert expected_scanner_2 in result.output or expected_scanner_2 in caplog.text


def test_exploit_command_without_exploits_shows_available_exploits(mocker, mock_coreframework, caplog):
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
    expected_output_start = "No exploits specified. Available exploits are:"
    expected_exploit_1 = "- session_hijacking"
    expected_exploit_2 = "- credential_extraction"

    assert expected_output_start in result.output or expected_output_start in caplog.text
    assert expected_exploit_1 in result.output or expected_exploit_1 in caplog.text
    assert expected_exploit_2 in result.output or expected_exploit_2 in caplog.text


def test_configure_command_shows_current_configuration(mocker, mock_coreframework, caplog):
    """
    Test that the 'configure' command without settings
    displays the current configuration.
    """
    # Mock the config_manager and its get_config method
    mock_config = MagicMock()
    mock_config.general.interface = 'wlan0mon'
    mock_config.general.report_directory = '/path/to/reports'
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
    expected_output_1 = "Current Configuration:"
    expected_output_2 = "[general]"
    expected_output_3 = "interface: wlan0mon"

    assert expected_output_1 in result.output or expected_output_1 in caplog.text
    assert expected_output_2 in result.output or expected_output_2 in caplog.text
    assert expected_output_3 in result.output or expected_output_3 in caplog.text


def test_report_command_generates_json_report(mocker, mock_coreframework, caplog):
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
    assert expected_message in result.output or expected_message in caplog.text

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
    # Concatenate all write calls
    written_data = ''.join(call.args[0] for call in handle.write.call_args_list)
    assert written_data == json.dumps(expected_report, indent=4)


def test_report_command_generates_txt_report(mocker, mock_coreframework, caplog):
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
    assert expected_message in result.output or expected_message in caplog.text

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

    # Concatenate all write calls
    written_data = ''.join(call.args[0] for call in handle.write.call_args_list)

    # Normalize line endings for comparison
    written_data_normalized = written_data.replace('\r\n', '\n')
    expected_report_normalized = expected_report.replace('\r\n', '\n')

    assert written_data_normalized == expected_report_normalized


def test_list_command_shows_available_scanners_and_exploits(mocker, mock_coreframework, caplog):
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
    expected_scanners_header = "\nAvailable Scanners:"
    expected_scanner_1 = "- encryption_scanner"
    expected_scanner_2 = "- auth_bypass_scanner"

    assert expected_scanners_header in result.output or expected_scanners_header in caplog.text
    assert expected_scanner_1 in result.output or expected_scanner_1 in caplog.text
    assert expected_scanner_2 in result.output or expected_scanner_2 in caplog.text

    # Assert output contains available exploits
    expected_exploits_header = "\nAvailable Exploits:"
    expected_exploit_1 = "- session_hijacking"
    expected_exploit_2 = "- credential_extraction"

    assert expected_exploits_header in result.output or expected_exploits_header in caplog.text
    assert expected_exploit_1 in result.output or expected_exploit_1 in caplog.text
    assert expected_exploit_2 in result.output or expected_exploit_2 in caplog.text


# ============================
# Tests for main.py
# ============================

def test_main_successful_invocation(mocker, mock_cli_main, mock_sys_exit, caplog):
    """
    Test that main() successfully invokes the CLI without errors.
    """
    # Arrange
    # Ensure that cli(obj={}) runs without raising an exception
    mock_cli_main.return_value = None  # cli returns nothing (equivalent to sys.exit(0))

    # Act
    from main import main
    main()

    # Assert
    mock_cli_main.assert_called_once_with(obj={})
    mock_sys_exit.assert_not_called()

    # Optionally, check that logging.info was called during setup
    # Since setup_logging sets up a console handler, we can check for initialization logs
    # However, since no log messages are generated in main(), we skip this


def test_main_cli_raises_exception(mocker, mock_cli_main, mock_sys_exit, caplog):
    """
    Test that if cli(obj={}) raises an exception, main() logs the error and exits with code 1.
    """
    # Arrange
    test_exception = Exception("Test CLI Exception")
    mock_cli_main.side_effect = test_exception

    # Act
    from main import main
    main()

    # Assert
    mock_cli_main.assert_called_once_with(obj={})
    mock_sys_exit.assert_called_once_with(1)

    # Check that the error was logged
    assert f"An error occurred while running the CLI: {test_exception}" in caplog.text


def test_main_logging_setup(mocker, caplog):
    """
    Test that the logging is set up correctly in main().
    """
    # Arrange
    with patch('main.cli') as mock_cli_main, \
            patch('sys.exit') as mock_sys_exit:
        # Reset the logger to remove any existing handlers
        logger = logging.getLogger()
        logger.handlers = []
        logger.setLevel(logging.NOTSET)

        # Act
        from main import main
        main()

    # Assert
    # Check that logging has at least one handler
    assert len(logger.handlers) >= 1

    # Check that the root logger level is set to DEBUG
    assert logger.level == logging.DEBUG

    # Check the formatter of the console handler
    console_handler = None
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            console_handler = handler
            break
    assert console_handler is not None, "No StreamHandler found in logger handlers."

    expected_format = '[%(asctime)s] %(levelname)s - %(name)s - %(message)s'
    assert console_handler.formatter._fmt == expected_format


def test_main_logging_error_on_exception(mocker, mock_cli_main, mock_sys_exit, caplog):
    """
    Test that if cli(obj={}) raises an exception, the error is logged correctly.
    """
    # Arrange
    test_exception = ValueError("Invalid value provided")
    mock_cli_main.side_effect = test_exception

    # Act
    from main import main
    main()

    # Assert
    mock_sys_exit.assert_called_once_with(1)
    # Check that the error message is logged
    assert f"An error occurred while running the CLI: {test_exception}" in caplog.text


# ============================
# Entry Point for Running Tests
# ============================

if __name__ == '__main__':
    pytest.main(['-v', 'test_all.py'])
