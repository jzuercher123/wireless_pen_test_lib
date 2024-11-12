import unittest
from unittest.mock import patch, MagicMock
from utils.authentication_tools import AuthenticationTools
import subprocess
import os
import logging


class TestAuthenticationTools(unittest.TestCase):
    def setUp(self):
        # Set up the logger to capture log outputs for assertions
        self.logger = logging.getLogger('AuthenticationTools')
        self.logger.setLevel(logging.DEBUG)
        self.auth_tools = AuthenticationTools()

    @patch('utils.authentication_tools.subprocess.run')
    def test_decrypt_handshake_success(self, mock_run):
        # Mock successful decryption with aircrack-ng
        mock_run.return_value = subprocess.CompletedProcess(
            args=['aircrack-ng', '-w', 'wordlist.txt', '-l', 'password.txt', 'handshake.cap'],
            returncode=0,
            stdout='KEY FOUND! [password]',
            stderr=''
        )

        result = self.auth_tools.decrypt_handshake('handshake.cap', 'wordlist.txt', 'password.txt')
        self.assertTrue(result)
        mock_run.assert_called_once_with(['aircrack-ng', '-w', 'wordlist.txt', '-l', 'password.txt', 'handshake.cap'],
                                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    @patch('utils.authentication_tools.subprocess.run')
    def test_decrypt_handshake_failure_no_key(self, mock_run):
        # Mock decryption attempt with no key found
        mock_run.return_value = subprocess.CompletedProcess(
            args=['aircrack-ng', '-w', 'wordlist.txt', '-l', 'password.txt', 'handshake.cap'],
            returncode=0,
            stdout='No keys found.',
            stderr=''
        )

        result = self.auth_tools.decrypt_handshake('handshake.cap', 'wordlist.txt', 'password.txt')
        self.assertFalse(result)
        mock_run.assert_called_once_with(['aircrack-ng', '-w', 'wordlist.txt', '-l', 'password.txt', 'handshake.cap'],
                                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    @patch('utils.authentication_tools.subprocess.run')
    def test_decrypt_handshake_command_error(self, mock_run):
        # Mock aircrack-ng command failure
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=['aircrack-ng', '-w', 'wordlist.txt', '-l', 'password.txt', 'handshake.cap'],
            stderr='Aircrack-ng failed to open handshake file.'
        )

        result = self.auth_tools.decrypt_handshake('handshake.cap', 'wordlist.txt', 'password.txt')
        self.assertFalse(result)
        mock_run.assert_called_once_with(['aircrack-ng', '-w', 'wordlist.txt', '-l', 'password.txt', 'handshake.cap'],
                                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Additional tests for generate_pmkid can be added similarly


if __name__ == '__main__':
    unittest.main()
