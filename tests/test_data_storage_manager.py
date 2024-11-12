import unittest
from unittest.mock import patch, mock_open
from utils.data_storage_manager import DataStorageManager
import os
import shutil
import json
import logging


class TestDataStorageManager(unittest.TestCase):
    def setUp(self):
        # Set up a temporary report directory
        self.test_report_dir = "test_reports"
        self.data_storage_manager = DataStorageManager(report_directory=self.test_report_dir)

    def tearDown(self):
        # Remove temporary report directory after tests
        shutil.rmtree(self.test_report_dir)

    def test_save_and_load_json(self):
        test_data = {'key': 'value'}
        filename = 'test.json'
        self.data_storage_manager.save_json(test_data, filename)

        # Ensure the file exists
        json_path = os.path.join(self.test_report_dir, 'json', filename)
        self.assertTrue(os.path.exists(json_path))

        # Load the data and verify
        loaded_data = self.data_storage_manager.load_json(filename)
        self.assertEqual(test_data, loaded_data)

    def test_save_text(self):
        test_text = "This is a test."
        filename = 'test.txt'
        self.data_storage_manager.save_text(test_text, filename)

        # Ensure the file exists
        text_path = os.path.join(self.test_report_dir, 'txt', filename)
        self.assertTrue(os.path.exists(text_path))

        # Read the file and verify
        with open(text_path, 'r') as f:
            content = f.read()
        self.assertEqual(test_text, content)

    def test_save_binary(self):
        test_binary = b'\x00\xFF\x00\xFF'
        filename = 'test.bin'
        self.data_storage_manager.save_binary(test_binary, filename)

        # Ensure the file exists
        binary_path = os.path.join(self.test_report_dir, 'binary', filename)
        self.assertTrue(os.path.exists(binary_path))

        # Read the file and verify
        with open(binary_path, 'rb') as f:
            content = f.read()
        self.assertEqual(test_binary, content)

    def test_get_report_path_valid(self):
        filename = 'report.json'
        path = self.data_storage_manager.get_report_path('json', filename)
        expected_path = os.path.join(self.test_report_dir, 'json', filename)
        self.assertEqual(path, expected_path)

    def test_get_report_path_invalid(self):
        filename = 'report.xyz'
        with self.assertRaises(ValueError):
            self.data_storage_manager.get_report_path('invalid_type', filename)


if __name__ == '__main__':
    unittest.main()
