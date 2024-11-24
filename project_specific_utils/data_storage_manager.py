# wireless_pen_test_lib/project_specific_utils/data_storage_manager.py

import os
import json
import logging


class DataStorageManager:
    """
    A class to manage data storage and report generation.
    """
    def __init__(self, report_directory: str = "reports", filename="report.txt"):
        """
        Initialize the DataStorageManager with the specified report directory.

        Args:
            report_directory (str): Path to the directory where reports will be stored.
        """
        self.report_directory = report_directory
        os.makedirs(self.report_directory, exist_ok=True)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info(f"DataStorageManager initialized for report directory: {self.report_directory}")
        self.filename = filename

    def generate_report(self, vulnerability_db: dict):
        """
        Generates a report based on the vulnerability database.

        Args:
            vulnerability_db (dict): Dictionary containing detected vulnerabilities.
        """
        self.logger.info("Generating reports...")
        # Ensure report directories exist
        json_dir = os.path.join(self.report_directory, "json")
        txt_dir = os.path.join(self.report_directory, "txt")
        os.makedirs(json_dir, exist_ok=True)
        os.makedirs(txt_dir, exist_ok=True)

        # JSON Report
        json_report_path = os.path.join(json_dir, "report.json")
        with open(json_report_path, 'w') as f:
            json.dump(vulnerability_db, f, indent=4)
        self.logger.info(f"JSON report generated at {json_report_path}")

        # TXT Report
        txt_report_path = os.path.join(txt_dir, "report.txt")
        with open(txt_report_path, 'w') as f:
            for scanner, vulnerabilities in vulnerability_db.get('scans', {}).items():
                f.write(f"Scanner: {scanner}\n")
                for vuln in vulnerabilities:
                    f.write(f"  - SSID: {vuln.get('ssid', 'N/A')}\n")
                    f.write(f"    BSSID: {vuln.get('bssid', 'N/A')}\n")
                    f.write(f"    Protocol: {vuln.get('protocol', 'N/A')}\n")
                    f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
            for exploit, vulnerabilities in vulnerability_db.get('exploits', {}).items():
                f.write(f"Exploit: {exploit}\n")
                for vuln in vulnerabilities:
                    f.write(f"  - BSSID: {vuln.get('bssid', 'N/A')}\n")
                    f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
                    f.write(f"    Action: {vuln.get('action', 'N/A')}\n")
        self.logger.info(f"TXT report generated at {txt_report_path}")


if __name__=="__main__":
    dsm = DataStorageManager()
    dsm.generate_report({
        'scans': {
            'WEPScanner': [
                {
                    'ssid': 'TestNet',
                    'bssid': '00:11:22:33:44:55',
                    'protocol': 'WEP',
                    'description': 'Weak WEP key detected.'
                }
            ]
        },
        'exploits': {
            'DeauthExploit': [
                {
                    'bssid': '00:11:22:33:44:55',
                    'description': 'Deauth attack successful.',
                    'action': 'Disconnect the client.'
                }
            ]
        }
    })
    print("Report generation completed.")