# core/modules/data_analytics/report_generation.py

import json
import csv
from fpdf import FPDF
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, Any, List

class ReportGenerator:
    def __init__(self, scan_results: Dict[str, Any], exploit_results: Dict[str, Any], report_data: Dict[str, Any]):
        """
        Initializes the ReportGenerator.

        Args:
            scan_results (Dict[str, Any]): Results from network scans.
            exploit_results (Dict[str, Any]): Results from exploit modules.
            report_data (Dict[str, Any]): Additional data for the report.
        """
        self.scan_results = scan_results
        self.exploit_results = exploit_results
        self.report_data = report_data

    def generate_pdf_report(self, file_path: str):
        """
        Generates a PDF report.

        Args:
            file_path (str): Path to save the PDF report.
        """
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(40, 10, "Wireless Penetration Test Report")
        pdf.ln(20)

        # Scan Results
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(40, 10, "Scan Results")
        pdf.ln(10)
        pdf.set_font("Arial", '', 10)
        for ap in self.scan_results.get('access_points', []):
            pdf.cell(0, 10, f"SSID: {ap['SSID']}, BSSID: {ap['BSSID']}, Security: {ap['Security']}")
            pdf.ln(5)

        # Exploit Results
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(40, 10, "Exploit Results")
        pdf.ln(10)
        pdf.set_font("Arial", '', 10)
        for exploit in self.exploit_results.get('exploits', []):
            pdf.cell(0, 10, f"Exploit: {exploit['name']}, Status: {exploit['status']}")
            pdf.ln(5)

        # Save PDF
        pdf.output(file_path)

    def export_json(self, file_path: str):
        """
        Exports report data to a JSON file.

        Args:
            file_path (str): Path to save the JSON file.
        """
        with open(file_path, 'w') as f:
            json.dump({
                'scan_results': self.scan_results,
                'exploit_results': self.exploit_results,
                'additional_data': self.report_data
            }, f, indent=4)

    def export_csv(self, file_path: str):
        """
        Exports report data to a CSV file.

        Args:
            file_path (str): Path to save the CSV file.
        """
        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['SSID', 'BSSID', 'Security'])
            for ap in self.scan_results.get('access_points', []):
                writer.writerow([ap['SSID'], ap['BSSID'], ap['Security']])
