import os
import json
import logging
from jinja2 import Environment, FileSystemLoader
import pdfkit
from core.config_manager import ConfigManager


class ReportGenerator:
    def __init__(self, config, scanners, exploits):
        self.config = config
        self.scanners = scanners
        self.exploits = exploits
        self.logger = logging.getLogger(self.__class__.__name__)
        self.env = Environment(loader=FileSystemLoader(searchpath=os.path.join(os.getcwd(), 'templates')))
        self.template = self.env.get_template('report_template.html')
        self.ensure_report_directories()

    def ensure_report_directories(self):
        os.makedirs(os.path.join(self.config.general.report_directory, 'html'), exist_ok=True)
        os.makedirs(os.path.join(self.config.general.report_directory, 'pdf'), exist_ok=True)
        os.makedirs(os.path.join(self.config.general.report_directory, 'json'), exist_ok=True)
        self.logger.debug("Report directories are ensured.")

    def generate_reports(self):
        # Gather data from scanners and exploits
        report_data = {
            'scanners': {},
            'exploits': {}
        }

        for sc_name, scanner in self.scanners.items():
            report_data['scanners'][sc_name] = {
                'results': scanner.detected_vulnerabilities
            }

        for ex_name, exploit in self.exploits.items():
            report_data['exploits'][ex_name] = {
                'results': exploit.detected_vulnerabilities
            }

        # Generate JSON report
        json_report_path = os.path.join(self.config.general.report_directory, 'json', 'report.json')
        with open(json_report_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        self.logger.info(f"JSON report generated at {json_report_path}")

        # Generate HTML report using Jinja2 template
        html_content = self.template.render(report=report_data)
        html_report_path = os.path.join(self.config.general.report_directory, 'html', 'report.html')
        with open(html_report_path, 'w') as f:
            f.write(html_content)
        self.logger.info(f"HTML report generated at {html_report_path}")

        # Convert HTML to PDF
        pdf_report_path = os.path.join(self.config.general.report_directory, 'pdf', 'report.pdf')
        try:
            pdfkit.from_file(html_report_path, pdf_report_path)
            self.logger.info(f"PDF report generated at {pdf_report_path}")
        except Exception as e:
            self.logger.error(f"Failed to generate PDF report: {e}")

    def create_html_template(self):
        # Create a simple HTML template if it doesn't exist
        templates_dir = os.path.join(os.getcwd(), 'templates')
        os.makedirs(templates_dir, exist_ok=True)
        template_path = os.path.join(templates_dir, 'report_template.html')
        if not os.path.exists(template_path):
            with open(template_path, 'w') as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>WirelessPenTestLib Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1, h2, h3 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 40px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .summary { background-color: #e6f7ff; padding: 10px; border: 1px solid #91d5ff; }
    </style>
</head>
<body>
    <h1>WirelessPenTestLib Report</h1>

    <div class="summary">
        <h2>Summary</h2>
        <p>Total Scanners Run: {{ report.scanners | length }}</p>
        <p>Total Exploits Run: {{ report.exploits | length }}</p>
    </div>

    <h2>Scanners Results</h2>
    {% for sc_name, sc_data in report.scanners.items() %}
        <h3>{{ sc_name.replace('_', ' ').title() }}</h3>
        {% if sc_data.results %}
            <table>
                <thead>
                    <tr>
                        <th>SSID</th>
                        <th>BSSID</th>
                        <th>Protocol</th>
                        <th>Description</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in sc_data.results %}
                        <tr>
                            <td>{{ vuln.ssid }}</td>
                            <td>{{ vuln.bssid }}</td>
                            <td>{{ vuln.protocol }}</td>
                            <td>{{ vuln.description }}</td>
                            <td>{{ vuln.action }}</td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <p>No vulnerabilities detected.</p>
        {% endif %}
    {% endfor %}

    <h2>Exploits Results</h2>
    {% for ex_name, ex_data in report.exploits.items() %}
        <h3>{{ ex_name.replace('_', ' ').title() }}</h3>
        {% if ex_data.results %}
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Description</th>
                        <th>Status</th>
                        <th>Action Taken</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in ex_data.results %}
                        <tr>
                            <td>{{ vuln.target }}</td>
                            <td>{{ vuln.description }}</td>
                            <td>{{ vuln.status }}</td>
                            <td>{{ vuln.action_taken }}</td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <p>No exploitation activities performed.</p>
        {% endif %}
    {% endfor %}

    <footer>
        <p>Report generated on {{ time }}</p>
    </footer>
</body>
</html>""")
            self.logger.info(f"HTML template created at {template_path}")
