# ui/cli.py

import click
import os
import sys
import json
import yaml
from core import CoreFramework

# Adjust the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.insert(0, project_root)

@click.group()
@click.version_option(version='1.0.0', prog_name='WirelessPenTestLib')
@click.pass_context
def cli(ctx):
    """WirelessPenTestLib: A Comprehensive Wireless Penetration Testing Library"""
    ctx.ensure_object(dict)
    core = ctx.obj.get('core')
    if core:
        core.logger.info("CLI initialized.")
    else:
        click.echo("CoreFramework instance not found.")
        sys.exit(1)

@cli.command()
@click.option('--scanner', '-s', multiple=True, help='Specify scanners to run (e.g., encryption_scanner, auth_bypass_scanner, dos_scanner).')
@click.option('--target-ssid', prompt='Target SSID', help='SSID of the target wireless network.')
@click.option('--target-bssid', prompt='Target BSSID', help='BSSID of the target wireless network.')
@click.pass_context
def scan(ctx, scanner, target_ssid, target_bssid):
    """
    Execute vulnerability scans on the specified target.
    """
    core = ctx.obj['core']
    vulnerability_db = core.vulnerability_db

    # Define the target
    target = {
        'ssid': target_ssid,
        'bssid': target_bssid
    }

    if not scanner:
        click.echo("No scanners specified. Available scanners are:")
        for sc in core.scanners.keys():
            click.echo(f"- {sc}")
        sys.exit(1)

    for sc in scanner:
        if sc not in core.scanners:
            click.echo(f"Scanner '{sc}' not found. Available scanners are:")
            for scanner_name in core.scanners.keys():
                click.echo(f"- {scanner_name}")
            continue
        click.echo(f"\nRunning scanner: {sc}")
        vulnerabilities = core.run_scanner(sc, target)
        # Merge vulnerabilities into the vulnerability_db
        for key, value in vulnerabilities.items():
            if key not in vulnerability_db:
                vulnerability_db[key] = []
            vulnerability_db[key].extend(value)

@cli.command()
@click.option('--exploit', '-e', multiple=True, help='Specify exploits to run (e.g., session_hijacking, credential_extraction, payload_delivery).')
@click.option('--target-ssid', prompt='Target SSID', help='SSID of the target wireless network.')
@click.option('--target-bssid', prompt='Target BSSID', help='BSSID of the target wireless network.')
@click.pass_context
def exploit(ctx, exploit, target_ssid, target_bssid):
    """
    Run exploitation modules on identified vulnerabilities.
    """
    core = ctx.obj['core']
    vulnerability_db = core.vulnerability_db

    # Define the target
    target = {
        'ssid': target_ssid,
        'bssid': target_bssid
    }

    if not exploit:
        click.echo("No exploits specified. Available exploits are:")
        for ex in core.exploits.keys():
            click.echo(f"- {ex}")
        sys.exit(1)

    for ex in exploit:
        if ex not in core.exploits:
            click.echo(f"Exploit '{ex}' not found. Available exploits are:")
            for exploit_name in core.exploits.keys():
                click.echo(f"- {exploit_name}")
            continue

        # For session hijacking, require target session details
        if ex == 'session_hijacking':
            target_session = {}
            target_session['target_ip'] = click.prompt('Target IP', type=str)
            target_session['target_mac'] = click.prompt('Target MAC Address', type=str)
            target_session['gateway_ip'] = click.prompt('Gateway IP', type=str)
            target_session['gateway_mac'] = click.prompt('Gateway MAC Address', type=str)
            vuln = vulnerability_db.get(ex, {})
            vuln['target_session'] = target_session

        # For payload delivery, specify payload type
        if ex == 'payload_delivery':
            payload_type = click.prompt('Payload Type', type=click.Choice(['reverse_shell', 'malicious_script']))
            vuln = vulnerability_db.get(ex, {})
            vuln['payload_type'] = payload_type
            vuln['duration'] = click.prompt('Exploit Duration (seconds)', default=10, type=int)

        # Run the exploit
        click.echo(f"\nRunning exploit: {ex}")
        vulnerabilities = core.run_exploit(ex, vuln)
        # Merge vulnerabilities into the vulnerability_db
        for key, value in vulnerabilities.items():
            if key not in vulnerability_db:
                vulnerability_db[key] = []
            vulnerability_db[key].extend(value)

@cli.command()
@click.option('--set', 'settings', nargs=2, multiple=True, help='Set configuration settings (e.g., general.interface wlan0mon).')
@click.pass_context
def configure(ctx, settings):
    """
    Configure settings and preferences.
    """
    core = ctx.obj['core']
    if not settings:
        click.echo("Current Configuration:")
        config_path = os.path.join(core.config_manager.config_dir, 'config.yaml')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            for section, values in config.items():
                click.echo(f"[{section}]")
                for key, value in values.items():
                    click.echo(f"{key}: {value}")
                click.echo("")
        else:
            click.echo("No configuration found.")
        return

    for key, value in settings:
        try:
            core.config_manager.set_config(key, value)
            click.echo(f"Set {key} to {value}")
        except ValueError as ve:
            click.echo(str(ve))
            continue

    click.echo("Configuration updated successfully.")

@cli.command()
@click.option('--format', '-f', type=click.Choice(['json', 'txt']), default='txt', help='Format of the report.')
@click.pass_context
def report(ctx, format):
    """
    View and export scan and exploit reports.
    """
    core = ctx.obj['core']
    click.echo("Generating report...")

    report_data = {
        'scans': {},
        'exploits': {}
    }

    for scan_type, vulnerabilities in core.vulnerability_db.items():
        report_data['scans'][scan_type] = vulnerabilities

    if format == 'json':
        report_path = os.path.join(core.config_manager.config.report_directory, 'json', 'report.json')
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        click.echo(f"JSON report exported to {report_path}")
    else:
        report_path = os.path.join(core.config_manager.config.report_directory, 'txt', 'report.txt')
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, 'w') as f:
            for scan_type, vulnerabilities in report_data['scans'].items():
                f.write(f"Scanner: {scan_type}\n")
                for vuln in vulnerabilities:
                    f.write(f"  - SSID: {vuln.get('ssid', 'N/A')}\n")
                    f.write(f"    BSSID: {vuln.get('bssid', 'N/A')}\n")
                    f.write(f"    Protocol: {vuln.get('protocol', 'N/A')}\n")
                    f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
            for exploit_type, vulnerabilities in report_data['exploits'].items():
                f.write(f"Exploit: {exploit_type}\n")
                for vuln in vulnerabilities:
                    f.write(f"  - BSSID: {vuln.get('bssid', 'N/A')}\n")
                    f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
                    f.write(f"    Action: {vuln.get('action', 'N/A')}\n")
        click.echo(f"TXT report exported to {report_path}")

@cli.command()
@click.pass_context
def list(ctx):
    """
    List available scanners and exploits.
    """
    core = ctx.obj['core']
    click.echo("\nAvailable Scanners:")
    for sc in core.scanners.keys():
        click.echo(f"- {sc}")

    click.echo("\nAvailable Exploits:")
    for ex in core.exploits.keys():
        click.echo(f"- {ex}")

@cli.command()
@click.pass_context
def finalize(ctx):
    """
    Finalize testing activities and generate reports.
    """
    core = ctx.obj['core']
    core.logger.info("Finalizing and generating reports.")
    core.finalize()
    click.echo("Reports generated successfully.")
