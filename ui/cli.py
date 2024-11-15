# ui/cli.py

import click
import os
import sys
import json
import yaml
import subprocess
import logging
import pandas as pd
from colorama import Fore
from core.config.protocols import register_scanners
from core.config.protocols import register_exploits


# Configure logging within cli.py if necessary or rely on core/__init__.py's logging
# Set up basic logging to capture errors during initialization
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ensure the project root is in the Python path for absolute imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def initialize_coreframework():
    from core import CoreFramework  # Import inside the function to avoid circular imports
    protocols_path = os.path.join(project_root, 'core', 'config', 'protocols')  # Correct path to protocols
    return CoreFramework(
        modules_path=protocols_path,  # Correct modules_path
        config_dir=os.path.join(project_root, 'core', 'config'), # Correct config_dir
        scanners=register_scanners(),
        exploits=register_exploits()
    )

@click.group()
@click.version_option(version='1.0.0', prog_name='WirelessPenTestLib')
@click.pass_context
def cli(ctx):
    """
    WirelessPenTestLib: A Comprehensive Wireless Penetration Testing Library
    """
    protocols_path = os.path.join(project_root, 'core', 'config', 'protocols')

    ctx.ensure_object(dict)
    try:
        # Initialize CoreFramework using the separate function
        core = initialize_coreframework()
        core.load_protocol_modules()
        ctx.obj['core'] = core
        core.logger.info("CLI initialized successfully with project root: %s and protocols path: %s", project_root, protocols_path)
    except Exception as e:
        logger.exception("Error initializing CoreFramework")  # Use logger here instead of core.logger
        click.echo(f"Error initializing CoreFramework: {e}")
        ctx.exit(1)


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
        click.echo("No scanners specified. Running all available scanners.")
        scanner = list(core.scanners.keys())

    for sc in scanner:
        if sc not in core.scanners:
            click.echo(f"Scanner '{sc}' not found. Available scanners are:")
            for scanner_name in core.scanners.keys():
                click.echo(f"- {scanner_name}")
            continue
        click.echo(f"\nRunning scanner: {sc}")
        try:
            vulnerabilities = core.run_scanner(sc, target)
            # Merge vulnerabilities into the vulnerability_db
            for key, value in vulnerabilities.items():
                if key not in vulnerability_db:
                    vulnerability_db[key] = []
                vulnerability_db[key].extend(value)
        except Exception as e:
            core.logger.exception(f"Error running scanner '{sc}'")
            click.echo(f"Error running scanner '{sc}': {e}")
            continue  # Skip failed scanner and proceed with the next one
    click.echo("\nAll specified scans have been executed.")

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
        ctx.exit(1)

    for ex in exploit:
        if ex not in core.exploits:
            click.echo(f"Exploit '{ex}' not found. Available exploits are:")
            for exploit_name in core.exploits.keys():
                click.echo(f"- {exploit_name}")
            continue

        # Prepare vulnerability information based on exploit type
        vuln_info = {}
        if ex == 'session_hijacking':
            click.echo("\n--- Session Hijacking Configuration ---")
            vuln_info['target_session'] = {
                'target_ip': click.prompt('Target IP', type=str),
                'target_mac': click.prompt('Target MAC Address', type=str),
                'gateway_ip': click.prompt('Gateway IP', type=str),
                'gateway_mac': click.prompt('Gateway MAC Address', type=str)
            }
        elif ex == 'payload_delivery':
            click.echo("\n--- Payload Delivery Configuration ---")
            vuln_info['payload_type'] = click.prompt('Payload Type', type=click.Choice(['reverse_shell', 'malicious_script']))
            vuln_info['duration'] = click.prompt('Exploit Duration (seconds)', default=10, type=int)

        # Run the exploit
        click.echo(f"\nRunning exploit: {ex}")
        try:
            vulnerabilities = core.run_exploit(ex, vuln_info)
            # Merge vulnerabilities into the vulnerability_db
            for key, value in vulnerabilities.items():
                if key not in vulnerability_db:
                    vulnerability_db[key] = []
                vulnerability_db[key].extend(value)
        except Exception as e:
            core.logger.exception(f"Error running exploit '{ex}'")
            click.echo(f"Error running exploit '{ex}': {e}")
            ctx.exit(1)
    click.echo("\nAll specified exploits have been executed.")

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
        config_path = os.path.join(str(core.config_manager.config_dir), 'config.yaml')
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                for section, values in config.items():
                    click.echo(f"\n[{section}]")
                    for key, value in values.items():
                        click.echo(f"{key}: {value}")
            except Exception as e:
                core.logger.exception("Error reading configuration")
                click.echo(f"Error reading configuration: {e}")
                ctx.exit(1)
        else:
            click.echo("No configuration found.")
        return

    for key, value in settings:
        try:
            core.config_manager.set_config(key, value)
            click.echo(f"Set '{key}' to '{value}'.")
        except ValueError as ve:
            core.logger.exception(f"Error setting '{key}'")
            click.echo(f"Error setting '{key}': {ve}")
            continue

    click.echo("\nConfiguration updated successfully.")

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

    # Categorize scan and exploit data
    for scan_type, vulnerabilities in core.vulnerability_db.items():
        if scan_type.startswith('scan'):
            report_data['scans'][scan_type] = vulnerabilities
        elif scan_type.startswith('exploit'):
            report_data['exploits'][scan_type] = vulnerabilities

    if format == 'json':
        report_path = os.path.normpath(os.path.join(str(core.config_manager.general.report_directory), 'json', 'report.json'))
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        try:
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=4)
            click.echo(f"JSON report exported to {report_path}")
        except Exception as e:
            core.logger.exception("Error exporting JSON report")
            click.echo(f"Error exporting JSON report: {e}")
    else:
        report_path = os.path.normpath(os.path.join(str(core.config_manager.general.report_directory), 'txt', 'report.txt'))
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        try:
            with open(report_path, 'w') as f:
                for scan_type, vulnerabilities in report_data['scans'].items():
                    f.write(f"Scanner: {scan_type}{os.linesep}")
                    for vuln in vulnerabilities:
                        f.write(f"  - SSID: {vuln.get('ssid', 'N/A')}{os.linesep}")
                        f.write(f"    BSSID: {vuln.get('bssid', 'N/A')}{os.linesep}")
                        f.write(f"    Protocol: {vuln.get('protocol', 'N/A')}{os.linesep}")
                        f.write(f"    Description: {vuln.get('description', 'N/A')}{os.linesep}")
                for exploit_type, vulnerabilities in report_data['exploits'].items():
                    f.write(f"Exploit: {exploit_type}{os.linesep}")
                    for vuln in vulnerabilities:
                        f.write(f"  - BSSID: {vuln.get('bssid', 'N/A')}{os.linesep}")
                        f.write(f"    Description: {vuln.get('description', 'N/A')}{os.linesep}")
                        f.write(f"    Action: {vuln.get('action', 'N/A')}{os.linesep}")
            click.echo(f"TXT report exported to {report_path}")
        except Exception as e:
            core.logger.exception("Error exporting TXT report")
            click.echo(f"Error exporting TXT report: {e}")

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
@click.option('--action', type=click.Choice(['start', 'stop', 'status']), required=True, help="Action to perform on the test network.")
@click.pass_context
def test_network(ctx, action):
    """
    Manage the test network environment.
    """
    core = ctx.obj['core']
    core.logger.info("Managing test network with action: %s", action)
    manage_script = os.path.normpath(os.path.join(project_root, 'test_network', 'manage.py'))
    manage_script = os.path.abspath(manage_script)

    if not os.path.exists(manage_script):
        click.echo(f"Manage script not found at {manage_script}")
        ctx.exit(1)

    if action == 'start':
        click.echo("Starting test network...")
        try:
            result = subprocess.run(['python', manage_script, 'start'], check=True, capture_output=True, text=True)
            click.echo(result.stdout)
            click.echo("Test network started successfully.")
        except subprocess.CalledProcessError as e:
            core.logger.exception("Error starting test network")
            click.echo(f"Error starting test network: {e}")
            click.echo(e.stderr)
            ctx.exit(1)
    elif action == 'stop':
        click.echo("Stopping test network...")
        try:
            result = subprocess.run(['python', manage_script, 'stop'], check=True, capture_output=True, text=True)
            click.echo(result.stdout)
            click.echo("Test network stopped successfully.")
        except subprocess.CalledProcessError as e:
            core.logger.exception("Error stopping test network")
            click.echo(f"Error stopping test network: {e}")
            click.echo(e.stderr)
            ctx.exit(1)
    elif action == 'status':
        click.echo("Checking test network status...")
        try:
            result = subprocess.run(['python', manage_script, 'status'], check=True, capture_output=True, text=True)
            click.echo(result.stdout)
        except subprocess.CalledProcessError as e:
            core.logger.exception("Error checking test network status")
            click.echo(f"Error checking test network status: {e}")
            click.echo(e.stderr)
            ctx.exit(1)
    else:
        click.echo("Invalid action.")
        ctx.exit(1)

# local network scan
@cli.command()
@click.pass_context
def local_scan(ctx):
    """
    Perform a local network scan using LocalScanner.
    """
    import click  # Ensure click is available
    core = ctx.obj.get('core')
    if not core:
        logger.error("Core framework is not initialized.")
        click.echo("Error: Core framework is not initialized.")
        ctx.exit(1)

    # Access the LocalScanner class; ensure 'local_network' is registered correctly
    try:
        local_scanner_class = core.scanners['local']  # Ensure this key is correct
    except KeyError:
        logger.error("LocalScanner ('local_network') is not registered in core.scanners.")
        click.echo("Error: LocalScanner ('local_network') is not registered. Please check your scanner registrations.")
        ctx.exit(1)

    # List available interfaces using the LocalScanner's static method
    try:
        available_interfaces = local_scanner_class.list_interfaces()
    except Exception as e:
        logger.exception("Failed to list network interfaces.")
        click.echo(f"Error: Failed to list network interfaces. Details: {e}")
        ctx.exit(1)

    if not available_interfaces:
        logger.info("No network interfaces found.")
        click.echo("No network interfaces found.")
        return

    # Create a DataFrame for available interfaces
    interfaces_df = pd.DataFrame({
        'Index': range(1, len(available_interfaces) + 1),
        'Interface Name': available_interfaces
    })

    click.echo(Fore.CYAN + "\nAvailable Network Interfaces:")
    click.echo(interfaces_df.to_string(index=False))

    # Prompt the user to select an interface using click's prompt
    try:
        selected_idx = click.prompt(
            f"\nSelect an interface [1-{len(available_interfaces)}]",
            type=click.IntRange(1, len(available_interfaces))
        )
        selected_interface = available_interfaces[selected_idx - 1]
    except click.exceptions.BadParameter as e:
        logger.error(f"Invalid selection: {e}")
        click.echo("Invalid selection. Please enter a valid number corresponding to the listed interfaces.")
        return

    # Initialize the LocalScanner with the selected interface
    try:
        scanner = local_scanner_class(selected_interface)
    except Exception as e:
        logger.exception(f"Failed to initialize LocalScanner with interface '{selected_interface}'.")
        click.echo(f"Error: Failed to initialize scanner. Details: {e}")
        return

    # Attempt to set monitor mode
    try:
        scanner.set_monitor_mode()
    except Exception as e:
        logger.error(f"Failed to set monitor mode on interface '{selected_interface}': {e}")
        click.echo(f"Error: Failed to set monitor mode on interface '{selected_interface}'. Details: {e}")
        # Decide whether to exit or continue; here we continue to show details
        # ctx.exit(1)

    # Retrieve and display interface details
    try:
        details = scanner.get_interface_details()
    except Exception as e:
        logger.error(f"Failed to retrieve interface details for '{selected_interface}': {e}")
        click.echo(f"Error: Failed to retrieve interface details for '{selected_interface}'. Details: {e}")
        return

    if not details:
        logger.info(f"No details found for interface '{selected_interface}'.")
        click.echo(f"No details found for interface '{selected_interface}'.")
        return

    # Convert details to DataFrame
    details_df = pd.DataFrame(details)

    click.echo(Fore.GREEN + f"\nInterface Details for '{selected_interface}':")
    click.echo(details_df.to_string(index=False))

@cli.command()
@click.pass_context
def finalize(ctx):
    """
    Finalize testing activities and generate reports.
    """
    core = ctx.obj['core']
    try:
        core.logger.info("Finalizing and generating reports.")
        core.finalize()
        click.echo("Reports generated successfully.")
    except Exception as e:
        core.logger.exception("Error during finalization")
        click.echo(f"Error during finalization: {e}")
        ctx.exit(1)
