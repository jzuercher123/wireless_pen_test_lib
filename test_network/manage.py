# test_network/manage.py

import subprocess
import argparse
import os
import sys

def run_command(command, cwd):
    try:
        subprocess.run(command, cwd=cwd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command '{' '.join(command)}' failed with error: {e}")
        sys.exit(1)

def start_network(compose_file):
    print("Starting test network...")
    run_command(['docker-compose', 'up', '-d'], cwd=os.path.dirname(compose_file))
    print("Test network started successfully.")

def stop_network(compose_file):
    print("Stopping test network...")
    run_command(['docker-compose', 'down'], cwd=os.path.dirname(compose_file))
    print("Test network stopped successfully.")

def status_network(compose_file):
    print("Checking test network status...")
    try:
        result = subprocess.run(['docker-compose', 'ps'], cwd=os.path.dirname(compose_file), check=True, stdout=subprocess.PIPE, text=True)
        output = result.stdout.strip()
        if "No containers" in output or "No services" in output:
            print("Test network is not running.")
        else:
            print("Test network is running:")
            print(output)
    except subprocess.CalledProcessError as e:
        print(f"Error checking test network status: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Manage Test Network")
    parser.add_argument('action', choices=['start', 'stop', 'status'], help="Action to perform on the test network.")
    args = parser.parse_args()

    compose_file = os.path.join(os.path.dirname(__file__), 'docker-compose.yml')

    if args.action == 'start':
        start_network(compose_file)
    elif args.action == 'stop':
        stop_network(compose_file)
    elif args.action == 'status':
        status_network(compose_file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
