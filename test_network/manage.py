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
    run_command(['docker-compose', 'ps'], cwd=os.path.dirname(compose_file))
    print("Test network status displayed above.")

def main():
    parser = argparse.ArgumentParser(description="Manage the test network environment.")
    parser.add_argument('action', choices=['start', 'stop', 'status'], help="Action to perform on the test network.")
    parser.add_argument('--compose-file', default='docker-compose.yml', help="Path to the docker-compose file.")

    args = parser.parse_args()

    compose_file = args.compose_file

    if not os.path.exists(compose_file):
        print(f"Docker Compose file '{compose_file}' not found.")
        sys.exit(1)

    if args.action == 'start':
        start_network(compose_file)
    elif args.action == 'stop':
        stop_network(compose_file)
    elif args.action == 'status':
        status_network(compose_file)
    else:
        print(f"Unknown action '{args.action}'.")
        sys.exit(1)

if __name__ == '__main__':
    main()
