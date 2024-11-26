import cmd
import logging
import sys
import os
from wireless_pen_test_lib.core import CoreFramework  # Replace with the actual import path for CoreFramework

class WirelessPenTestConsole(cmd.Cmd):
    intro = "Welcome to WirelessPenTest Console. Type 'help' or '?' to list commands.\n"
    prompt = "WirelessPenTest> "

    def __init__(self):
        super().__init__()
        self.core = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        # Set up logging handlers
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # print cwd
        print(f"Current Working Directory: {os.getcwd()}")

        try:
            self.logger.info("Initializing CoreFramework...")
            self.core = CoreFramework(
                modules_path='../core/config/protocols',
                config_dir="../../configs",
                vulnerabilities_path="../core/vulnerabilities/vulnerabilities.json",
            )
            self.logger.info("CoreFramework initialized successfully.")
        except Exception as e:
            self.logger.error(f"Failed to initialize CoreFramework: {e}")
            sys.exit(1)

    def do_scan(self, arg):
        """
        Execute a scan on the target network.
        Usage: scan <interface>
        """
        args = arg.split()
        if len(args) != 1:
            print("Usage: scan <interface>")
            return
        interface = args[0]
        print(f"Running scan on interface: {interface}")
        try:
            results = self.core.run_local_scan(interface)
            for device in results.get("devices", []):
                print(f"Device: {device}")
        except Exception as e:
            print(f"Error during scan: {e}")

    def do_exploit(self, arg):
        """
        Run an exploit against a discovered vulnerability.
        Usage: exploit <exploit_name>
        """
        args = arg.split()
        if len(args) != 1:
            print("Usage: exploit <exploit_name>")
            return
        exploit_name = args[0]
        print(f"Running exploit: {exploit_name}")
        try:
            results = self.core.run_exploit(exploit_name)
            print(f"Exploit results: {results}")
        except Exception as e:
            print(f"Error during exploit: {e}")

    def do_list(self, arg):
        """
        List available tools (scanners, exploits, etc.).
        Usage: list
        """
        print("\nAvailable Scanners:")
        for scanner in self.core.scanners.keys():
            print(f"  - {scanner}")
        print("\nAvailable Exploits:")
        for exploit in self.core.exploits.keys():
            print(f"  - {exploit}")

    def do_configure(self, arg):
        """
        Configure library settings.
        Usage: configure <key> <value>
        """
        args = arg.split()
        if len(args) != 2:
            print("Usage: configure <key> <value>")
            return
        key, value = args
        try:
            self.core.config_manager.set_config(key, value)
            print(f"Configuration updated: {key} = {value}")
        except Exception as e:
            print(f"Error updating configuration: {e}")

    def do_report(self, arg):
        """
        Generate a scan or exploit report.
        Usage: report <format>
        """
        args = arg.split()
        if len(args) != 1 or args[0] not in ["txt", "json"]:
            print("Usage: report <format>\nSupported formats: txt, json")
            return
        format = args[0]
        try:
            self.core.generate_report(format)
            print(f"Report generated in {format} format.")
        except Exception as e:
            print(f"Error generating report: {e}")

    def do_exit(self, arg):
        """
        Exit the console.
        Usage: exit
        """
        print("Exiting WirelessPenTest Console. Goodbye!")
        return True

    def default(self, line):
        print(f"Unknown command: {line}")

    def emptyline(self):
        pass  # Ignore empty lines

if __name__ == "__main__":
    WirelessPenTestConsole().cmdloop()
