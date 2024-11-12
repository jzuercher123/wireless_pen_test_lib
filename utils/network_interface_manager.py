import subprocess
import logging

class NetworkInterfaceManager:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def run_command(self, command: list) -> subprocess.CompletedProcess:
        """
        Executes a system command and returns the CompletedProcess instance.
        """
        self.logger.debug(f"Executing command: {' '.join(command)}")
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.logger.debug(f"Command Output: {result.stdout}")
            if result.stderr:
                self.logger.warning(f"Command Error Output: {result.stderr}")
            return result
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command '{' '.join(command)}' failed with error: {e.stderr}")
            raise e

    def enable_monitor_mode(self, interface: str):
        """
        Enables monitor mode on the specified wireless interface.
        """
        self.logger.info(f"Enabling monitor mode on interface {interface}")
        # Stop the network manager to prevent conflicts
        self.run_command(['sudo', 'airmon-ng', 'check', 'kill'])
        # Start monitor mode
        self.run_command(['sudo', 'airmon-ng', 'start', interface])

    def disable_monitor_mode(self, interface: str):
        """
        Disables monitor mode on the specified wireless interface.
        """
        self.logger.info(f"Disabling monitor mode on interface {interface}")
        self.run_command(['sudo', 'airmon-ng', 'stop', interface])
        # Restart the network manager
        self.run_command(['sudo', 'service', 'NetworkManager', 'restart'])

    def bring_interface_up(self, interface: str):
        """
        Brings the specified network interface up.
        """
        self.logger.info(f"Bringing interface {interface} up")
        self.run_command(['sudo', 'ifconfig', interface, 'up'])

    def bring_interface_down(self, interface: str):
        """
        Brings the specified network interface down.
        """
        self.logger.info(f"Bringing interface {interface} down")
        self.run_command(['sudo', 'ifconfig', interface, 'down'])

    def get_interface_status(self, interface: str) -> str:
        """
        Retrieves the status of the specified network interface.
        """
        self.logger.debug(f"Retrieving status for interface {interface}")
        result = self.run_command(['iwconfig', interface])
        if "Mode:Monitor" in result.stdout:
            status = "Monitor Mode"
        elif "Mode:Managed" in result.stdout:
            status = "Managed Mode"
        else:
            status = "Unknown"
        self.logger.info(f"Interface {interface} is in {status}")
        return status
