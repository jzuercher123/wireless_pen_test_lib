# WirelessPenTestLib

WirelessPenTestLib is a comprehensive tool for wireless network penetration testing. It provides a graphical user interface (GUI) for various functionalities such as live network monitoring, fake device management, and rogue access point setup.

## Features

- **Live Network Details**: Monitor live network details and connected devices.
- **Live Packet Monitor**: Capture and analyze network packets in real-time.
- **Fake Devices Manager**: Manage fake devices for testing purposes.
- **Rogue Access Point Manager**: Create and manage rogue access points.
- **Scans**: Perform network scans using various scanners.
- **Exploits**: Execute network exploits.
- **Reports**: Generate and export detailed reports.
- **Settings**: Configure application settings.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/wireless_pen_test_lib.git
    cd wireless_pen_test_lib
    ```

2. Create a virtual environment and activate it:
    ```sh
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```

3. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Ensure you have the necessary permissions to run the application:
    ```sh
    sudo python main.py
    ```

2. Run the application:
    ```sh
    python main.py
    ```

## Running Tests

To run the tests, use the following command:
```sh
pytest