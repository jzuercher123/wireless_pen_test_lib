## **Installation**

1. **Clone the Repository**

    ```bash
    git clone https://github.com/yourusername/wireless_pen_test_lib.git
    cd wireless_pen_test_lib
    ```

2. **Create a Virtual Environment**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install Python Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4. **Install System Dependencies**

    - **Aircrack-ng**:

        ```bash
        sudo apt-get install aircrack-ng
        ```

    - **Other Dependencies**:

        Install any other required system packages as needed.

5. **Set Up Wireless Interface**

    - Switch your wireless interface to monitor mode using `airmon-ng`:

        ```bash
        sudo airmon-ng start wlan0
        ```

    - Verify that `wlan0mon` (or similar) is active.

6. **Run the Test Script**

    ```bash
    sudo python tests/test_scanners.py
    ```

## **Usage Guidelines**

- **Ethical Usage**: Always obtain explicit permission before testing networks.
- **Legal Compliance**: Ensure compliance with local laws and regulations regarding wireless testing.
- **Safe Operations**: Use the library responsibly to avoid unintended network disruptions.

## **Contributing**

Contributions are welcome! Please submit pull requests or open issues for any enhancements or bugs.

## **License**

Specify your project's license here.

