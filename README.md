# Shodan-and-Censys-automation Tool

This is a Python tool that performs IP enumeration using the Shodan and Censys APIs. It collects information about a given IP address, such as open ports, services, banners, and other relevant details.

## Prerequisites

Before running the script, make sure you have the following:

- Python 3.x installed
- Required Python packages: `shodan`, `requests`, `configparser`
- Shodan API key and Censys authentication token (refer to the Configuration section)

## Configuration

Before running the script, you need to set up the configuration file. Follow these steps:

[SHODAN]
API_KEY = <your Shodan API key>

[CENSYS]
AUTH_TOKEN = <your Censys authentication token>


Replace `<your Shodan API key>` with your actual Shodan API key and `<your Censys authentication token>` with your Censys authentication token in Configuration.conf file.

## Usage

To use the script, follow these steps:

1. Open a command prompt or terminal.
2. Navigate to the project directory.
3. Run the script using the following command:

```shell
python <script_name>.py <IP_address>
```

Replace `<script_name>` with the actual name of your Python script file and `<IP_address>` with the IP address you want to enumerate.

4. The script will perform IP enumeration using both the Shodan and Censys APIs.
5. The results will be merged and saved to a file named `results.json` in the project directory.

## Contributing

Contributions to this project are welcome. If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer
This tool is provided for educational and research purpose only. The author of this project is no way responsible for any misuse of this tool.
