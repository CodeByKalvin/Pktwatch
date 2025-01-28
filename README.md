# Network Traffic Analyzer (CLI)

This is a command-line tool for capturing and analyzing network traffic to detect suspicious activity. It's designed for basic network monitoring and security analysis, focusing on a simple and straightforward implementation.

## Features

*   **Packet Capture:** Captures network traffic on a specified interface using the `scapy` library.
*   **Context Extraction:** Extracts key information from each packet, including:
    *   Timestamp
    *   Source and destination IP addresses
    *   Source and destination ports
    *   Protocol (TCP/UDP)
    *   User agent (when available from HTTP headers)
*   **Signature-Based Analysis:** Detects suspicious activity using a pre-defined set of rules loaded from a JSON file. These rules include:
    *   SQL injection patterns
    *   Command injection patterns
    *   Brute-force attempt keywords
    *   Long payload thresholds
*   **Thresholds:** Implements rate-limiting for brute-force detection by tracking login attempts per source IP within a time window.
*   **Protocol Decoding:** Provides basic parsing for:
    *   HTTP (identifies requests, user agent)
    *   DNS (identifies responses)
    *   SSH (identifies connection attempts)
*   **Simple Filtering:** Allows filtering of alerts based on a case-insensitive string search term.
*   **Basic Reporting:** Generates a plain text report with a summary of captured packets, generated alerts, and the list of all alerts.
*   **Command-Line Interface (CLI):** Provides a straightforward interface for interaction.
*   **Logging:** Saves events, alerts, and errors to a log file.

## Technologies Used

*   **Python 3.6+:** The primary programming language.
*   **Scapy:** For network packet capture and analysis (`pip install scapy`).
*   **JSON:** For storing attack signatures.
*   **Standard Libraries:**  `logging`, `re`, `time`, `collections`, `datetime`, `threading`.

## How to Use

1.  **Clone the Repository:**
    ```bash
    git clone [repository_url]
    cd [project_directory]
    ```
2.  **Install Dependencies:**
    ```bash
    pip install scapy
    ```
3.  **Run as Root/Administrator:** The script requires elevated privileges to capture network traffic.

    ```bash
    sudo python your_script_name.py
    ```
    (Replace `your_script_name.py` with the actual filename)

4.  **Interact with the CLI:**
    The application presents the following prompts:
    *   `start`: Start capturing and analyzing network traffic.
    *   `stop`: Stop capturing network traffic.
    *   `search`: Search alerts by case-insensitive string.
    *   `report`: Generate a basic report.
    *   `exit`: Stop and exit the application.

5.  **Check the output:**
    *   Alert messages will be shown on the console.
    *   Detailed log messages will be saved in `suspicious_traffic.log`.
    *   Reports will be saved in `traffic_report.txt`

## Configuration

The application is configured via a few global variables at the beginning of the Python script and an attack rules file `attack_rules.json`:

*   `INTERFACE`: The network interface to sniff (e.g., "eth0", "wlan0").
*   `FILTER`: The scapy filter string (e.g., "tcp or udp").
*   `LOG_FILE`: Name of the log file (default: "suspicious_traffic.log").
*   `RULE_FILE`:  Name of the attack rules file (default: "attack_rules.json")
*   `REPORT_FILE`:  Name of the report file (default "traffic_report.txt").
*   `MAX_LOGIN_ATTEMPTS`: Maximum login attempts within a given time period.
*   `LOGIN_ATTEMPT_WINDOW`: The time window (in seconds) for brute-force detection.

The `attack_rules.json` file defines the attack patterns. Example:

```json
{
  "sql_injection": [
      "'.*?--",
      "union\\s+select",
      "exec\\(",
      "\\s+or\\s+\\d+\\s*=\\s*\\d+",
      "\\s+and\\s+1=1",
      "information_schema",
      ";"
    ],
  "command_injection": [
      "\\|",
      ";",
      "`",
      "\\$\\(",
      "sh\\s+-c"
    ],
   "brute_force_keywords": [
      "login",
      "failed|invalid|incorrect",
      "password"
    ],
   "long_payload": {
     "threshold": 4000
    }
}

```
## Important Notes

    Run as Root/Administrator: Capturing network packets requires elevated privileges.

    Responsibility: Use this tool responsibly and only on networks where you have permission to analyze traffic.

    False Positives: The tool may generate false positives. Adjust attack rules for your needs.

    Security Disclaimer: This tool is not a complete or professional-grade security solution. It's a basic tool to explore network analysis.

## Further Development

Future enhancements could include:

    More complex filtering logic.

    More detailed and customizable reports.

    An interactive command-line interface using a library like prompt_toolkit.

    Expanding protocol decoding with support for more protocols.

    A more robust and flexible rule format, with support for multiple thresholds or rules.

## Contributing

Feel free to contribute by forking the repository and submitting pull requests.

## License

Mit License
