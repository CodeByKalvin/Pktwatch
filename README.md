# Pktwatch

Pktwatch is a Python-based network security monitoring application designed to capture and analyze network traffic for suspicious activities.

This application captures network packets, analyzes them against a set of predefined attack signatures, and alerts you through logging and console output when suspicious traffic is detected.

### Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Starting and Stopping the Sniffer](#starting-and-stopping-the-sniffer)
  - [Generating Reports](#generating-reports)
  - [Searching Alerts](#searching-alerts)
  - [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Important Notes](#important-notes)
- [Contributing](#contributing)
- [License](#license)
- [Future Improvements](#future-improvements)
- [Authors](#authors)

---

### Features

-   **Packet Capture:** Sniffs network packets using Scapy.
-   **Real-time Analysis:** Analyzes captured packets in real-time against attack signatures.
-   **Attack Detection:** Detects common attack patterns like SQL injection, command injection, brute force attempts, and long payloads.
-   **Logging:** Logs suspicious activity with relevant context (timestamp, protocol, source/destination IP/port).
-   **Reporting:** Generates reports summarizing captured traffic and alerts.
-   **Alert Searching:** Allows searching for specific alerts based on keywords.
-   **Configurable Rules:** Attack signatures are defined in a JSON file, allowing easy customization and extension.
-   **Brute-Force Detection:** Tracks login attempts and flags potential brute-force attacks based on configurable thresholds.

---

### Installation

To run Pktwatch locally, follow these steps:

#### 1. Clone the Repository

```bash
git clone https://github.com/CodeByKalvin/Pktwatch.git 
cd Pktwatch
```

#### 2. Install Dependencies

Make sure you have **Python 3** installed. Install the required dependencies using `pip`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` should contain the following (or similar):

```txt
scapy
logging
re
time
json
collections
datetime
threading
```

**Important:**  Scapy might require additional steps depending on your operating system. Refer to the Scapy documentation for installation instructions.
---

### Usage

Once installed, you can run the application from the command line using:

```bash
sudo python pktwatch.py
```

This will launch the Pktwatch command-line interface, where you can start and stop the sniffer, generate reports, and search alerts.

---

#### Starting and Stopping the Sniffer

-   Enter `start` to start the network sniffer. This will begin capturing and analyzing network traffic.
-   Enter `stop` to stop the network sniffer.

---

#### Generating Reports

-   Enter `report` to generate a report of the captured traffic and alerts. The report will be saved to the `traffic_report.txt` file.

---

#### Searching Alerts

-   Enter `search` to search for specific alerts. You will be prompted to enter a search term.  The tool will then display any alerts containing that term in the message.

---

#### Configuration

The application is configured via a few global variables at the beginning of the Python script and an attack rules file `attack_rules.json`:

*   `INTERFACE`: The network interface to sniff (e.g., "eth0", "wlan0").
*   `FILTER`: The scapy filter string (e.g., "tcp or udp").
*   `LOG_FILE`: Name of the log file (default: "suspicious.log").
*   `RULE_FILE`:  Name of the attack rules file (default: "attack_rules.json")
*   `REPORT_FILE`:  Name of the report file (default "traffic_report.txt").
*   `MAX_LOGIN_FAILS`: Maximum login attempts within a given time period.
*   `LOGIN_WINDOW`: The time window (in seconds) for brute-force detection.

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
  "cmd_injection": [
      "\\|",
      ";",
      "`",
      "\\$\\(",
      "sh\\s+-c"
    ],
   "brute_force": [
      "login",
      "failed|invalid|incorrect",
      "password"
    ],
   "long_payload": {
     "threshold": 4000
    }
}
```

**Important:** When defining regular expressions in `attack_rules.json`, remember to escape special characters appropriately (e.g., `\` for backslash).

---

### Project Structure

```
Pktwatch/
│
├── pktwatch.py          # Main Python script
├── README.md            # This README file
├── requirements.txt     # List of dependencies
├── attack_rules.json    # Attack rule configuration file
├── suspicious.log       # Log file for suspicious activity
└── traffic_report.txt   # Report file for traffic analysis
```

---

### Requirements

-   **Python 3** or higher
-   **Pip** to install dependencies
-   **Scapy:**  For packet capture and analysis.
-   **Regular Expression (re):** Used for matching attack signatures.
-   **Other standard Python Libraries:** logging, time, json, collections, datetime, threading.  These are typically included with Python.

To install the dependencies:

```bash
pip install -r requirements.txt
```

---

## Important Notes

-   **Run as Root/Administrator:** Capturing network packets requires elevated privileges.  You typically need to run the script with `sudo` on Linux/macOS.
-   **Responsibility:** Use this tool responsibly and only on networks where you have permission to analyze traffic.
-   **False Positives:** The tool may generate false positives. Adjust attack rules for your needs.
-   **Security Disclaimer:** This tool is not a complete or professional-grade security solution. It's a basic tool to explore network analysis.

### Contributing

If you want to contribute to this project, feel free to submit a pull request or create an issue with a detailed description of the feature or bug you're addressing.

#### Steps to Contribute:

1.  Fork the repository.
2.  Create a new branch for your feature (`git checkout -b feature-name`).
3.  Make your changes.
4.  Test your changes.
5.  Commit your changes (`git commit -m 'Add some feature'`).
6.  Push to your branch (`git push origin feature-name`).
7.  Create a pull request.

---

### Future Improvements

-   Implement more sophisticated attack detection techniques.
-   Add support for different output formats (e.g., JSON, CSV).
-   Enhance reporting capabilities with more detailed statistics.
-   Develop a graphical user interface (GUI).
-   Add the ability to save captured packets to a PCAP file.
-   Improve documentation and add more example attack signatures.

---

### License

This project is open-source and available under the [MIT License](LICENSE).

---

### Authors

-   **CodeByKalvin** - *Initial work* - [GitHub Profile](https://github.com/codebykalvin)
