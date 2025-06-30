# IP Reputation Checker

Just a simple script I wrote to quickly check a list of IP addresses with VirusTotal and AbuseIPDB. It saves the results in a CSV file so I can look at them later.

I needed a quick way to get reputation data for a bunch of IPs without having to manually look them up one by one. This script automates that process for me.

## Setup

1.  **API Keys:** This script needs API keys to talk to VirusTotal and AbuseIPDB.
    *   Get a free [VirusTotal API key](https://www.virustotal.com/gui/join-us).
    *   Get a free [AbuseIPDB API key](https://www.abuseipdb.com/register).

2.  **Securely Store Keys:**
    *   Create a file named `.env` in the same directory as `ip_check.py`.
    *   Add your API keys to this file like this (replace with the actual keys):

        ```
        VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
        ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_API_KEY"
        ```
    **Future plan** 
    I will implement API key encryption soon (idk if it's actually useful tho. it's just for fun)

3.  **Install Dependencies:** The script uses the `requests` and `python-dotenv` libraries. You can install them using pip:
    ```bash
    pip install -r requirements.txt
    ```

## How to Use

1.  Create a text file (e.g., `ips.txt`) and put one IP address on each line.
    ```
    8.8.8.8
    1.1.1.1
    123.123.123.123

    ```

2.  Run the script from your terminal and give it the path to your file.
    ```bash
    python3 ip_check.py ips.txt
    ```

The script will print the results to the screen and also save them in a file named `ip_check_results.csv` in the same directory.
