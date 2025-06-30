import requests
import argparse
import csv
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CSV_FILE = "ip_check_results.csv"

def VirustotalCheck(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal request failed: {e}"}

def AbuseipdbCheck(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"AbuseIPDB request failed: {e}"}

def write_to_csv(data):
    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, 'a', newline='') as csvfile:
        fieldnames = [
            'check_timestamp', 'ip_address', 'abuseipdb_score',
            'abuseipdb_country', 'abuseipdb_isp', 'virustotal_reputation',
            'virustotal_malicious_hits'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

def main():
    parser = argparse.ArgumentParser(
        description="Check IP addresses from a file with VirusTotal and AbuseIPDB.",
        usage="usage: python3 %(prog)s <file.txt>"
    )
    parser.add_argument("input_file", metavar="<file.txt>", help="Path to a text file containing IP addresses (.txt file btw).")
    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print(f"[!] Error: Input file not found at '{args.input_file}'")
        return

    with open(args.input_file, 'r') as f:
        ip_addresses = [line.strip() for line in f if line.strip()]

    print(f"[*] Found {len(ip_addresses)} IP addresses to check.")

    for ip in ip_addresses:
        print(f"--- Checking IP: {ip} ---")

        vt_data = check_virustotal(ip)
        abuse_data = check_abuseipdb(ip)

        #AbuseIP
        abuse_score = "N/A"
        abuse_country = "N/A"
        abuse_isp = "N/A"
        if "error" in abuse_data:
            print(f"  [!] AbuseIPDB: {abuse_data['error']}")
        elif 'data' in abuse_data:
            abuse_score = abuse_data['data']['abuseConfidenceScore']
            abuse_country = abuse_data['data']['countryCode']
            abuse_isp = abuse_data['data']['isp']
            print(f"  [+] AbuseIPDB Score: {abuse_score}%")
            print(f"  [+] Country: {abuse_country}")
            print(f"  [+] ISP: {abuse_isp}")

        # VirusTotal
        vt_reputation = "N/A"
        vt_malicious_hits = 0
        if "error" in vt_data:
            print(f"[!] VirusTotal: {vt_data['error']}")
        elif 'data' in vt_data:
            attributes = vt_data['data']['attributes']
            vt_reputation = attributes['reputation']
            vt_malicious_hits = attributes['last_analysis_stats']['malicious']
            print(f"  [+] VirusTotal Reputation: {vt_reputation}")
            print(f"  [+] Malicious Detections: {vt_malicious_hits}")

        #Save data to csv
        csv_data = {
            'check_timestamp': datetime.now().isoformat(),
            'ip_address': ip,
            'abuseipdb_score': abuse_score,
            'abuseipdb_country': abuse_country,
            'abuseipdb_isp': abuse_isp,
            'virustotal_reputation': vt_reputation,
            'virustotal_malicious_hits': vt_malicious_hits
        }
        write_to_csv(csv_data)

    print(f"[*] All checks complete. Results saved to {CSV_FILE}")


if __name__ == "__main__":
    main()
