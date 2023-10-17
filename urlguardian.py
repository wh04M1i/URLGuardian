import requests
import json
from datetime import datetime

# Replace 'YOUR_API_KEY' with your VirusTotal API key
API_KEY = 'YOUR_API_KEY'

# Function to scan an IP address or URL on VirusTotal
def scan_ip_or_url(ip_or_url):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': API_KEY, 'url': ip_or_url}
    response = requests.post(url, data=params)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return None

# Function to get the scan report
def get_scan_report(resource):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return None

# Read input from a text file
input_file = 'input.txt'
output_file = 'output.txt'

with open(output_file, 'a') as output:
    output.write(f"Scan Date and Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

with open(input_file, 'r') as f:
    for line in f:
        ip_or_url = line.strip()
        scan_result = scan_ip_or_url(ip_or_url)
        if scan_result:
            resource = scan_result['resource']
            report = get_scan_report(resource)
            if report:
                with open(output_file, 'a') as output:
                    output.write(f"IP/URL: {ip_or_url}\n")
                    output.write("Scan Results:\n")
                    output.write(f"   - Total Engines: {report['total']}\n")
                    output.write(f"   - Detected as Malicious: {report['positives']}\n")
                    output.write(f"   - Clean: {report['total'] - report['positives']}\n")
                    output.write(f"Detection Ratio: {report['positives']}/{report['total']}\n")
                    output.write("Antivirus Engines That Detected as Malicious:\n")
                    for scanner, result in report['scans'].items():
                        if result['detected']:
                            output.write(f"   - {scanner}\n")
                    output.write("Additional Metadata:\n")
                    output.write(f"   - Scan ID: {report['scan_id']}\n")
                    output.write(f"   - Permalink: {report['permalink']}\n")
                    output.write("\n")
