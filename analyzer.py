import os
import base64
import requests

# Retrieve API Key securely from environment variables
API_KEY = os.getenv("VT_API_KEY")

def evaluate_risk(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    print(f"Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless}")

    if malicious >= 3:
        print("STATUS: [!!!] HIGH RISK - Malicious indicator detected. Block immediately!")
    elif malicious > 0 or suspicious > 0:
        print("STATUS: [?] LOW RISK / POSSIBLE FALSE POSITIVE - Manual verification required.")
    else:
        print("STATUS: [OK] CLEAN - No threats detected.")

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    res = requests.get(url, headers={"x-apikey": API_KEY})
    if res.status_code == 200:
        print(f"\n--- Analysis Report for IP: {ip} ---")
        evaluate_risk(res.json()["data"]["attributes"]["last_analysis_stats"])
    else:
        print(f"Error ({res.status_code}): Check the IP format or API Key.")

def check_url(target_url):
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    res = requests.get(url, headers={"x-apikey": API_KEY})
    if res.status_code == 200:
        print(f"\n--- Analysis Report for URL: {target_url} ---")
        evaluate_risk(res.json()["data"]["attributes"]["last_analysis_stats"])
    else:
        print(f"Error ({res.status_code}): URL not found in VirusTotal database.")

def check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    res = requests.get(url, headers={"x-apikey": API_KEY})
    if res.status_code == 200:
        print(f"\n--- Analysis Report for File Hash: {file_hash} ---")
        evaluate_risk(res.json()["data"]["attributes"]["last_analysis_stats"])
    else:
        print(f"Error ({res.status_code}): File hash not found.")

if __name__ == "__main__":
    if not API_KEY:
        print("[!] ERROR: API Key missing. Run: export VT_API_KEY='your_api_key'")
        exit(1)

    print("=== SOC Multi-IOC Threat Analyzer ===")
    print("1. Check IP Address")
    print("2. Check URL / Domain")
    print("3. Check File Hash (MD5/SHA256)")
    
    choice = input("\nSelect an option (1/2/3): ").strip()
    
    if choice == "1":
        check_ip(input("Enter IP address: ").strip())
    elif choice == "2":
        check_url(input("Enter URL (e.g., https://example.com): ").strip())
    elif choice == "3":
        check_hash(input("Enter File Hash: ").strip())
    else:
        print("Invalid selection.")
