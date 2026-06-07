import argparse
import sys
import re
import json

# Optimized regular expression to extract key security telemetry fields
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\b[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'  
    r'\S+\s+sshd\[\d+\]:\s+'                                       
    r'(?P<status>Failed password|Accepted password)\s+for\s+'      
    r'(?:invalid user\s+)?(?P<user>\S+)\s+from\s+'                 
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'                  
)

DEFENSIVE_THRESHOLD = 3

def parse_log_file(file_path):
    parsed_events = []
    failed_attempts_tracker = {}
    flagged_malicious_ips = []
    
    try:
        with open(file_path, 'r') as file:
            print(f"[*] Starting Real-Time Telemetry Analysis on: {file_path}\n" + "="*65)
            
            for line in file:
                match = LOG_PATTERN.search(line)
                if match:
                    data = match.groupdict()
                    parsed_events.append(data)
                    source_ip = data['ip']
                    
                    if data['status'] == "Failed password":
                        failed_attempts_tracker[source_ip] = failed_attempts_tracker.get(source_ip, 0) + 1
                        current_failures = failed_attempts_tracker[source_ip]
                        
                        if current_failures >= DEFENSIVE_THRESHOLD:
                            print(f"[CRITICAL] Brute-Force signature from IP: {source_ip} ({current_failures} failures)")
                            if source_ip not in flagged_malicious_ips:
                                flagged_malicious_ips.append(source_ip)
                        else:
                            print(f"[ALERT] Failed login attempt from {source_ip} | User: {data['user']}")
                            
                    elif data['status'] == "Accepted password":
                        print(f"[INFO] Successful authentication: User '{data['user']}' from {source_ip}")
            
            # --- NEW: GENERATE EXECUTIVE SUMMARY REPORT ---
            print("\n" + "="*65)
            print("                SOC POST-ANALYSIS INCIDENT REPORT               ")
            print("="*65)
            print(f"[+] Total Authentication Events Scanned: {len(parsed_events)}")
            print(f"[+] Total Unique IP Addresses Interacted: {len(set(e['ip'] for e in parsed_events))}")
            print(f"[+] Malicious IPs Recommended for Firewall Block: {len(flagged_malicious_ips)}")
            
            for bad_ip in flagged_malicious_ips:
                print(f"    └── 🛑 BLOCK IMMEDIATELY: {bad_ip} ({failed_attempts_tracker[bad_ip]} attempts)")
            print("="*65)
            
            # --- NEW: JSON EXPORT ENGINE ---
            report_data = {
                "total_events_parsed": len(parsed_events),
                "malicious_ips_detected": flagged_malicious_ips,
                "attacker_metrics": failed_attempts_tracker
            }
            
            output_json_file = "security_report.json"
            with open(output_json_file, 'w') as json_file:
                json.dump(report_data, json_file, indent=4)
            print(f"[*] Threat intelligence exported successfully to: {output_json_file}\n")
                
    except FileNotFoundError:
        print(f"[-] Error: File '{file_path}' not found.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="SOC Telemetry Parser Labs")
    parser.add_argument('-f', '--file', required=True, help="Path to target log file")
    args = parser.parse_args()
    parse_log_file(args.file)

if __name__ == "__main__":
    main()