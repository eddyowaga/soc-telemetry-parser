import argparse
import sys
import re
import json

# This regex captures the date, status (Failed/Accepted), user, and source IP
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\b[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'  # Matches Date & Time
    r'\S+\s+sshd\[\d+\]:\s+'                                       # Matches system process identifiers
    r'(?P<status>Failed password|Accepted password)\s+for\s+'      # Matches Auth Status
    r'(?:invalid user\s+)?(?P<user>\S+)\s+from\s+'                 # Matches Username (handles "invalid user" flag)
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'                  # Matches Source IP Address
)

def parse_log_file(file_path):
    """
    Reads log file line by line, extracts telemetry fields using regex,
    and prints structured alerts.
    """
    parsed_events = []
    
    try:
        with open(file_path, 'r') as file:
            print(f"[*] Starting log parsing on: {file_path}\n" + "="*50)
            
            for line_num, line in enumerate(file, 1):
                match = LOG_PATTERN.search(line)
                
                if match:
                    # Extract the named groups into a clean dictionary
                    data = match.groupdict()
                    parsed_events.append(data)
                    
                    # Log a live alert to the console based on status
                    status_flag = "[ALERT]" if data['status'] == "Failed password" else "[INFO]"
                    print(f"{status_flag} Time: {data['timestamp']} | User: {data['user']} | IP: {data['ip']} | Status: {data['status']}")
                else:
                    # If a line doesn't match our SSH auth rules, skip it or log it
                    pass
                    
            print("="*50 + f"\n[*] Ingestion complete. Successfully parsed {len(parsed_events)} authentication events.")
            
            # Return the collected data for the next step (Anomaly Detection)
            return parsed_events
                
    except FileNotFoundError:
        print(f"[-] Error: The file '{file_path}' does not exist.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="SOC Telemetry Parser Labs - Parse and analyze authentication logs."
    )
    parser.add_argument(
        '-f', '--file', 
        required=True, 
        help="Path to the target log file"
    )
    
    args = parser.parse_args()
    parse_log_file(args.file)

if __name__ == "__main__":
    main()