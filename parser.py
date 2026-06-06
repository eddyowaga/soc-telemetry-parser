import argparse
import sys

def parse_log_file(file_path):
    """
    Reads the log file line by line and prepares it for processing.
    """
    try:
        with open(file_path, 'r') as file:
            print(f"[*] Successfully opened {file_path}. Starting ingestion...")
            
            for line_num, line in enumerate(file, 1):
                # For now, we will just print the line to verify ingestion works
                # Stripping the newline character for cleaner console printing
                print(f"Line {line_num}: {line.strip()}")
                
    except FileNotFoundError:
        print(f"[-] Error: The file '{file_path}' does not exist.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        sys.exit(1)

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="SOC Telemetry Parser Labs - Parse and analyze authentication logs."
    )
    parser.add_argument(
        '-f', '--file', 
        required=True, 
        help="Path to the target log file (e.g., auth.log)"
    )
    
    args = parser.parse_args()
    parse_log_file(args.file)

if __name__ == "__main__":
    main()