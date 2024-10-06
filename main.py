import nmap
import socket
import sys
import os
from art import art

# Create an instance of the nmap scanner
scanner = nmap.PortScanner()

# Check if the script is running as root
def check_root():
    if os.geteuid() != 0:
        print("Error: This script requires root privileges for certain scans.")
        print("Please rerun the script using 'sudo'.")
        sys.exit(1)

# Function to display the results in a readable format
def display_results(scan_data, target_ip):
    results = f"\nScan Results for: {target_ip}\n"
    
    if 'tcp' in scan_data['scan'][target_ip]:
        results += "\n[Open TCP Ports]\n"
        for port, details in scan_data['scan'][target_ip]['tcp'].items():
            results += f"Port: {port} | State: {details['state']} | Service: {details['name']}\n"
    
    if 'hostnames' in scan_data['scan'][target_ip]:
        if scan_data['scan'][target_ip]['hostnames']:
            results += "\n[Hostnames]\n"
            for hostname in scan_data['scan'][target_ip]['hostnames']:
                results += f"Hostname: {hostname['name']} | Type: {hostname['type']}\n"
    
    if 'addresses' in scan_data['scan'][target_ip]:
        results += "\n[IP Addresses]\n"
        for addr_type, addr in scan_data['scan'][target_ip]['addresses'].items():
            results += f"{addr_type.capitalize()}: {addr}\n"
    
    if 'osclass' in scan_data['scan'][target_ip]:
        results += "\n[Operating System Information]\n"
        for osclass in scan_data['scan'][target_ip]['osclass']:
            results += f"OS: {osclass['osfamily']} | Accuracy: {osclass['accuracy']}%\n"

    return results

# Function to prompt the user to save scan results to a text file
def save_results_to_file(scan_results):
    save_option = input("\nWould you like to save the results to a text file? (y/n): ").strip().lower()
    
    if save_option == 'y':
        file_name = input("Enter the name of the text file (without extension): ").strip() + ".txt"
        try:
            with open(file_name, 'w') as file:
                file.write(scan_results)
            print(f"Results saved to {file_name}")
        except Exception as e:
            print(f"Error saving file: {e}")
    else:
        print("Results not saved.")

# Function to perform a scan based on user selection
def perform_scan(target_ip):
    while True:
        print("\nScan Options:")
        print("1. Quick Scan (Top 100 Ports)")
        print("2. Comprehensive Scan (SYN, Service Detection, OS Detection)")
        print("3. Ping Scan (Host Discovery)")
        print("4. Vulnerability Scan")
        print("5. OS Detection")
        print("6. Aggressive Recon (OS, Service Detection, Traceroute)")
        print("7. Traceroute")
        print("8. Custom Port Range Scan")
        print("9. DNS Enumeration")
        print("10. Firewall Evasion Techniques")
        print("11. Exit")
        scan_type = input("Select a scan type (1-11): ").strip()

        if scan_type == '11':
            print("Exiting RapidRecon.")
            sys.exit(0)

        try:
            if scan_type == '1':
                print(f"\nStarting Quick Scan on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments='--top-ports 100')
            elif scan_type == '2':
                print(f"\nStarting Comprehensive Scan on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments='-sS -sV -O')
            elif scan_type == '3':
                print(f"\nStarting Ping Scan on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments='-sn')
            elif scan_type == '4':
                print(f"\nStarting Vulnerability Scan on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments='--script vuln')
            elif scan_type == '5':
                print(f"\nStarting OS Detection on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments='-O')
            elif scan_type == '6':
                print(f"\nStarting Aggressive Scan on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments='-A')
            elif scan_type == '7':
                print(f"\nStarting Traceroute on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments='--traceroute')
            elif scan_type == '8':
                port_range = input("Enter the port range to scan (e.g., 80-443): ").strip()
                print(f"\nStarting Custom Port Range Scan on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments=f'-p {port_range}')
            elif scan_type == '9':
                print(f"\nStarting DNS Enumeration on {target_ip}...\n")
                scan_data = scanner.scan(target_ip, arguments='--script dns-brute')
            elif scan_type == '10':
                print("Select a firewall evasion technique:")
                print("1. Fragmentation (-f)")
                print("2. Bad Checksum (--badsum)")
                print("3. Randomize Hosts (--randomize-hosts)")
                evasion_choice = input("Choose 1, 2, or 3: ").strip()
                if evasion_choice == '1':
                    print(f"\nStarting Firewall Evasion (Fragmentation) on {target_ip}...\n")
                    scan_data = scanner.scan(target_ip, arguments='-f')
                elif evasion_choice == '2':
                    print(f"\nStarting Firewall Evasion (Bad Checksum) on {target_ip}...\n")
                    scan_data = scanner.scan(target_ip, arguments='--badsum')
                elif evasion_choice == '3':
                    print(f"\nStarting Firewall Evasion (Randomize Hosts) on {target_ip}...\n")
                    scan_data = scanner.scan(target_ip, arguments='--randomize-hosts')
                else:
                    print("Invalid choice! Returning to main menu.")
                    continue
            else:
                print("Invalid option selected! Please choose between 1 and 11.")
                continue

            # Check if the target is up
            if scan_data['scan'][target_ip]['status']['state'] == 'up':
                scan_results = display_results(scan_data, target_ip)
                print(scan_results)

                # Prompt to save the results to a file
                save_results_to_file(scan_results)
            else:
                print(f"{target_ip} appears to be down or unreachable.")

        except nmap.PortScannerError as e:
            print(f"Nmap Error: {e}")
        except KeyError:
            print("Scan failed or no valid data returned. Please verify the target IP.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

# Function to start the scan loop
def start_scan():
    art()
    print("Welcome to RapidRecon!")
    target = input("Please enter a domain name or IP address: ").strip()

    # Resolve domain to IP if needed
    try:
        target_ip = socket.gethostbyname(target)
        print(f"\nResolved {target} to IP: {target_ip}")
    except socket.gaierror:
        print("Error: Unable to resolve domain name. Please check the input.")
        sys.exit(1)

    # Loop to perform multiple scans or exit
    perform_scan(target_ip)

# Entry point of the script
if __name__ == "__main__":
    check_root()  # Ensure the user is running as root
    try:
        start_scan()
    except KeyboardInterrupt:
        print("\nScan interrupted. Exiting.")
        sys.exit(0)