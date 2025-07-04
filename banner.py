import socket
import ipaddress
import sys

def grab_banner(ip, port, timeout=2):
    """
    Connects to a specific IP and port to grab the service banner.

    Args:
        ip (str): The target IP address.
        port (int): The target port.
        timeout (int): The connection timeout in seconds.

    Returns:
        str: The banner received from the service, or None if it fails.
    """
    try:
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        
        s.connect((ip, port))
        
       
        banner = s.recv(1024)
        
        
        s.close()
        
       
        return banner.decode('utf-8', errors='ignore').strip()
        
    except socket.timeout:
        
        return None
    except socket.error as e:

        return None
    except Exception as e:

        return None

def main():
    """
    Main function to drive the banner grabbing process for a subnet.
    """
    print("--- Python Subnet Banner Grabber ---")
    print("=" * 35)


    subnet_str = input("Enter the subnet to scan (e.g., 192.168.1.0/24): ")
    

    try:
        port_str = input("Enter the port to grab banners from (e.g., 80): ")
        port = int(port_str)
        if not (0 < port < 65536):
            print("Error: Port must be between 1 and 65535.")
            sys.exit(1)
    except ValueError:
        print("Error: Invalid port number.")
        sys.exit(1)


    try:
        
        network = ipaddress.ip_network(subnet_str, strict=False)
        print(f"\n[+] Scanning subnet: {network}")
        print(f"[+] Targeting port: {port}")
        print("-" * 35)
    except ValueError:
        print(f"Error: Invalid subnet format '{subnet_str}'. Please use CIDR notation.")
        sys.exit(1)

    found_count = 0
    
    for ip in network.hosts():
        ip_str = str(ip)
        print(f"[*] Checking host: {ip_str}...")
        
        
        banner = grab_banner(ip_str, port)
        
        if banner:
            found_count += 1
            print(f"\n[SUCCESS] Found Banner on {ip_str}:{port}")
            print(f"--> {banner}\n")
    
    print("-" * 35)
    print(f"Scan complete. Found {found_count} banner(s) on port {port}.")

if __name__ == "__main__":
    main()
