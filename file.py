import scapy.all as scapy
import argparse
import socket
import ipaddress # Added for better IP/subnet handling

def scan_ip(ip):
    # Suppress Scapy warnings for cleaner output
    scapy.conf.verb = 0 
    
    # Validate the target input to ensure it's a valid IP or subnet
    try:
        network = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        print(f"[-] Error: Invalid target IP or subnet '{ip}'. Please provide a valid format (e.g., 192.168.1.1 or 192.168.1.0/24).")
        return []

    print(f"[*] Starting ARP scan on {ip}...")
    arp_req = scapy.ARP(pdst=str(network)) 
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    
    # srp returns a tuple of (answered, unanswered). We only care about answered.
    # Adjust timeout if network is slow or for larger subnets.
    try:
        answered_list = scapy.srp(arp_req_broadcast, timeout=2, verbose=False)[0]
    except Exception as e:
        print(f"[-] Error during ARP scan: {e}")
        print("    Hint: On Linux/macOS, you might need root privileges (sudo) for ARP scanning.")
        return []

    clients = []
    for element in answered_list:
        # element[0] is the sent packet, element[1] is the received packet
        client = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients.append(client)
    
    print(f"[+] ARP scan completed. Found {len(clients)} active devices.")
    return clients

def scan_ports(ip, ports):
    # This is a TCP Connect scan as it completes the full TCP handshake.
    print(f"\n[*] Scanning {ip} for open ports: {ports}")
    open_ports_found = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            sock.settimeout(1) 
            result = sock.connect_ex((ip, port)) # connect_ex returns 0 on success, errno on failure
            if result == 0:
                print(f"[+] Port {port} is open on {ip}")
                open_ports_found.append(port)
            sock.close() # Always close the socket
        except socket.gaierror:
            print(f"[-] Hostname '{ip}' could not be resolved.")
            break # No point continuing if host isn't resolvable
        except socket.error as e:
            # Catch specific socket errors for better feedback
            print(f"[-] Socket error scanning {ip}:{port} - {e}")
        except Exception as e:
            # Catch any other unexpected errors
            print(f"[-] Error scanning {ip}:{port} - {e}")
    
    if not open_ports_found:
        print(f"[-] No open ports found on {ip} in the specified range.")
    return open_ports_found # Return list of open ports for further processing/storage

def get_arguments():
    parser = argparse.ArgumentParser(description="Simple Network Scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP address, hostname, or subnet (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", dest="ports", help="Comma-separated ports to scan (e.g., 22,80,443 or 1-1024 for range)", default="")
    
    args = parser.parse_args()
    
    if not args.target:
        # If no target, print help and exit
        parser.error("[-] Please specify a target IP/subnet. Use --help for more information.")
    
    # Handle port ranges for -p option
    if args.ports:
        parsed_ports = set()
        for part in args.ports.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    parsed_ports.update(range(start, end + 1))
                except ValueError:
                    parser.error(f"[-] Invalid port range: {part}. Use format like '1-1024'.")
            elif part.isdigit():
                parsed_ports.add(int(part))
            else:
                parser.error(f"[-] Invalid port format: {part}. Use comma-separated numbers or ranges.")
        args.ports = sorted(list(parsed_ports))
    else:
        # Default common ports if -p is not provided and port scan is implied
        # you'd define a list of common ports to use here.
        args.ports = [] 

    return args

def main():
    args = get_arguments()
    
    # Perform ARP scan for host discovery
    discovered_clients = scan_ip(args.target)
    
    if not discovered_clients:
        print("[-] No active devices found on the target subnet via ARP scan.")
        return

    print("\n[+] Discovered devices:")
    for client in discovered_clients:
        print(f"IP: {client['ip']}\tMAC: {client['mac']}")
        
        # If ports are specified, perform port scan for each discovered client
        if args.ports:
            scan_ports(client['ip'], args.ports)
        else:
            print(f"    No ports specified to scan for {client['ip']}.")

if __name__ == "__main__":
    main()
