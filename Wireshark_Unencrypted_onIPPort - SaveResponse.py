import pyshark

def is_unencrypted(packet):
    # Check for common unencrypted protocols
    if 'HTTP' in packet:
        return True
    if 'FTP' in packet:
        return True
    if 'FTP-DATA' in packet:
        return True
    if 'TELNET' in packet:
        return True
    if 'SMTP' in packet:
        return True
    if 'POP' in packet:
        return True
    if 'IMAP' in packet:
        return True
    if 'NNTP' in packet:
        return True
    if 'SNMP' in packet:
        return True
    if 'RLOGIN' in packet:
        return True
    if 'RSH' in packet:
        return True
    if 'LDAP' in packet:
        return True
    if 'TFTP' in packet:
        return True
    if 'ICMP' in packet:
        return True  # Although ICMP is not typically encrypted, it's included for completeness
    
    # Check if HTTPS data is actually transferred in cleartext
    if 'TLS' in packet and hasattr(packet, 'tls'):
        # Inspect TLS payload for cleartext data (e.g., HTTP headers in cleartext)
        try:
            tls_layers = packet.tls
            for layer in tls_layers:
                if hasattr(layer, 'app_data'):
                    app_data = bytes(layer.app_data).decode(errors='ignore')
                    if 'HTTP' in app_data or any(keyword in app_data for keyword in ['user', 'password', 'pass', 'username']):
                        return True
        except Exception as e:
            pass

    return False

def analyze_pcap(pcap_file, ip_ports, output_file):
    try:
        # Open the pcap file
        cap = pyshark.FileCapture(pcap_file)

        print(f"Analyzing communication to IPs and ports: {ip_ports} in {pcap_file}...\n")

        found_unencrypted = False
        with open(output_file, 'w') as f:
            for packet in cap:
                # Check if the packet matches any of the specified IP and port combinations
                if 'IP' in packet:
                    dest_ip = packet.ip.dst
                    if 'TCP' in packet:
                        dest_port = packet.tcp.dstport
                    elif 'UDP' in packet:
                        dest_port = packet.udp.dstport
                    else:
                        continue

                    if (dest_ip, dest_port) in ip_ports:
                        if is_unencrypted(packet):
                            f.write(f"Unencrypted communication found: {dest_ip}:{dest_port} in packet {packet.number}\n")
                            f.write(f"{packet}\n\n")
                            found_unencrypted = True

            if not found_unencrypted:
                f.write("No unencrypted communication found for the specified IPs and ports.\n")

        print(f"Analysis complete. Results saved to {output_file}.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # User inputs
    pcap_file = input("Enter the path to the .pcapng file: ")
    ip_ports_input = input("Enter the destination IPs and ports in the format 'IP:port', separated by commas: ")

    # Process the IPs and ports input
    ip_ports = [tuple(ip_port.split(':')) for ip_port in ip_ports_input.split(',')]
    ip_ports = [(ip, port) for ip, port in ip_ports]

    # Analyze the pcap file
    analyze_pcap(pcap_file, ip_ports, 'unencrypted_communication.txt')
