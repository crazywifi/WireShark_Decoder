import pyshark

def search_in_pcap(pcap_file, search_terms):
    try:
        # Open the pcap file
        cap = pyshark.FileCapture(pcap_file)

        print(f"Searching for {search_terms} in {pcap_file}...\n")

        found = False
        for packet in cap:
            # Convert packet to string and search for any of the provided terms
            packet_str = str(packet)
            for term in search_terms:
                if term in packet_str:
                    print(f"Found '{term}' in packet {packet.number}:")
                    print(packet)
                    print("\n")
                    found = True
                    break  # Exit the loop if any term is found in the packet

        if not found:
            print(f"None of the terms {search_terms} were found in {pcap_file}.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # User inputs
    pcap_file = input("Enter the path to the .pcapng file: ")
    
    # List of terms to search for
    search_terms = [
        "user", "username", "pass", "password", "USER_NAME", "PIN", "Secret", 
        "email", "address", "phone", "phone number", "customer", "database", 
        "session", "billing", "shipping", "cert", "encrypt", "signin", 
        "Onboarding", "SQL", "Private", "Private IP", "Secret", "pwd", "CERT"
    ]

    # Search in the pcap file
    search_in_pcap(pcap_file, search_terms)
