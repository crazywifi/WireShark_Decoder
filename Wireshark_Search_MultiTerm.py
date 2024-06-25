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
    search_input = input("Enter the string(s) to search for, separated by commas: ")
    
    # Split the input string into a list of terms
    search_terms = [term.strip() for term in search_input.split(',')]

    # Search in the pcap file
    search_in_pcap(pcap_file, search_terms)
