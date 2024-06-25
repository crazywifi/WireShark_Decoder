import pyshark

def search_in_pcap(pcap_file, search_string):
    try:
        # Open the pcap file
        cap = pyshark.FileCapture(pcap_file)

        print(f"Searching for '{search_string}' in {pcap_file}...\n")

        found = False
        for packet in cap:
            # Convert packet to string and search for the provided string
            if search_string in str(packet):
                print(f"Found in packet {packet.number}:")
                print(packet)
                print("\n")
                found = True

        if not found:
            print(f"String '{search_string}' not found in {pcap_file}.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # User inputs
    pcap_file = input("Enter the path to the .pcapng file: ")
    search_string = input("Enter the string to search for: ")

    # Search in the pcap file
    search_in_pcap(pcap_file, search_string)
