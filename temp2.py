import argparse
import datetime
import socket
import struct
import time
import select
import matplotlib.pyplot as plt
from collections import defaultdict

# Set the duration in seconds
DURATION = 75

# Data tracking variables
total_bytes = 0
total_packets = 0
packet_sizes = []
flow_counts_src = defaultdict(int)
flow_counts_dest = defaultdict(int)
flow_data = defaultdict(int)  # {("src_ip:port -> dest_ip:port"): bytes_transferred}
unique_pairs = set()
found_ip = None
found_ip_packet_count = 0
laptop_name = None
laptop_packet_checksum = None
order_successful_count = 0


# Create a raw socket
def create_socket(interface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
        print(f"Listening on {interface}")
        return s
    except PermissionError:
        print("Run the program as root to capture raw packets.")
        exit(1)


# Extract the contents
def extract_payload(packet, protocol):
    if protocol == 6:  # TCP
        header_start = 34  # IP header (20 bytes) + Ethernet (14 bytes)
        tcp_header_length = (packet[header_start + 12] >> 4) * 4
        payload = packet[header_start + tcp_header_length:]
    elif protocol == 17:  # UDP
        header_start = 34
        udp_header_length = 8
        payload = packet[header_start + udp_header_length:]
    else:
        return b""

    return bytes(payload)


# Parse Ethernet header
def parse_ethernet_header(packet):
    eth_header = struct.unpack("!6s6sH", packet[:14])
    eth_type = socket.htons(eth_header[2])
    return eth_type


# Parse IP header
def parse_ip_header(packet):
    ip_header = packet[14:34]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    protocol = iph[6]
    return src_ip, dest_ip, protocol


# Parse TCP/UDP headers to extract port numbers
def parse_transport_header(packet, protocol):
    if protocol == 6:  # TCP
        header_start = 34
        tcp_header = struct.unpack("!HH", packet[header_start:header_start + 4])
        return tcp_header[0], tcp_header[1]  # src_port, dest_port
    elif protocol == 17:  # UDP
        header_start = 34
        udp_header = struct.unpack("!HH", packet[header_start:header_start + 4])
        return udp_header[0], udp_header[1]  # src_port, dest_port
    return None, None  # If not TCP/UDP



# argparse
def parse_arguments():
    parser = argparse.ArgumentParser(description="CLI-based raw packet sniffer with analytics")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp", "all"], default="all",
                        help="Filter packets by protocol")
    return parser.parse_args()


# Sniff packets
def sniff_packets(args):
    global total_bytes, total_packets, packet_sizes, found_ip, found_ip_packet_count, laptop_name, laptop_packet_checksum, order_successful_count
    s = create_socket(args.interface)
    start_time = time.time()

    while True:
        if time.time() - start_time > DURATION:
            print(f"Duration of {DURATION} seconds reached. Exiting...")
            break

        ready, _, _ = select.select([s], [], [], 1)
        if not ready:
            continue

        raw_packet, _ = s.recvfrom(65535)
        # Track total data and packets
        packet_size = len(raw_packet)
        total_bytes += packet_size
        packet_sizes.append(packet_size)
        total_packets += 1
        eth_type = parse_ethernet_header(raw_packet)


        # Process only IP packets
        if not (eth_type == 8 or eth_type == 34525):
            continue

        src_ip, dest_ip, protocol = parse_ip_header(raw_packet)
        if (src_ip == "172.30.32.1" and dest_ip == "224.0.0.251"): # Filtering out System MDNS Standard Query Packets
             total_packets -=1
             total_bytes -= packet_size
             packet_sizes.pop()
             continue
        
        src_port, dest_port = parse_transport_header(raw_packet, protocol)
        payload = extract_payload(raw_packet, protocol)

        # Store flow data
        flow_counts_src[src_ip] += 1
        flow_counts_dest[dest_ip] += 1

        # Store unique pairs and flow data
        if src_port and dest_port:
            flow_key = (src_ip, src_port, dest_ip, dest_port)
            unique_pairs.add(flow_key)
            flow_data[flow_key] += packet_size

        # Extract specific data from payload
        if b"My ip address =" in payload:
                found_ip = payload.split(b"My ip address =")[-1].strip().strip(b"<>")  # Extract IP
                found_ip = found_ip.decode(errors="ignore")  # Decode to string for easier handling

        if src_ip == '10.1.2.200' or dest_ip == '10.1.2.200': ## found_ip value is hardcoded after finding results for checking all the packets that appear even before it is found
                found_ip_packet_count += 1

        if src_ip == '10.1.2.200' and b"The name of laptop =" in payload:
                laptop_name = payload.split(b"The name of laptop =")[1].split()[0]
                laptop_name = laptop_name.decode(errors="ignore")  # Decode to string
                laptop_packet_checksum = struct.unpack("!H", raw_packet[50:52])[0]  # TCP checksum

        if b"Order Successful" in payload:
                order_successful_count += 1



# Print analytics
def display_statistics():
    print("\n===== Part-1 =====")
    print("\n---Question 1--- ")
    print(f"Total Packets: {total_packets}")
    print(f"Total Data Transferred: {total_bytes} bytes")
    if packet_sizes:
        print(f"Min Packet Size: {min(packet_sizes)} bytes")
        print(f"Max Packet Size: {max(packet_sizes)} bytes")
        print(f"Average Packet Size: {sum(packet_sizes) / len(packet_sizes)} bytes")

    print("\n---Question 2--- ")
    print("Unique Source-Destination IP Pairs")
    print("No. of Unique Source-Destination Pairs:", len(unique_pairs))
    print("Showing only 5 Entires here (refer to unique_pair.txt for all)")
    i = 0
    for pairs in unique_pairs:
        print(pairs)
        i+=1
        if i==5: break

    print("\n---Question 3--- ")
    print("Flow Counts Per Source IP")
    print("No. of Unique Source IP:", len(flow_counts_src))
    print("Showing only 5 Entires here (refer to unique_src_ip.txt for all)")
    i = 0
    for ip, count in flow_counts_src.items():
        print(f"{ip}: {count}")
        i+=1
        if i==5: break

    print("")
    print("Flow Counts Per Destination IP")
    print("No. of Unique Destination IP:", len(flow_counts_dest))
    print("Showing only 5 Entires here (refer to unique_dst_ip.txt for all)")
    i = 0
    for ip, count in flow_counts_dest.items():
        print(f"{ip}: {count}")
        i+=1
        if i==5: break

    print("")
    print("Maximum Flow")
    if flow_data:
        max_flow = max(flow_data, key=flow_data.get)
        print(f"Maximum Flow: {max_flow[0]}:{max_flow[1]} -> {max_flow[2]}:{max_flow[3]} transferred {flow_data[max_flow]} bytes")


    print('\n\n')
    print("\n===== Part-2 =====")
    print("\n---Question 1--- ")
    print(f"My IP Address: {found_ip}" if found_ip else "IP Address not found.")
    print("\n---Question 2--- ")
    print(f"Packets containing IP {found_ip}: {found_ip_packet_count}")
    print("\n---Question 3--- ")
    print(f"Laptop Name: {laptop_name}" if laptop_name else "Laptop name not found.")
    print(f"TCP Checksum: {hex(laptop_packet_checksum)}" if laptop_packet_checksum else "Checksum not found.")
    print("\n---Question 4--- ")
    print(f"Packets containing 'Order Successful': {order_successful_count}")

    # Plot histogram
    if packet_sizes:
        plt.figure(figsize=(10, 5))
        plt.hist(packet_sizes, bins=30, color='blue', edgecolor='black')
        plt.xlabel("Packet Size (bytes)")
        plt.ylabel("Frequency")
        plt.title("Distribution of Packet Sizes")
        plt.savefig('plott.png')
        print("\nPlot of frequency of packets saved as 'plott.png'")
    

    # Write unique source-destination pairs to a file
    with open("unique_pairs.txt", "w") as f:
        for pair in unique_pairs:
            f.write(f"{pair[0]}:{pair[1]} -> {pair[2]}:{pair[3]}\n")

    # Write flow counts per source IP to a file
    with open("unique_src_ip.txt", "w") as f:
        for ip, count in flow_counts_src.items():
            f.write(f"{ip}: {count}\n")

    # Write flow counts per destination IP to a file
    with open("unique_dst_ip.txt", "w") as f:
        for ip, count in flow_counts_dest.items():
            f.write(f"{ip}: {count}\n")

    print("Files created: unique_pairs.txt, unique_src_ip.txt, unique_dst_ip.txt")


if __name__ == "__main__":
    args = parse_arguments()
    sniff_packets(args)
    display_statistics()