import argparse
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Packet received from {src_ip} to {dst_ip} with protocol {protocol}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = packet[TCP].payload

            print(f"TCP Packet: Source Port {src_port}, Destination Port {dst_port}")
            if payload:
                print(f"Payload: {payload}")
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            print(f"UDP Packet: Source Port {src_port}, Destination Port {dst_port}")

def main(interface, packet_count, filter):
    print(f"Starting packet capture on interface {interface} with filter {filter}")
    sniff(iface=interface, prn=packet_callback, store=0, count=packet_count, filter=filter)
    print("Packet capture complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter for packet capture")
    args = parser.parse_args()

    main(args.interface, args.count, args.filter)
