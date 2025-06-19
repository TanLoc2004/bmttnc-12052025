from scapy.all import *

def modify_icmp_packet(packet):
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        icmp_packet = packet[ICMP]

        print("Original ICMP Packet:")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Type: {icmp_packet.type}")
        print(f"Code: {icmp_packet.code}")
        print(f"ID: {icmp_packet.id}")
        print(f"Sequence: {icmp_packet.seq}")
        print("=" * 30)

        # Tạo payload mới
        new_load = b"This is a modified ICMP packet."

        # Tạo gói tin ICMP mới đảo chiều
        new_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                     ICMP(type=icmp_packet.type, code=icmp_packet.code,
                          id=icmp_packet.id, seq=icmp_packet.seq) / \
                     new_load

        print("\nModified ICMP Packet:")
        print(f"Source IP: {new_packet[IP].src}")
        print(f"Destination IP: {new_packet[IP].dst}")
        print(f"Type: {new_packet[ICMP].type}")
        print(f"Code: {new_packet[ICMP].code}")
        print(f"ID: {new_packet[ICMP].id}")
        print(f"Sequence: {new_packet[ICMP].seq}")
        print(f"Load: {new_load}")
        print("=" * 30)

        # Gửi lại gói ICMP mới
        send(new_packet)

def main():
    print("🔁 Listening for ICMP packets (Press Ctrl+C to stop)...")
    sniff(prn=modify_icmp_packet, filter="icmp", store=0)

if __name__ == "__main__":
    main()
