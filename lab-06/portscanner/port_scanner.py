import socket
from scapy.all import *

# Danh sách các cổng phổ biến
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]

def scan_common_ports(target_domain, timeout=2):
    open_ports = []
    try:
        target_ip = socket.gethostbyname(target_domain)
    except socket.gaierror:
        print("Không thể phân giải tên miền.")
        return []

    for port in COMMON_PORTS:
        # Gửi gói TCP với cờ SYN (S)
        response = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"),
                       timeout=timeout, verbose=0)

        # Nếu có phản hồi và cờ là SYN-ACK (0x12), nghĩa là cổng mở
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            open_ports.append(port)

            # Gửi gói RST để đóng kết nối (lịch sự)
            send(IP(dst=target_ip)/TCP(dport=port, flags="R"), verbose=0)

    return open_ports

def main():
    target_domain = input("Enter the target domain or IP: ")
    open_ports = scan_common_ports(target_domain)

    if open_ports:
        print("✅ Open common ports:")
        for port in open_ports:
            print(f" - Port {port}")
    else:
        print("❌ No open common ports found.")

if __name__ == "__main__":
    main()
