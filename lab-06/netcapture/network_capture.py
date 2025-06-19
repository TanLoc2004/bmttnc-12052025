import subprocess
from scapy.all import sniff, Raw

# Hàm lấy danh sách các giao diện mạng
def get_interfaces():
    result = subprocess.run(["netsh", "interface", "show", "interface"],
                            capture_output=True, text=True)
    output_lines = result.stdout.splitlines()[3:]  # Bỏ qua 3 dòng đầu tiêu đề
    interfaces = []
    for line in output_lines:
        parts = line.split()
        if len(parts) >= 4:
            interfaces.append(parts[3])  # Tên giao diện ở cột 4
    return interfaces

# Hàm xử lý gói tin
def packet_handler(packet):
    if packet.haslayer(Raw):
        print("Captured Packet:")
        print(packet.summary())
        print(packet.show())

def main():
    # Lấy danh sách các giao diện mạng
    interfaces = get_interfaces()

    # In danh sách giao diện cho người dùng lựa chọn
    print("Danh sách các giao diện mạng:")
    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}. {iface}")

    # Người dùng chọn giao diện
    try:
        choice = int(input("Chọn một giao diện mạng (nhập số): "))
        selected_iface = interfaces[choice - 1]
    except (ValueError, IndexError):
        print("Lựa chọn không hợp lệ.")
        return

    print(f"Bắt gói tin trên giao diện: {selected_iface} (nhấn Ctrl+C để dừng)")

    # Bắt gói tin TCP trên giao diện đã chọn
    sniff(iface=selected_iface, prn=packet_handler, filter="tcp", store=0)

if __name__ == "__main__":
    main()
