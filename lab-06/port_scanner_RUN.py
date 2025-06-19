import sys
import socket
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.port_scanner_ui import Ui_MainWindow
from scapy.all import IP, TCP, sr1, send

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]

class PortScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.scanButton.clicked.connect(self.start_scan)

    def start_scan(self):
        target = self.ui.targetInput.text().strip()
        if not target:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng nhập tên miền hoặc IP.")
            return

        self.ui.resultBox.clear()
        self.ui.resultBox.appendPlainText(f"🔍 Đang quét {target}...\n")

        open_ports = self.scan_common_ports(target)

        if open_ports:
            self.ui.resultBox.appendPlainText("✅ Cổng mở:")
            for port in open_ports:
                self.ui.resultBox.appendPlainText(f" - Port {port}")
        else:
            self.ui.resultBox.appendPlainText("❌ Không tìm thấy cổng phổ biến nào mở.")

    def scan_common_ports(self, target_domain, timeout=2):
        open_ports = []
        try:
            target_ip = socket.gethostbyname(target_domain)
        except socket.gaierror:
            self.ui.resultBox.appendPlainText("❌ Không thể phân giải tên miền.")
            return []

        for port in COMMON_PORTS:
            response = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"),
                           timeout=timeout, verbose=0)

            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                open_ports.append(port)
                send(IP(dst=target_ip)/TCP(dport=port, flags="R"), verbose=0)

        return open_ports

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PortScanner()
    window.show()
    sys.exit(app.exec_())
