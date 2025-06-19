import sys, subprocess, requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.QtCore import pyqtSignal
from ui.packet_sniffer_ui import Ui_MainWindow      # file sinh ra ở bước 2
from scapy.all import AsyncSniffer, Raw, TCP     # dùng AsyncSniffer cho gọn

class PacketSniffer(QMainWindow):
    packetSignal = pyqtSignal(str)               # signal để cập nhật GUI an toàn

    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Kết nối nút
        self.ui.refreshButton.clicked.connect(self.load_interfaces)
        self.ui.startButton.clicked.connect(self.start_sniff)
        self.ui.stopButton.clicked.connect(self.stop_sniff)

        self.ui.stopButton.setEnabled(False)     # dừng -> disabled lúc đầu
        self.packetSignal.connect(self.append_output)

        self.sniffer = None
        self.load_interfaces()

    # ---------- Lấy danh sách NIC ----------
    def load_interfaces(self):
        self.ui.ifaceCombo.clear()
        for iface in self.get_interfaces():
            self.ui.ifaceCombo.addItem(iface)

    @staticmethod
    def get_interfaces():
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, check=False
        )
        lines = result.stdout.splitlines()[3:]   # bỏ header 3 dòng
        ifaces = []
        for ln in lines:
            parts = ln.split()
            if len(parts) >= 4:
                ifaces.append(parts[3])
        return ifaces

    # ---------- Bắt gói ----------
    def start_sniff(self):
        iface = self.ui.ifaceCombo.currentText()
        if not iface:
            QMessageBox.warning(self, "Lỗi", "Chưa chọn giao diện mạng")
            return

        self.ui.startButton.setEnabled(False)
        self.ui.stopButton.setEnabled(True)
        self.ui.outputEdit.appendPlainText(f"--- Bắt gói trên {iface} ---")

        # Dùng AsyncSniffer để không khoá GUI
        self.sniffer = AsyncSniffer(
            iface=iface,
            filter="tcp",
            prn=self.handle_packet,
            store=False
        )
        self.sniffer.start()

    def handle_packet(self, pkt):
        if pkt.haslayer(Raw):                    # tuỳ bạn lọc sâu hơn
            summary = pkt.summary()
            self.packetSignal.emit(summary)      # gửi về slot GUI

    def append_output(self, text):
        self.ui.outputEdit.appendPlainText(text)

    # ---------- Dừng ----------
    def stop_sniff(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            self.ui.outputEdit.appendPlainText("--- Dừng ---")
        self.ui.startButton.setEnabled(True)
        self.ui.stopButton.setEnabled(False)

    # ---------- Đóng cửa sổ ----------
    def closeEvent(self, event):
        try:
            self.stop_sniff()
        finally:
            event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = PacketSniffer()
    win.show()
    sys.exit(app.exec_())
