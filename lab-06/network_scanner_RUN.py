import sys
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QTableWidgetItem
from scapy.all import ARP, Ether, srp
from ui.network_scanner_ui import Ui_MainWindow  

class NetworkScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.scanButton.clicked.connect(self.scan_network)

    def scan_network(self):
        ip_range = self.ui.ipInput.text()
        if not ip_range:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập dải IP")
            return

        devices = self.local_network_scan(ip_range)
        self.display_results(devices)

    def local_network_scan(self, ip_range):
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'vendor': self.get_vendor_by_mac(received.hwsrc)
            })

        return devices

    def get_vendor_by_mac(self, mac):
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}")
            return response.text if response.status_code == 200 else "Unknown"
        except:
            return "Unknown"

    def display_results(self, devices):
        self.ui.resultTable.setRowCount(0)
        for i, device in enumerate(devices):
            self.ui.resultTable.insertRow(i)
            self.ui.resultTable.setItem(i, 0, QTableWidgetItem(device['ip']))
            self.ui.resultTable.setItem(i, 1, QTableWidgetItem(device['mac']))
            self.ui.resultTable.setItem(i, 2, QTableWidgetItem(device['vendor']))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkScanner()
    window.show()
    sys.exit(app.exec_())
