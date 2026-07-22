# main.py
import tkinter as tk
from gui_interface import SecurityAppGUI
from file_handler import save_hosts_to_file, load_hosts_from_file
from analytics import show_analytics_dashboard

class NetworkHost:
    """a single network device under security analysis."""
    # high-risk ports 
    DANGEROUS_PORTS: dict = {
        #Unencrypted Legacy Protocols
        21: "FTP",
        23: "Telnet",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        #remote management & file sharing exposures
        22: "SSH",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5900: "VNC",
        # databse infrastructure exposures
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        # alternative web services & proxies
        8080: "HTTP-Alt",
        8843: "HTTPS-Alt",
    }

    def __init__(self, ip_address: str, operating_system: str):
        # instance variables
        self.ip_address = ip_address
        self.operating_system: str = operating_system
        self.open_ports: list = [] # core container stores open ports
        self.risk_level: str = "Low"
        self.dangerous_ports_found: list = [] # feature  tracker

    def add_port(self, port_number: int) -> None:
        """ Host  a unique port to the profile if not already present."""
        if port_number not in self.open_ports:
            self.open_ports.append(port_number)
            if port_number in NetworkHost.DANGEROUS_PORTS:
                vuln_desc = f"Port {port_number}: {NetworkHost.DANGEROUS_PORTS[port_number]} "
                self.dangerous_ports_found.append(vuln_desc)
            self.calculate_risk()

    def calculate_risk(self) -> None:
        """Ecaluates security thereat levels dynamically"""
        total_ports = len(self.open_ports)
        has_critical_vuln = len(self.dangerous_ports_found) > 0

        if total_ports == 0:
            self.risk_level = "Low"
        elif total_ports <= 2 and not has_critical_vuln:
            self.risk_level = "Medium"
        else:
            self.risk_level = "High"

    def to_dictionary(self) -> dict:
        """returns a dictionary representation of the host profile."""
        return {
            "ip_address": self.ip_address,
            "operating_system": self.operating_system,
            "open_ports": self.open_ports,
            "risk_level": self.risk_level,
            "dangerous_ports_found": self.dangerous_ports_found
        }


def main():
    """Application entry point connecting data persistence, GUI, and analytics."""
    active_inventory = load_hosts_from_file()

    root = tk.Tk()
    app = SecurityAppGUI(
        root=root,
        hosts_list=active_inventory,
        save_callback=save_hosts_to_file,
        analytics_callback=show_analytics_dashboard
    )
    root.mainloop()

if __name__ == "__main__":
    main()