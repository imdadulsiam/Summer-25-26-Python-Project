# main.py
import json
import numpy as np

# =====================================================================
# MEMBER 1 WORK: CORE DATA MODEL
# =====================================================================
class NetworkHost:
    """Represents a single network device under security analysis."""
    
    def __init__(self, ip_address: str, operating_system: str):
        self.ip_address: str = ip_address
        self.operating_system: str = operating_system
        self.open_ports: list = []  # Core container list to store open port numbers
        self.risk_level: str = "Low"

    def add_port(self, port_number: int) -> None:
        """Appends a scanned unique port to the host profile if not present."""
        if port_number not in self.open_ports:
            self.open_ports.append(port_number)
            self.calculate_risk()

    def calculate_risk(self) -> None:
        """Evaluates target security threat levels by counting open ports."""
        total_ports = len(self.open_ports)
        if total_ports == 0:
            self.risk_level = "Low"
        elif 1 <= total_ports <= 2:
            self.risk_level = "Medium"
        else:
            self.risk_level = "High"

    def to_dictionary(self) -> dict:
        """Maps asset instance attributes directly into standard dictionary format."""
        return {
            "ip_address": self.ip_address,
            "operating_system": self.operating_system,
            "open_ports": self.open_ports,
            "risk_level": self.risk_level
        }


# =====================================================================
# MEMBER 3 WORK: FILE STORAGE & PERMANENT RETRIEVAL
# =====================================================================
DATA_FILE = "network_inventory.json"

def save_hosts_to_file(hosts_list: list) -> None:
    """Converts host objects into dictionaries and saves them permanently."""
    try:
        serializable_data = [host.to_dictionary() for host in hosts_list]
        with open(DATA_FILE, "w") as f:
            json.dump(serializable_data, f, indent=4)
        print("[System] Data successfully saved to file.")
    except Exception as e:
        print(f"[Error] Failed to save data: {e}")

def load_hosts_from_file() -> list:
    """Loads historical host profiles from storage with safety checks."""
    loaded_hosts = []
    try:
        with open(DATA_FILE, "r") as f:
            raw_data = json.load(f)
            for item in raw_data:
                host = NetworkHost(item["ip_address"], item["operating_system"])
                host.open_ports = item["open_ports"]
                host.risk_level = item["risk_level"]
                loaded_hosts.append(host)
        print("[System] Persistent database loaded successfully.")
    except FileNotFoundError:
        print("[System] No previous scan history found. Starting fresh database.")
    except json.JSONDecodeError:
        print("[Warning] Database file corrupted. Initializing new storage.")
    return loaded_hosts


# =====================================================================
# MEMBER 2 WORK: SYSTEM INPUT, VALIDATION & MANAGEMENT
# =====================================================================
def validate_ip(ip: str) -> bool:
    """Verifies basic structure formatting of an IP address string."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def add_new_host_ui(hosts_list: list) -> None:
    """Handles inputs, rejects duplicate records, and adds target profiles."""
    print("\n--- Add New Target Asset ---")
    ip = input("Enter Target IP Address (e.g., 192.168.1.1): ").strip()
    
    if not validate_ip(ip):
        print("[Input Error] Invalid IP address format syntax configuration.")
        return

    # Using set membership check style to prevent duplicate profile inputs
    existing_ips = {host.ip_address for host in hosts_list}
    if ip in existing_ips:
        print("[Input Error] Record asset profile already exists for this IP address.")
        return

    os_choice = input("Enter Operating System (Windows/Linux/Mac): ").strip()
    if not os_choice:
        print("[Input Error] Operating system designation label cannot be empty.")
        return

    new_host = NetworkHost(ip, os_choice)
    
    # Optional setup for adding initial open ports safely via validation check loops
    while True:
        port_input = input("Enter an open port to register (or type 'done' to stop): ").strip()
        if port_input.lower() == 'done':
            break
        try:
            port_num = int(port_input)
            if 1 <= port_num <= 65535:
                new_host.add_port(port_num)
                print(f"[Port Added] Registered port {port_num}")
            else:
                print("[Input Error] Ports must fall inside standard network ranges 1-65535.")
        except ValueError:
            print("[Input Error] Integer values are explicitly required for port entry fields.")

    hosts_list.append(new_host)
    save_hosts_to_file(hosts_list)
    print(f"[Success] Target asset {ip} profile generated structurally.")

def view_all_hosts(hosts_list: list) -> None:
    """Displays structured profiles matching course console separation style."""
    if not hosts_list:
        print("\n[System] Inventory is empty. No assets scanned yet.")
        return
    print("\n" + "=" * 50)
    print(f"{'IP Address':<18} {'OS':<12} {'Risk':<10} {'Open Ports'}")
    print("=" * 50)
    for host in hosts_list:
        ports_str = ", ".join(map(str, host.open_ports)) if host.open_ports else "None"
        print(f"{host.ip_address:<18} {host.operating_system:<12} {host.risk_level:<10} {ports_str}")
    print("=" * 50)


# =====================================================================
# MEMBER 4 WORK: NUMPY ANALYTICS DASHBOARD
# =====================================================================
def display_security_analytics(hosts_list: list) -> None:
    """Utilizes NumPy processing engines to extract deep vector inventory analytics."""
    if not hosts_list:
        print("\n[Dashboard] Analytical calculation engine offline: Dataset is empty.")
        return

    print("\n" + "-" * 15 + " METRIC REPORT DASHBOARD " + "-" * 15)
    
    # 1. Map properties out to raw analytical arrays
    total_ports_array = np.array([len(host.open_ports) for host in hosts_list])
    risk_labels_list = [host.risk_level for host in hosts_list]

    # 2. Extract numeric summary indicators using NumPy calculation calls
    avg_open_ports = np.mean(total_ports_array)
    max_open_ports = np.max(total_ports_array)
    total_assets = len(hosts_list)

    # 3. Calculate categorization percentages via array masking assertions
    high_count = np.sum(np.array([1 for risk in risk_labels_list if risk == "High"]))
    med_count = np.sum(np.array([1 for risk in risk_labels_list if risk == "Medium"]))
    low_count = np.sum(np.array([1 for risk in risk_labels_list if risk == "Low"]))

    high_pct = (high_count / total_assets) * 100
    med_pct = (med_count / total_assets) * 100
    low_pct = (low_count / total_assets) * 100

    # Output computed metrics matching instruction parameters
    print(f"Total Network Assets Cataloged  : {total_assets}")
    print(f"Average Open Ports per Device   : {avg_open_ports:.2f}")
    print(f"Max Vulnerable Ports on 1 Asset : {max_open_ports}")
    print("-" * 45)
    print("Threat Breakdown Allocations:")
    print(f" -> High Severity Threat Risk   : {high_pct:.1f}% ({high_count} Hosts)")
    print(f" -> Medium Severity Threat Risk : {med_pct:.1f}% ({med_count} Hosts)")
    print(f" -> Low Severity Threat Risk    : {low_pct:.1f}% ({low_count} Hosts)")
    print("-" * 45)


# =====================================================================
# INTERFACE IMPLEMENTATION: APPLICATION CORE CONTROL INTERACTIVE LOOP
# =====================================================================
def main() -> None:
    """Controls administrative choice routines via interactive selection matrices."""
    # Instantly pull data files down into memory execution layers at boot
    active_inventory = load_hosts_from_file()

    while True:
        print("\n========================================")
        print("    CYBERSECURITY VULNERABILITY AUDITOR ")
        print("========================================")
        print("1. Add New Target Asset Evaluation Profile")
        print("2. View Registered Active Assets Status")
        print("3. Execute Analytical Security Dashboard Statistics")
        print("4. Terminate Core Execution Engine Loop")
        print("========================================")
        
        choice = input("Select System Operations Option (1-4): ").strip()
        
        if choice == "1":
            add_new_host_ui(active_inventory)
        elif choice == "2":
            view_all_hosts(active_inventory)
        elif choice == "3":
            display_security_analytics(active_inventory)
        elif choice == "4":
            print("\n[Shutdown] Closing vulnerability operational framework modules safely. Goodbye.")
            break
        else:
            print("[Selection Warning] Operation directive choice index not found out of bound limits.")

if __name__ == "__main__":
    main()