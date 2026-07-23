# file_handler.py
import json

DATA_FILE = 'network_inventory.json'

def save_hosts_to_file(host_list: list) -> None:
    # save all hosts to json file
    try:
        serializable_data = [host.to_dictionary() for host in host_list]
        with open(DATA_FILE, 'w') as f:
            json.dump(serializable_data, f, indent=4)
        print("[Storage] Inventory successfully saved to database file.")
    except IOError as e:
        print(f"[Error] Failed to write data to file: {e}")
    except Exception as e:
        print(f"[Unexpected Error] Could not save data: {e}")

def load_hosts_from_file(network_host_cls) -> list:
    # load saved hosts back into memory
    loaded_hosts = []
    try:
        with open(DATA_FILE, "r") as f:
            raw_data = json.load(f)
            for item in raw_data:
                # recreate object using passed class to avoid import issue
                host = network_host_cls(item["ip_address"], item.get("operating_system", "Unknown"))
                host.open_ports = item.get("open_ports", [])
                host.dangerous_ports_found = item.get("dangerous_ports_found", [])
                host.risk_level = item.get("risk_level", "Low")
                loaded_hosts.append(host)

        print("[Storage] Persistent records loaded successfully.")
    except FileNotFoundError:
        print("[Storage] No existing database file found. Starting fresh inventory.")
    except json.JSONDecodeError:
        print("[Warning] Database file is corrupted or improperly formatted. Starting fresh inventory.")
    except Exception as e:
        print(f"[Unexpected Error] Failed to load database: {e}")
        
    return loaded_hosts