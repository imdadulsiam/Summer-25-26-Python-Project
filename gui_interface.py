# gui_interface.py
from logging import root
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Self
from main import NetworkHost 

class SecurityAppGUI:
    """Graphical User Interface for the Network Security Application."""

    def __init__(self, root, host_list, save_callback, analytics_callback):
        self.root = root
        self.host_list = host_list
        self.save_callback = save_callback
        self.analytics_callback = analytics_callback
        self.root.title("Cybersecurity Vulnerability Auditor")
        self.root.geometry("750x550")
        self.root.resizable(False, False)

        # Title Banner 
        title_lable = tk.Label(
            root,
            text="Cybersecurity Vulnerability Auditor",
            font=("Helvetica", 16, "bold"),
            bg="#1f2937",
            fg="white",
            py=10
        )
        title_lable.pack(fill=tk.X)

        # Input Frame
        input_frame = tk.LabelFrame(root, text="Add New Target Asset", font=("Helvetica", 10, "bold"), padx=15, pady=10)
        input_frame.pack(fill=tk.X, padx=15, pady=10)

        # IP Entry
        tk.Label(input_frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_entry = tk.Entry(input_frame, width=18)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        # OS Entry
        tk.Label(input_frame, text="OS (Windows/Linux/Mac):").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.os_entry = tk.Entry(input_frame, width=18)
        self.os_entry.grid(row=0, column=3, padx=5, pady=5)

        # Ports Entry
        tk.Label(input_frame, text="Open Ports (comma-separated):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ports_entry = tk.Entry(input_frame, width=40)
        self.ports_entry.grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Add Button
        add_btn = tk.Button(input_frame, text="Register Asset", command=self.add_host, bg="#10b981", fg="white", font=("Helvetica", 10, "bold"))
        add_btn.grid(row=2, column=3, sticky=tk.E, pady=5)
     
        # Table Display Frame
        table_frame = tk.LabelFrame(root, text=" Registered Active Assets ", font=("Helvetica", 10, "bold"), padx=10, pady=10)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)
     
        columns = ("IP Address", "OS", "Risk Level", "Open Ports", "Vulnerabilities")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, anchor=tk.CENTER)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Action Buttons 
        btn_frame = tk.Frame(root, pady=10)
        btn_frame.pack()
     
        analytics_btn = tk.Button(btn_frame, text="View Analytics Dashboard", command=self.show_analytics, bg="#3b82f6", fg="white", font=("Helvetica", 10, "bold"), padx=10)
        analytics_btn.pack(side=tk.LEFT, padx=10)
        refresh_btn = tk.Button(btn_frame, text="Refresh List", command=self.refresh_tree, bg="#f59e0b", fg="white", font=("Helvetica", 10, "bold"), padx=10)
        refresh_btn.pack(side=tk.LEFT, padx=10)

        self.refresh_tree()
     
    def validate_ip(self, ip: str) -> bool:
        """Validate the IP address format."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
         
    def add_host(self):
        """Add a new host to the list after validation."""
        ip = self.ip_entry.get().strip()
        os = self.os_entry.get().strip()
        ports = self.ports_entry.get().strip()

        # Validation
        if not self.validate_ip(ip):
            messagebox.showerror("Invalid Input", "Please enter a valid IP address.")
            return
        if not os:
            messagebox.showerror("Invalid Input", "Please enter the operating system.")
            return
         
        new_host = NetworkHost(ip, os)

        if ports:
            ports_items = ports.split(",")
            for p in ports_items:
                try:
                    port_num = int(p.strip())
                    if 1 <= port_num <= 65535:
                        new_host.add_port(port_num)
                    else:
                        messagebox.showerror("Invalid Input", f"Port {port_num} out of range (1-65535). Skipped.")
                except ValueError:
                    messagebox.showerror("Invalid Input", f"Invalid port value '{p}'. Skipped.")
                    
        self.host_list.append(new_host)
        self.save_callback(self.host_list)
        self.refresh_tree()

        # Clear Entries
        self.ip_entry.delete(0, tk.END)
        self.os_entry.delete(0, tk.END)
        self.ports_entry.delete(0, tk.END)
        messagebox.showinfo("Success", f"Target asset {ip} registered successfully.")

    def refresh_tree(self):
        """Refreshes tree contents with current memory state"""
        for row in self.tree.get_children():
            self.tree.delete(row)

        for host in self.host_list:
            ports_str = ", ".join(map(str, host.open_ports)) if host.open_ports else "None"
            vulns_str = f"{len(host.dangerous_ports_found)} Detected" if host.dangerous_ports_found else "Clean"
            # Host attribute compatibility fallback (host.os or host.operating_system)
            host_os = getattr(host, 'os', getattr(host, 'operating_system', 'Unknown'))
            self.tree.insert("", tk.END, values=(host.ip_address, host_os, host.risk_level, ports_str, vulns_str))

    def show_analytics(self):
        """Trigger the analytics dashboard callback."""
        self.analytics_callback(self.host_list)