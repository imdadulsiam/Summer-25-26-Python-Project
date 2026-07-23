# gui_interface.py
import tkinter as tk
from tkinter import ttk, messagebox

class SecurityAppGUI:
    # main gui window class
    def __init__(self, root, host_list, save_callback, analytics_callback, network_host_cls):
        self.root, self.host_list = root, host_list
        self.save_callback, self.analytics_callback = save_callback, analytics_callback
        self.NetworkHost = network_host_cls
        self.root.title("Security Auditor")
        self.root.geometry("700x480")

        # header
        tk.Label(root, text="Cybersecurity Vulnerability Auditor", font=("Helvetica", 14, "bold"), bg="#1f2937", fg="white", pady=8).pack(fill=tk.X)

        # input form section
        form = tk.LabelFrame(root, text="Add New Target Asset", font=("Helvetica", 10, "bold"), padx=10, pady=5)
        form.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(form, text="IP:").grid(row=0, column=0)
        self.ip_entry = tk.Entry(form, width=15)
        self.ip_entry.grid(row=0, column=1, padx=5)

        tk.Label(form, text="OS:").grid(row=0, column=2)
        self.os_entry = tk.Entry(form, width=15)
        self.os_entry.grid(row=0, column=3, padx=5)

        tk.Label(form, text="Ports:").grid(row=1, column=0, pady=5)
        self.ports_entry = tk.Entry(form, width=30)
        self.ports_entry.grid(row=1, column=1, columnspan=2, padx=5)

        tk.Button(form, text="Register Asset", command=self.add_host, bg="#10b981", fg="white", font=("Helvetica", 9, "bold")).grid(row=1, column=3, padx=5)

        # table view
        cols = ("IP Address", "OS", "Risk Level", "Open Ports", "Vulnerabilities")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", height=7)
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=110, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # buttons
        btn_frame = tk.Frame(root, pady=5)
        btn_frame.pack()
        tk.Button(btn_frame, text="View Analytics Dashboard", command=lambda: self.analytics_callback(self.host_list), bg="#3b82f6", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Refresh List", command=self.refresh_tree, bg="#f59e0b", fg="white").pack(side=tk.LEFT, padx=5)
        self.refresh_tree()

    def add_host(self):
        # handle input form
        ip, os, ports = self.ip_entry.get().strip(), self.os_entry.get().strip(), self.ports_entry.get().strip()
        if len(ip.split(".")) != 4 or not os:
            messagebox.showerror("Invalid Input", "Please enter valid IP and OS.")
            return

        new_host = self.NetworkHost(ip, os)
        if ports:
            for p in ports.split(","):
                if p.strip().isdigit() and 1 <= int(p.strip()) <= 65535:
                    new_host.add_port(int(p.strip()))

        self.host_list.append(new_host)
        self.save_callback(self.host_list)
        self.refresh_tree()
        self.ip_entry.delete(0, tk.END); self.os_entry.delete(0, tk.END); self.ports_entry.delete(0, tk.END)

    def refresh_tree(self):
        # refresh tree table
        self.tree.delete(*self.tree.get_children())
        for host in self.host_list:
            ports_str = ", ".join(map(str, host.open_ports)) if host.open_ports else "None"
            vulns_str = f"{len(host.dangerous_ports_found)} Detected" if host.dangerous_ports_found else "Clean"
            self.tree.insert("", tk.END, values=(host.ip_address, getattr(host, 'operating_system', 'Unknown'), host.risk_level, ports_str, vulns_str))