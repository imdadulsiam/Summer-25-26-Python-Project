# analytics.py
import tkinter as tk
from tkinter import messagebox
import numpy as np

def show_analytics_dashboard(hosts_list: list) -> None:
    # check if list is empty first
    if not hosts_list:
        messagebox.showinfo("Dashboard Info", "Database is empty. Please add network assets first.")
        return

    # convert ports count to numpy array
    total_ports_array = np.array([len(host.open_ports) for host in hosts_list])
    risk_labels = [host.risk_level for host in hosts_list]
    total_assets = len(hosts_list)

    # calc average and max using numpy
    avg_open_ports = np.mean(total_ports_array)
    max_open_ports = np.max(total_ports_array)

    # count risk levels
    high_count = np.sum(np.array([1 for r in risk_labels if r == "High"]))
    med_count = np.sum(np.array([1 for r in risk_labels if r == "Medium"]))
    low_count = np.sum(np.array([1 for r in risk_labels if r == "Low"]))

    # percentage calculations
    high_pct = (high_count / total_assets) * 100
    med_pct = (med_count / total_assets) * 100
    low_pct = (low_count / total_assets) * 100

    # popup window setup
    report_win = tk.Toplevel()
    report_win.title("Security Analytics Dashboard")
    report_win.geometry("450x380")
    report_win.resizable(False, False)

    # heading label
    title = tk.Label(
        report_win, 
        text="Network Threat Analytics Dashboard", 
        font=("Helvetica", 12, "bold"), 
        bg="#111827", 
        fg="white", 
        pady=8
    )
    title.pack(fill=tk.X)

    # summary frame
    summary_frame = tk.LabelFrame(report_win, text=" Summary Indicators (NumPy Engine) ", font=("Helvetica", 10, "bold"), padx=15, pady=10)
    summary_frame.pack(fill=tk.X, padx=15, pady=10)

    tk.Label(summary_frame, text=f"Total Network Assets Scanned: {total_assets}", font=("Helvetica", 9, "bold")).pack(anchor=tk.W, pady=2)
    tk.Label(summary_frame, text=f"Average Open Ports per Device: {avg_open_ports:.2f}", font=("Helvetica", 9)).pack(anchor=tk.W, pady=2)
    tk.Label(summary_frame, text=f"Max Open Ports on Single Asset: {max_open_ports}", font=("Helvetica", 9)).pack(anchor=tk.W, pady=2)

    # breakdown section
    breakdown_frame = tk.LabelFrame(report_win, text=" Threat Exposure Allocations ", font=("Helvetica", 10, "bold"), padx=15, pady=10)
    breakdown_frame.pack(fill=tk.X, padx=15, pady=10)

    tk.Label(breakdown_frame, text=f"🔴 High Severity Threats: {high_pct:.1f}% ({high_count} Hosts)", fg="#dc2626", font=("Helvetica", 9, "bold")).pack(anchor=tk.W, pady=2)
    tk.Label(breakdown_frame, text=f"🟡 Medium Severity Threats: {med_pct:.1f}% ({med_count} Hosts)", fg="#d97706", font=("Helvetica", 9, "bold")).pack(anchor=tk.W, pady=2)
    tk.Label(breakdown_frame, text=f"🟢 Low Severity Threats: {low_pct:.1f}% ({low_count} Hosts)", fg="#16a34a", font=("Helvetica", 9, "bold")).pack(anchor=tk.W, pady=2)

    # close button
    close_btn = tk.Button(report_win, text="Close Report", command=report_win.destroy, bg="#374151", fg="white")
    close_btn.pack(pady=10)