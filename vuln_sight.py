import tkinter as tk
from tkinter import scrolledtext, messagebox

import nmap
import subprocess
import datetime
import os
import threading

# Create reports folder if not exists
if not os.path.exists("reports"):
    os.makedirs("reports")

def classify_risk(port):
    high = [21, 22, 23, 445, 3389]
    medium = [80, 443, 8080]

    if port in high:
        return "HIGH"
    elif port in medium:
        return "MEDIUM"
    else:
        return "LOW"

# ----------------------------
# AI Explanation Engine
# ----------------------------
def ai_explanation(service, port):
    knowledge_base = {
        "ssh": {
            "risk": "Brute Force Risk",
            "impact": "Attackers may gain remote shell access.",
            "mitigation": "Use SSH keys and disable password login."
        },
        "ftp": {
            "risk": "Credential Exposure",
            "impact": "Credentials transmitted in plaintext.",
            "mitigation": "Use SFTP instead."
        },
        "http": {
            "risk": "Web Exploits",
            "impact": "Possible SQLi, XSS or outdated server attacks.",
            "mitigation": "Patch server and use WAF."
        }
    }

    service = service.lower()

    if service in knowledge_base:
        data = knowledge_base[service]
        return f"""
[AI ANALYSIS]
Service: {service.upper()}
Threat: {data['risk']}
Impact: {data['impact']}
Mitigation: {data['mitigation']}
"""
    else:
        return f"""
[AI ANALYSIS]
Service: {service.upper()}
Threat: Unknown
Mitigation: Restrict exposure if unnecessary.
"""

# SCAN FUNCTION

def scan_target():
    target = target_entry.get()

    if not target:
        messagebox.showerror("Error", "Enter Target")
        return

    output_area.delete(1.0, tk.END)
    output_area.insert(tk.END, f"Starting Scan on {target}\n\n")

    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV -T4')

    report = "VulnSight Report\n"
    report += "=" * 60 + "\n"
    report += f"Target: {target}\n"
    report += f"Date: {datetime.datetime.now()}\n\n"

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                risk = classify_risk(port)

                report += f"Port: {port}\n"
                report += f"Service: {service}\n"
                report += f"Version: {version}\n"
                report += f"Risk Level: {risk}\n"
                report += ai_explanation(service, port)
                report += "\n"

    output_area.insert(tk.END, report)

def threaded_scan():
    thread = threading.Thread(target=scan_target)
    thread.start()



# GUI Starts Below
root = tk.Tk()
root.title("VulnSight - AI Vulnerability Scanner")
root.geometry("1000x650")
root.configure(bg="#1e1e1e")

title = tk.Label(root, text="VulnSight", font=("Arial", 24),
                 fg="red", bg="#1e1e1e")
title.pack(pady=10)

frame = tk.Frame(root, bg="#1e1e1e")
frame.pack(pady=10)

tk.Label(frame, text="Target IP / Domain:",
         fg="white", bg="#1e1e1e").pack(side=tk.LEFT)

target_entry = tk.Entry(frame, width=40)
target_entry.pack(side=tk.LEFT, padx=10)

scan_button = tk.Button(root,
                        text="Start Scan",
                        command=threaded_scan,
                        bg="red",
                        fg="white")
scan_button.pack(pady=10)

output_area = scrolledtext.ScrolledText(root, width=120, height=30,
                                        bg="#2b2b2b", fg="white")
output_area.pack(pady=20)

root.mainloop()
