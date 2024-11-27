# VERSION 5 #

import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, TCP, get_if_list, conf
from scapy.layers.inet import IP
import threading
import psutil
import time
import subprocess
import platform
import logging
import re
import ipaddress
from datetime import datetime
import os

log_file_path = os.path.join(os.path.dirname(__file__), "ids_logfile.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler()
    ]
)

class Firewall:
    def __init__(self):
        self.blocked_ips = set()
        self.whitelisted_ips = {"192.168.1.1", "127.0.0.1"}
        self.os_name = platform.system()

    def sync_with_iptables(self):
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                stdout=subprocess.PIPE,
                text=True
            )
            self.blocked_ips.clear()
            for line in result.stdout.splitlines():
                if "DROP" in line:
                    parts = line.split()
                    for part in parts:
                        if self.is_valid_ip(part):
                            self.blocked_ips.add(part)
                            logging.info(f"Synchronized blocked IP(s) from iptables: {part}")
        except Exception as e:
            logging.error(f"Failed to synchronize with iptables: {e}")

    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
        
    def block_ip(self, ip):
        if ip in self.whitelisted_ips or ip in self.blocked_ips:
            return
        try:
            if self.os_name == "Linux":
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif self.os_name == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block_{ip}", f"dir=in", f"action=block", f"remoteip={ip}"], check=True)
            else:
                raise OSError(f"Unsupported OS: {self.os_name}")
            self.blocked_ips.add(ip)
            logging.info(f"Blocked IP: {ip}")
        except Exception as e:
            logging.error(f"Error blocking IP: {ip}: {e}")

    def unblock_ip(self, ip):
        if ip not in self.blocked_ips:
            return
        try:
            if self.os_name == "Linux":
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif self.os_name == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block_{ip}", f"dir=in", f"action=block", f"remoteip={ip}"], check=True)
            else:
                raise OSError(f"Unsupported OS: {self.os_name}")
            self.blocked_ips.add(ip)
            logging.info(f"Unblocked IP: {ip}")
        except Exception as e:
            logging.error(f"Error unblocking IP: {ip}: {e}")

    def get_blocked_ips(self):
        self.sync_with_iptables()
        return list(self.blocked_ips)

class Sniffer:
    def __init__(self, firewall, alert_callback):
        self.firewall = firewall
        self.failed_attempts = {}
        self.alert_threshold = 5
        self.alert_callback = alert_callback
        self.os_name = platform.system()
        self.running = False

    def monitor_logs(self):
        self.running = True
        if self.os_name == "Linux":
            self.monitor_journald()
        elif self.os_name == "Windows":
            self.monitor_event_logs()
        else:
            logging.error(f"Unsupported OS: {self.os_name}")

    def monitor_journald(self):
        try:
            process = subprocess.Popen(
                ["journalctl", "-u", "ssh", "-f", "-n", "0"],
                stdout=subprocess.PIPE,
                text=True
            )
            while self.running:
                line = process.stdout.readline()
                if not line:
                    continue
                failed_match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
                if failed_match:
                    src_ip = failed_match.group(1)
                    self.process_failed_attempt(src_ip)
            process.terminate()
        except Exception as e:
            logging.error(f"Error monitoring journald: {e}")

    def stop_monitoring(self):
        self.running = False

    def monitor_event_logs(self):
        try:
            command = [
                "powershell",
                "-Command",
                "Get-EventLog -LogName Security | Where-Object { $_.EventID -eq 4625 }"
            ]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
            logging.info("Monitoring Windows Event Logs via Powershell...")
            while self.running:
                line = process.stdout.readline()
                if "Failure" in line:
                    src_ip_match = re.search(r"Source Network Address: (\d+\.\d+\.\d+\.\d+)", line)
                    if src_ip_match:
                        src_ip = src_ip_match.group(1)
                        self.process_failed_attempt(src_ip)
        except Exception as e:
            logging.error(f"Error using Powershell for monitoring logs: {e}")

    def process_failed_attempt(self, src_ip):
        self.failed_attempts[src_ip] = self.failed_attempts.get(src_ip, 0) + 1
        attempt_count = self.failed_attempts[src_ip]
        if attempt_count > self.alert_threshold:
            self.firewall.block_ip(src_ip)
            self.alert_callback(f"Blocked IP {src_ip} after {attempt_count} failed attempts.")

class TextWidgetLogger(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
    
    def emit(self, record):
        log_entry = self.format(record)
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, log_entry + "\n")
        self.text_widget.configure(state="disabled")
        self.text_widget.yview(tk.END)


def show_alert(title, message):
    """
    Display popup alert with information.
    """
    logging.info(f"ALERT: {title} - {message}")
    messagebox.showinfo(title, message)

def get_valid_interface():
    """
    Detects a valid network interface for sniffing.
    Returns:
        str: Name of a valid interface or None if no valid interface is found.
    """
    try:
        interfaces = get_if_list()
        logging.info(f"Available interfaces: {interfaces}")

        #check the default interface first
        default_interface = conf.iface
        if default_interface in interfaces:
            logging.info(f"Using default interface: {default_interface}")
            show_alert("Adapter Selected", f"Using default network adapter: {default_interface}")
            return default_interface

        #test each interface
        for iface in interfaces:
            try:
                #test binding to the interface
                sniff(iface=iface, count=1, timeout=1, store=0)
                logging.info(f"Valid interface found: {iface}")
                show_alert("Adapter Selected", f"Valid network adapter selected: {iface}")
                return iface
            except Exception as e:
                logging.error(f"Interface {iface} is not valid: {e}")

        logging.error("No valid interface found.")
        show_alert("No Valid Adapter", "No valid adapter could be found.")
        return None
    except Exception as e:
        logging.error(f"Error detecting network interfaces: {e}")
        return None

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Intrusion Detection System")
        self.geometry("800x680")
        self.configure(bg="#1E1E1E")

        self.show_logs = tk.BooleanVar(value=False)
        self.log_widget = None
        self.log_handler = None

        self.radio_var = tk.StringVar()
        self.syn_threshold = tk.IntVar()
        self.ports_to_monitor = tk.StringVar()
        self.cpu_threshold = tk.DoubleVar()
        self.memory_threshold = tk.DoubleVar()

        self.syn_count = 0
        self.syn_monitoring = False
        self.process_monitoring = False
        self.sniff_thread = None
        self.process_monitoring_thread = None

        self.firewall = Firewall()
        self.sniffer_thread = None
        self.sniffer = Sniffer(self.firewall, self.show_alert)

        self.blocked_ips = set()
        self.ip_count = {}

        self.protocol("WM_DELETE_WINDOW", self.close_application)
        self.create_tabs()

        self.setup_log_viewer()

    def setup_log_viewer(self):
        """
        Sets up log viewer and integrates with logging system.
        """
        self.log_checkbox = tk.Checkbutton(
            self,
            text="Show Logs",
            variable=self.show_logs,
            command=self.toggle_log_viewer,
            bg="#1E1E1E",
            fg="#00FF00",
            font=("Courier", 12),
            activebackground="#1E1E1E",
            activeforeground="#00FF00",
            selectcolor="#333333"
        )
        self.log_checkbox.pack(anchor="ne", pady=5, padx=5)

        self.log_widget = tk.Text(self, height=10, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12))
        self.log_widget.pack(fill="x", side="bottom", padx=10, pady=5)
        self.log_widget.configure(state="disabled")
        self.log_widget.pack_forget()

        self.log_handler = TextWidgetLogger(self.log_widget)
        self.log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.getLogger().addHandler(self.log_handler)

    def toggle_log_viewer(self):
        """
        Toggle for log view.
        """
        if self.show_logs.get():
            self.log_widget.pack(fill="x", side="bottom", padx=10, pady=5)
            self.geometry("800x800")
        else:
            self.log_widget.pack_forget()
            self.geometry("800x680")

    def create_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, expand=True)

        self.hids_frame = tk.Frame(self.notebook, bg="#1E1E1E")
        self.process_monitor_frame = tk.Frame(self.notebook, bg="#1E1E1E")
        self.brute_force_frame = tk.Frame(self.notebook, bg="#1E1E1E")
        self.blocked_ips_frame = tk.Frame(self.notebook, bg="#1E1E1E")

        self.notebook.add(self.hids_frame, text="HIDS")
        self.notebook.add(self.process_monitor_frame, text="Process Monitor")
        self.notebook.add(self.brute_force_frame, text="Brute Force Monitor")
        self.notebook.add(self.blocked_ips_frame, text="Blocked IPs")


        self.create_hids_widgets(self.hids_frame)
        self.create_process_monitor_widgets(self.process_monitor_frame)
        self.create_brute_force_widgets(self.brute_force_frame)
        self.create_blocked_ips_widgets(self.blocked_ips_frame)

    def create_hids_widgets(self, frame):
        header = tk.Label(frame, text="HIDS - SYN Packet Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        parameters_frame = tk.Frame(frame, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
        parameters_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(parameters_frame, text="SYN Packet Threshold:", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.syn_threshold_entry = tk.Entry(parameters_frame, textvariable=self.syn_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.syn_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
        self.syn_threshold.set(100)

        tk.Label(parameters_frame, text="Ports to Monitor (comma-separated):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ports_entry = tk.Entry(parameters_frame, textvariable=self.ports_to_monitor, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5)
        self.ports_to_monitor.set("80,443")

        control_frame = tk.Frame(frame, bg="#1E1E1E")
        control_frame.pack(pady=10)

        start_button = tk.Button(control_frame, text="Start SYN Monitoring", bg="#333333", fg="#00FF00", command=self.start_syn_monitor, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
        start_button.grid(row=0, column=0, padx=5)

        stop_button = tk.Button(control_frame, text="Stop SYN Monitoring", bg="#333333", fg="#FF4500", command=lambda: self.stop_monitoring("SYN"), font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
        stop_button.grid(row=0, column=1, padx=5)

        unblock_button = tk.Button(control_frame, text="View/Unblock IPs", bg="#333333", fg="#00FF00", command=self.view_blocked_ips, font=("Courier", 12))
        unblock_button.grid(row=1, column=0, columnspan=2, pady=5)

        self.create_charts(frame)

    def create_process_monitor_widgets(self, frame):
        header = tk.Label(frame, text="Process Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        parameters_frame = tk.Frame(frame, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
        parameters_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(parameters_frame, text="CPU Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.cpu_threshold_entry = tk.Entry(parameters_frame, textvariable=self.cpu_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.cpu_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
        self.cpu_threshold.set(80.0)

        tk.Label(parameters_frame, text="Memory Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.memory_threshold_entry = tk.Entry(parameters_frame, textvariable=self.memory_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.memory_threshold_entry.grid(row=1, column=1, padx=5, pady=5)
        self.memory_threshold.set(80.0)

        control_frame = tk.Frame(frame, bg="#1E1E1E")
        control_frame.pack(pady=10)

        start_button = tk.Button(control_frame, text="Start Process Monitoring", bg="#333333", fg="#00FF00", command=self.start_process_monitor, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
        start_button.grid(row=0, column=0, padx=5)

        stop_button = tk.Button(control_frame, text="Stop Process Monitoring", bg="#333333", fg="#FF4500", command=lambda: self.stop_monitoring("Process"), font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
        stop_button.grid(row=0, column=1, padx=5)

        self.process_alert_label = tk.Label(frame, text="", font=("Courier", 14), bg="#1E1E1E", fg="#FF4500")
        self.process_alert_label.pack(pady=10)

    def create_brute_force_widgets(self, frame):
        header = tk.Label(frame, text="Brute Force Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        self.brute_force_status = tk.Label(frame, text="Status: Stopped", font=("Courier", 14), bg="#1E1E1E", fg="#FF4500")
        self.brute_force_status.pack(pady=10)

        start_button = tk.Button(frame, text="Start Brute Force Monitoring", bg="#333333", fg="#00FF00", font=("Courier", 12), command=self.start_brute_force_monitor)
        start_button.pack(pady=5)

        stop_button = tk.Button(frame, text="Stop Brute Force Monitoring", bg="#333333", fg="#FF4500", font=("Courier", 12), command=self.stop_brute_force_monitor)
        stop_button.pack(pady=5)

        self.blocked_ips_listbox = tk.Listbox(frame, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12), width=50, height=15)
        self.blocked_ips_listbox.pack(pady=10)

        refresh_button = tk.Button(frame, text="Refresh Blocked IP(s)", bg="#333333", fg="#00FF00", font=("Courier", 12), command=self.refresh_blocked_ips)
        refresh_button.pack(pady=5)

    def start_brute_force_monitor(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.show_alert("Error", "Brute Force Monitor is already running.")
            return
        self.sniffer_thread = threading.Thread(target=self.sniffer.monitor_logs, daemon=True)
        self.sniffer_thread.start()
        self.brute_force_status.config(text="Status: Running", fg="#00FF00")
        self.show_alert("Brute Force Monitor", "Brute Force Monitoring has started.")

    def stop_brute_force_monitor(self):
        if self.sniffer_thread:
            self.sniffer.stop_monitoring()
            self.sniffer_thread.join(timeout=1)
            self.sniffer_thread = None
        self.brute_force_status.config(text="Status: Stopped", fg="#FF4500")
        self.show_alert("Brute Force Monitor", "Brute Force Monitoring has stopped.")

    def refresh_blocked_ips(self):
        self.blocked_ips_listbox.delete(0, tk.END)
        blocked_ips = self.firewall.get_blocked_ips()
        for ip in blocked_ips:
            self.blocked_ips_listbox.insert(tk.END, ip)

    def show_alert(self, title, message):
        logging.info(f"ALERT: {title} - {message}")
        messagebox.showinfo(title, message)

    def create_charts(self, frame):
        chart_frame = tk.Frame(frame, bg="#1E1E1E")
        chart_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        self.fig, self.ax = plt.subplots(facecolor="#1E1E1E")
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.ax.set_title('SYN Packets Count', color="#00FF00")
        self.ax.set_xlabel('Time', color="#00FF00")
        self.ax.set_ylabel('SYN Packets', color="#00FF00")
        self.ax.tick_params(axis='x', colors='#00FF00')
        self.ax.tick_params(axis='y', colors='#00FF00')
        self.ax.spines['bottom'].set_color('#00FF00')
        self.ax.spines['top'].set_color('#00FF00')
        self.ax.spines['right'].set_color('#00FF00')
        self.ax.spines['left'].set_color('#00FF00')

        self.times = []
        self.syn_counts = []

        self.anim = FuncAnimation(self.fig, self.update_chart_animation, interval=1000, blit=False)

    def start_syn_monitor(self):
        self.syn_monitoring = True
        self.syn_count = 0
        self.monitor_ports = [int(port.strip()) for port in self.ports_to_monitor.get().split(",") if port.strip().isdigit()]
        logging.info(f"Monitoring SYN packets on ports: {self.monitor_ports} with threshold {self.syn_threshold.get()}")
        show_alert("SYN Monitoring Started", f"Monitoring started on ports: {self.monitor_ports} with threshold: {self.syn_threshold.get()}")

        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def sniff_packets(self):
        interface = get_valid_interface()
        if not interface:
            logging.error("No valid network interface available for sniffing.")
            return

        logging.info(f"Sniffing on interface: {interface}")
        try:
            sniff(iface=interface, prn=self.process_packet, store=0, stop_filter=lambda x: not self.syn_monitoring)
        except Exception as e:
            logging.error(f"Error in sniffing thread: {e}")

    def process_packet(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            if packet[TCP].flags == 'S' and packet[TCP].dport in self.monitor_ports:
                self.syn_count += 1
                logging.info(f"SYN packet detected from {src_ip} on port {packet[TCP].dport}. Total SYN count: {self.syn_count}")

                if src_ip not in self.blocked_ips:
                    self.ip_count[src_ip] = self.ip_count.get(src_ip, 0) + 1

                    if self.ip_count[src_ip] >= self.syn_threshold.get():
                        logging.info(f"SYN packet threshold reached for IP {src_ip}! Blocking...")
                        self.block_ip(src_ip)
                        self.blocked_ips.add(src_ip)
                        show_alert("SYN Threshold Reached", f"SYN packet threshold reached for IP: {src_ip}. This IP is now blocked.")

                self.update_chart()

    def block_ip(self, ip):
        """
        Block IP based on which OS is being used.
        """
        try:
            os_name = platform.system()
            if os_name == "Linux":
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif os_name == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block_{ip}", f"dir=in", f"action=block", f"remoteip={ip}"], check=True)
            else:
                logging.error(f"Unsupported OS: {os_name}")
                return              
            logging.info(f"Blocked IP: {ip}")
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {e}")

    def unblock_ip(self, ip):
        """
        Unblock IP based on which OS is being used.
        """
        try:
            os_name = platform.system()
            if os_name == "Linux":
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif os_name == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block_{ip}", f"dir=in", f"action=block", f"remoteip={ip}"], check=True)
            else:
                logging.error(f"Unsupported OS: {os_name}")
                return              
            logging.info(f"Unblocked IP: {ip}")
        except Exception as e:
            logging.error(f"Error unblocking IP {ip}: {e}")

    def view_blocked_ips(self):
        unblock_window = tk.Toplevel(self)
        unblock_window.title("Blocked IPs")
        unblock_window.geometry("400x300")
        unblock_window.configure(bg="#1E1E1E")

        tk.Label(unblock_window, text="Blocked IPs", font=("Courier", 18), bg="#1E1E1E", fg="#00FF00").pack(pady=10)

        listbox = tk.Listbox(unblock_window, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12))
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for ip in self.blocked_ips:
            listbox.insert(tk.END, ip)

        def unblock_selected():
            selected_ip = listbox.get(tk.ACTIVE)
            if selected_ip:
                self.unblock_ip(selected_ip)
                listbox.delete(tk.ACTIVE)

        unblock_button = tk.Button(unblock_window, text="Unblock Selected", bg="#333333", fg="#FF4500", command=unblock_selected, font=("Courier", 12))
        unblock_button.pack(pady=10)

    def create_blocked_ips_widgets(self, frame):
        header = tk.Label(frame, text="Blocked IPs", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        self.blocked_ips_listbox = tk.Listbox(frame, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12), width=50, height=15)
        self.blocked_ips_listbox.pack(pady=10)

        unblock_button = tk.Button(frame, text="Unblock Selected IP", bg="#333333", fg="#FF4500", command=self.unblock_ip, font=("Courier", 12))
        unblock_button.pack(pady=10)

    def start_process_monitor(self):
        self.process_monitoring = True
        logging.info(f"Starting process monitoring. CPU threshold: {self.cpu_threshold.get()}%, "f"Memory threshold: {self.memory_threshold.get()}%")
        show_alert("Process Monitoring Started", f"Process monitoring started with CPU threshold: {self.cpu_threshold.get()}% and Memory Threshold: {self.memory_threshold.get()}%.")

        self.process_monitoring_thread = threading.Thread(target=self.monitor_processes)
        self.process_monitoring_thread.daemon = True
        self.process_monitoring_thread.start()

    def stop_syn_monitor(self):
        self.syn_monitoring = False
        logging.info("Stopped SYN monitoring.")
        show_alert("SYN Monitoring Stopped", "SYN monitoring has been stopped.")

    def stop_process_monitor(self):
        self.process_monitoring = False
        logging.info("Stopped Process monitoring.")
        show_alert("Process Monitoring Stopped", "Process monitoring has been stopped.")

    def close_application(self):
        """Gracefully close the application by stopping threads and destroying the window."""
        logging.info("Closing application...")
        
        #stop monitoring if running
        if self.syn_monitoring or self.process_monitoring:
            self.stop_monitoring()

        #wait for threads to finish
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1)
        if self.process_monitoring_thread and self.process_monitoring_thread.is_alive():
            self.process_monitoring_thread.join(timeout=1)

        #destroy the main window
        self.destroy()
        logging.info("Application closed.")

    def stop_monitoring(self, monitor_type=None):
        """
        Stop the specified monitor. Either SYN or Process, if none then both.
        """
        if monitor_type == "SYN" or monitor_type is None:
            if self.syn_monitoring:
                self.stop_syn_monitor()
        if monitor_type == "Process" or monitor_type is None:
            if self.process_monitoring:
                self.stop_process_monitor()

    def monitor_processes(self):
        while self.process_monitoring:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    cpu_usage = proc.info['cpu_percent']
                    memory_usage = proc.info['memory_percent']

                    if cpu_usage > self.cpu_threshold.get() or memory_usage > self.memory_threshold.get():
                        logging.info(f"Killing process {proc.info['name']} (PID: {proc.info['pid']}) for exceeding thresholds. CPU: {cpu_usage}%, Memory: {memory_usage}%")
                        show_alert(
                            "Process Killed",
                            f"Process '{proc.info['name']}' (PID: {proc.info['pid']}) exceeded set threshold.\n"
                            f"CPU Usage: {cpu_usage}%\nMemory Usage: {memory_usage}%. This process has been killed."
                        )
                        proc.terminate()

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            time.sleep(5)

    def update_chart(self):
        self.times.append(len(self.times))
        self.syn_counts.append(self.syn_count)
        self.ax.clear()
        self.ax.set_title('SYN Packets Count', color="#00FF00")
        self.ax.set_xlabel('Time', color="#00FF00")
        self.ax.set_ylabel('SYN Packets', color="#00FF00")
        self.ax.plot(self.times, self.syn_counts, color="#00FF00")
        self.canvas.draw()

    def update_chart_animation(self, i):
        self.ax.clear()
        self.ax.set_title('SYN Packets Count', color="#00FF00")
        self.ax.set_xlabel('Time', color="#00FF00")
        self.ax.set_ylabel('SYN Packets', color="#00FF00")
        self.ax.plot(self.times, self.syn_counts, color="#00FF00")
        self.ax.tick_params(axis='x', colors='#00FF00')
        self.ax.tick_params(axis='y', colors='#00FF00')
        self.ax.spines['bottom'].set_color('#00FF00')
        self.ax.spines['top'].set_color('#00FF00')
        self.ax.spines['right'].set_color('#00FF00')
        self.ax.spines['left'].set_color('#00FF00')

    def alert_user(self):
        alert_label = tk.Label(self.hids_frame, text="ALERT: SYN packet threshold reached!", font=("Courier", 18), bg="#1E1E1E", fg="#FF4500")
        alert_label.pack(pady=20)


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
