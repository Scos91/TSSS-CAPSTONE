# Windows Event log style - works by checking logs every second - NEED ADMIN Priviledge to work

import os
import signal
import subprocess
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from scapy.all import sniff, TCP, get_if_list, conf
from scapy.layers.inet import IP
import threading
import psutil
import re
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import time
import selectors
import io
import threading
from typing import Set
import win32evtlog

log_file_path = os.path.join(os.path.dirname(__file__), "ids_logfile.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file_path), logging.StreamHandler()],
)

def signal_handler(sig, frame):
    logging.info(f"Signal {sig} received. Initiating application shutdown...")
    try:
        if app:
            app.close_application()
        else:
            logging.warning("Application instance not available. Exiting without cleanup.")
    except Exception as e:
        logging.error(f"Error during signal handling: {e}")
    finally:
        logging.info("Application exited.")
        os._exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class Firewall:
    def __init__(self):
        self.blocked_ips = set()
        self.whitelisted_ips = {"192.168.1.1", "127.0.0.1"}

    def block_ip(self, ip):
        if ip in self.whitelisted_ips or ip in self.blocked_ips:
            logging.warning(f"Attempted to block whitelisted or already blocked IP: {ip}")
            return
        try:
            subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name=Block_{ip}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                ],
                check=True,
            )
            self.blocked_ips.add(ip)
            logging.info(f"Blocked IP: {ip}")
            app.refresh_blocked_ips()
        except subprocess.CalledProcessError as e:
            logging.error(f"Subprocess error while blocking IP {ip}: {e.stderr}")
        except Exception as e:
            logging.error(f"Unexpected error while blocking IP: {ip}: {e}")

    def unblock_ip(self, ip):
        if ip not in self.blocked_ips:
            logging.warning(f"Attempted to unblock non-blocked IP: {ip}")
            return
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Block_{ip}"],
                check=True,
            )
            self.blocked_ips.discard(ip)
            logging.info(f"Unblocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Subprocess error while unblocking IP {ip}: {e.stderr}")
        except Exception as e:
            logging.error(f"Unexpected error while unblocking IP: {ip}: {e}")

class Sniffer:
    def __init__(self, firewall, alert_callback):
        self.firewall = firewall
        self.failed_attempts = {}
        self.alert_threshold = 5
        self.alert_callback = alert_callback
        self.running = False
        self.child_process = None
        self.stop_event = threading.Event()
        self.waiting_for_subprocess = False
        self.sniffer_thread = None

    def monitor_logs(self):
        self.running = True
        self.stop_event.clear()
        self.monitor_event_logs()

    def stop_monitoring(self):
        self.running = False
        self.stop_event.set()

        if self.child_process:
            try:
                logging.info("Terminating child process...")
                self.child_process.terminate()
                self.child_process.wait(timeout=5)
            except Exception as e:
                logging.error(f"Error stopping subprocess: {e}")
            finally:
                self.child_process = None

        logging.info("Monitoring stopped.")

    def monitor_event_logs(self):
        server = "localhost"
        logtype = "Security"
        hand = win32evtlog.OpenEventLog(server, logtype)

        logging.info("Started monitoring Windows Event Logs for brute force attempts.")

        while not self.stop_event.is_set():
            try:
                events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
                for event in events:
                    if event.EventID == 4625:
                        src_ip_match = re.search(r"Source Network Adress: (\d+\.\d+\.\d+\.\d+)", str(event.StringInserts))
                        if src_ip_match:
                            src_ip = src_ip_match.group(1)
                            self.process_failed_attempt(src_ip)
            except Exception as e:
                logging.error(f"Error reading event logs: {e}")

    def process_failed_attempt(self, src_ip):
        if src_ip in self.firewall.blocked_ips:
            logging.info(f"IP {src_ip} is already blocked. Ignoring further attempts.")
            return
        self.failed_attempts[src_ip] = self.failed_attempts.get(src_ip, 0) + 1
        attempt_count = self.failed_attempts[src_ip]
        if attempt_count > self.alert_threshold:
            self.firewall.block_ip(src_ip)
            self.alert_callback(f"Blocked IP {src_ip} after {attempt_count} failed attempts.")
            self.failed_attempts.pop(src_ip, None)

class TextWidgetLogger(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
    
    def emit(self, record):
        log_entry = self.format(record)
        self.text_widget.configure(state="normal")

        if record.levelno == logging.INFO:
            tag = "info"
        elif record.levelno == logging.WARNING:
            tag = "warning"
        elif record.levelno == logging.ERROR:
            tag = "error"
        else:
            tag = "default"

        self.text_widget.insert(tk.END, log_entry + "\n")
        self.text_widget.configure(state="disabled")
        self.text_widget.yview(tk.END)

        if record.levelno >= logging.ERROR:
            self.text_widget.bell()

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
        self.geometry("1280x800")
        self.configure(bg="#1E1E1E")

        self.main_frame = tk.Frame(self, bg="#1E1E1E")
        self.main_frame.pack(fill="both", expand=True)

        self.left_frame = tk.Frame(self.main_frame, bg="#1E1E1E")
        self.center_frame = tk.Frame(self.main_frame, bg="#1E1E1E")
        self.right_frame = tk.Frame(self.main_frame, bg="#2E2E2E", width=300)

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

        self.setup_log_viewer()
        self.create_tabs()
        self.update_layout()

    def setup_log_viewer(self):
        """
        Sets up log viewer and integrates with logging system.
        """
        tk.Label(
            self.right_frame, text="Logs", font=("Courier", 18), bg="#2E2E2E", fg="#00FF00"
        ).pack(pady=5)

        self.log_widget = tk.Text(
            self.right_frame, height=30, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12)
        )
        self.log_widget.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_widget.configure(state="disabled")

        self.log_widget.tag_configure("info", foreground="#00FF00")
        self.log_widget.tag_configure("warning", foreground="#FFA500")
        self.log_widget.tag_configure("error", foreground="#FF4500")
        self.log_widget.tag_configure("default", foreground="#FFFFFF")

        self.log_handler = TextWidgetLogger(self.log_widget)
        self.log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.getLogger().addHandler(self.log_handler)

    def toggle_log_viewer(self):
        """
        Toggle for log view, dynamically fits the window rsolution.
        """
        self.update_layout()

    def update_layout(self):
        """
        Dynamically update the layout based on the checkbox.
        """
        if self.show_logs.get():
            self.center_frame.pack_forget()
            self.left_frame.pack(side="left", fill="both", expand=True)
            self.notebook.pack_forget()
            self.notebook.pack(in_=self.left_frame, pady=10, expand=True, fill="both")
            self.right_frame.pack(side="right", fill="y")
        else:
            self.left_frame.pack_forget()
            self.right_frame.pack_forget()
            self.center_frame.pack(fill="both", expand=True)
            self.notebook.pack_forget()
            self.notebook.pack(in_=self.center_frame, pady=120, expand=True, fill="both")

    def create_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, expand=True)

        self.syn_frame = tk.Frame(self.notebook, bg="#1E1E1E")
        self.process_monitor_frame = tk.Frame(self.notebook, bg="#1E1E1E")
        self.brute_force_frame = tk.Frame(self.notebook, bg="#1E1E1E")

        self.notebook.add(self.syn_frame, text="SYN Monitor")
        self.notebook.add(self.process_monitor_frame, text="Process Monitor")
        self.notebook.add(self.brute_force_frame, text="Brute Force Monitor")

        self.create_syn_widgets(self.syn_frame)
        self.create_process_monitor_widgets(self.process_monitor_frame)
        self.create_brute_force_widgets(self.brute_force_frame)

    def add_log_checkbox(self, frame):
        """
        Adding the 'show logs' checkbox to each tab.
        """
        log_checkbox = tk.Checkbutton(
            frame,
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
        log_checkbox.pack(anchor="center", pady=5)

    def create_syn_widgets(self, frame):
        header = tk.Label(frame, text="SYN Packet Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
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

        stop_button = tk.Button(control_frame, text="Stop SYN Monitoring", bg="#333333", fg="#FF4500", command=self.stop_syn_monitor, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
        stop_button.grid(row=0, column=1, padx=5)

        view_blocked_ips_button = tk.Button(
            frame,
            text="View Blocked IPs",
            bg="#333333",
            fg="#00FF00",
            command=self.view_blocked_ips,
            font=("Courier", 12),
            activebackground="#00FF00",
            activeforeground="#1E1E1E"
        )
        view_blocked_ips_button.pack(pady=10)

        self.add_log_checkbox(frame)

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

        stop_button = tk.Button(control_frame, text="Stop Process Monitoring", bg="#333333", fg="#FF4500", command=self.stop_process_monitor, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
        stop_button.grid(row=0, column=1, padx=5)

        self.process_alert_label = tk.Label(frame, text="", font=("Courier", 14), bg="#1E1E1E", fg="#FF4500")
        self.process_alert_label.pack(pady=10)

        self.add_log_checkbox(frame)

    def create_brute_force_widgets(self, frame):
        header = tk.Label(frame, text="Brute Force Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        self.brute_force_status = tk.Label(frame, text="Status: Stopped", font=("Courier", 14), bg="#1E1E1E", fg="#FF4500")
        self.brute_force_status.pack(pady=10)

        start_button = tk.Button(frame, text="Start Brute Force Monitoring", bg="#333333", fg="#00FF00", font=("Courier", 12), command=self.start_brute_force_monitor)
        start_button.pack(pady=5)

        stop_button = tk.Button(frame, text="Stop Brute Force Monitoring", bg="#333333", fg="#FF4500", command=self.stop_brute_force_monitor, font=("Courier", 12))
        stop_button.pack(pady=5)

        self.blocked_ips_listbox = tk.Listbox(frame, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12), width=50, height=15)
        self.blocked_ips_listbox.pack(pady=10)

        refresh_button = tk.Button(frame, text="Refresh Blocked IP(s)", bg="#333333", fg="#00FF00", font=("Courier", 12), command=self.refresh_blocked_ips)
        refresh_button.pack(pady=5)

        view_blocked_ips_button = tk.Button(
            frame,
            text="View Blocked IPs",
            bg="#333333",
            fg="#00FF00",
            command=self.view_blocked_ips,
            font=("Courier", 12),
            activebackground="#00FF00",
            activeforeground="#1E1E1E"
        )
        view_blocked_ips_button.pack(pady=10)

        self.add_log_checkbox(frame)

    def start_brute_force_monitor(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.show_alert("Error", "Brute Force Monitor is already running.")
            return
        
        if self.sniffer.child_process and self.sniffer.child_process.poll() is None:
            logging.warning("Previous monitoring process is still running. Terminating it.")
            self.sniffer.stop_monitoring()

        self.sniffer_thread = threading.Thread(target=self.sniffer.monitor_logs, daemon=True)
        self.sniffer_thread.start()
        self.brute_force_status.config(text="Status: Running", fg="#00FF00")
        self.show_alert("Brute Force Monitor", "Brute Force Monitoring has started.")

    def stop_brute_force_monitor(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            logging.info("Stopping brute force monitoring thread...")

            self.sniffer.stop_monitoring()
            self.sniffer_thread.join(timeout=2)
            self.sniffer_thread = None

        self.brute_force_status.config(text="Status: Stopped", fg="#FF4500")
        self.show_alert("Brute Force Monitor", "Brute Force Monitoring has stopped.")
        logging.info(f"Thread state: {threading.enumerate()}")

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

        self.line, = self.ax.plot([], [], color="#00FF00")

        self.anim = FuncAnimation(self.fig, self.update_chart_animation, interval=1000)

    def start_syn_monitor(self):
        self.syn_monitoring = True
        self.syn_count = 0
        self.monitor_ports = [int(port.strip()) for port in self.ports_to_monitor.get().split(",") if port.strip().isdigit()] or [80, 443]
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
        try:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                src_ip = packet[IP].src
                if packet[TCP].flags == 'S' and packet[TCP].dport in self.monitor_ports:
                    self.syn_count += 1
                    logging.info(f"SYN packet detected from {src_ip} on port {packet[TCP].dport}. Total SYN count: {self.syn_count}")

                    self.times.append(len(self.times))
                    self.syn_counts.append(self.syn_count)

                    if src_ip not in self.blocked_ips:
                        self.ip_count[src_ip] = self.ip_count.get(src_ip, 0) + 1

                        if self.ip_count[src_ip] >= self.syn_threshold.get():
                            logging.info(f"SYN packet threshold reached for IP {src_ip}! Blocking...")
                            self.block_ip(src_ip)
                            self.blocked_ips.add(src_ip)
                            app.refresh_blocked_ips()
                            show_alert("SYN Threshold Reached", f"SYN packet threshold reached for IP: {src_ip}. This IP is now blocked.")
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            logging.debug(f"Packet summary: {packet.summary()}")

    def block_ip(self, ip):
        self.firewall.block_ip(ip)

    def unblock_ip(self, ip):
        self.firewall.unblock_ip(ip)

    def view_blocked_ips(self):
        unblock_window = tk.Toplevel(self)
        unblock_window.title("Blocked IPs")
        unblock_window.geometry("600x500")
        unblock_window.configure(bg="#1E1E1E")
        unblock_window.pack_propagate(False)

        tk.Label(unblock_window, text="Blocked IPs", font=("Courier", 18), bg="#1E1E1E", fg="#00FF00").pack(pady=10)

        listbox_frame = tk.Frame(unblock_window, bg="#1E1E1E")
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        listbox = tk.Listbox(
            listbox_frame, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12), selectmode=tk.SINGLE, width=50, height=15, yscrollcommand=scrollbar.set
        )
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)

        blocked_ips = self.firewall.get_blocked_ips()
        for ip in blocked_ips:
            listbox.insert(tk.END, ip)

        def unblock_selected():
            """
            Unblock the selected IP from the listbox.
            """
            selected_ip = listbox.get(tk.ACTIVE)
            if selected_ip:
                def unblock_task():
                    self.firewall.unblock_ip(selected_ip)
                    messagebox.showinfo("Success", f"IP {selected_ip} unblocked successfully.")
                    refresh_listbox()

                threading.Thread(target=unblock_task, daemon=True).start()

        def refresh_listbox():
            """
            Refresh the listbox to display the updated list of blocked IPs.
            """
            listbox.delete(0, tk.END)
            updated_blocked_ips = self.firewall.get_blocked_ips()
            for ip in updated_blocked_ips:
                listbox.insert(tk.END, ip)

        unblock_button = tk.Button(
            unblock_window,
            text="Unblock Selected",
            bg="#333333",
            fg="#FF4500",
            command=unblock_selected,
            font=("Courier", 12),
            activebackground="#FF4500",
            activeforeground="#1E1E1E",
        )
        unblock_button.pack(pady=10, fill=tk.X, expand=True)

    def create_blocked_ips_widgets(self, frame):
        header = tk.Label(frame, text="Blocked IPs", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        self.blocked_ips_listbox = tk.Listbox(frame, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12), width=50, height=15)
        self.blocked_ips_listbox.pack(pady=10)

        unblock_button = tk.Button(frame, text="Unblock Selected IP", bg="#333333", fg="#FF4500", command=self.unblock_ip, font=("Courier", 12))
        unblock_button.pack(pady=10)

        self.add_log_checkbox(frame)

    def start_process_monitor(self):
        self.process_monitoring = True
        logging.info(f"Starting process monitoring. CPU threshold: {self.cpu_threshold.get()}%, "f"Memory threshold: {self.memory_threshold.get()}%")
        show_alert("Process Monitoring Started", f"Process monitoring started with CPU threshold: {self.cpu_threshold.get()}% and Memory Threshold: {self.memory_threshold.get()}%.")

        self.process_monitoring_thread = threading.Thread(target=self.monitor_processes)
        self.process_monitoring_thread.daemon = True
        self.process_monitoring_thread.start()

    def stop_syn_monitor(self):
        self.syn_monitoring = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1)
            self.sniff_thread = None
        logging.info("Stopped SYN monitoring.")
        show_alert("SYN Monitoring Stopped", "SYN monitoring has been stopped.")

    def stop_process_monitor(self):
        self.process_monitoring = False
        if self.process_monitoring_thread and self.process_monitoring_thread.is_alive():
            self.process_monitoring_thread.join(timeout=1)
            self.process_monitoring_thread = None
        logging.info("Stopped Process monitoring.")
        show_alert("Process Monitoring Stopped", "Process monitoring has been stopped.")

    def close_application(self):
        """Gracefully close the application by stopping threads and destroying the window."""
        logging.info("Closing application...")

        try:
            if self.sniff_thread and self.sniff_thread.is_alive():
                logging.info("Stopped sniffer thread...")
                self.syn_monitoring = False
                self.sniff_thread.join(timeout=1)

            if self.process_monitoring_thread and self.process_monitoring_thread.is_alive():
                logging.info("Stopping process monitoring thread...")
                self.process_monitoring = False
                self.process_monitoring_thread.join(timeout=1)

            if self.sniffer_thread and self.sniffer_thread.is_alive():
                logging.info("Stopping brute force monitoring thread...")
                self.sniffer.stop_monitoring()
                self.sniffer_thread.join(timeout=2)

            if self.sniffer.child_process:
                logging.info("Terminating any running subprocess...")
                try:
                    self.sniffer.child_process.terminate()
                    self.sniffer.child_process.wait(timeout=5)
                except Exception as e:
                    logging.error(f"Error terminating subprocess: {e}")
                finally:
                    self.sniffer.child_process = None

        except Exception as e:
            logging.error(f"Error during application shutdown: {e}")
        finally:
            self.destroy()
            os._exit(0)

    def stop_all_monitoring(self, monitor_type=None):
        """
        Stop the specified monitor. Either SYN or Process or Brute, if none then all.
        """
        if monitor_type == "SYN" or monitor_type is None:
            if self.syn_monitoring:
                self.stop_syn_monitor()

        if monitor_type == "Process" or monitor_type is None:
            if self.process_monitoring:
                self.stop_process_monitor()

        if monitor_type == "Brute Force" or monitor_type is None:
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer.stop_monitoring()
                self.sniffer_thread.join(timeout=1)
                self.sniffer_thread = None

    def monitor_processes(self):
        current_pid = os.getpid()
        while self.process_monitoring:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    if proc.info['pid'] == current_pid:
                        continue

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

    def update_chart_animation(self, frame):
        if self.syn_counts and self.times:
            self.line.set_data(self.times, self.syn_counts)
            self.ax.set_xlim(max(0, self.times[-1] - 20), self.times[-1] + 1)
            self.ax.set_ylim(0, max(self.syn_counts) + 10)
        self.canvas.draw()

    def alert_user(self):
        alert_label = tk.Label(self.syn_frame, text="ALERT: SYN packet threshold reached!", font=("Courier", 18), bg="#1E1E1E", fg="#FF4500")
        alert_label.pack(pady=20)


if __name__ == "__main__":
    app = MainWindow()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    app.mainloop()









# WinEvent Style - 'works' in perpetuity

# import os
# import signal
# import subprocess
# import logging
# import tkinter as tk
# from tkinter import ttk, messagebox
# from datetime import datetime
# from scapy.all import sniff, TCP, get_if_list, conf
# from scapy.layers.inet import IP
# import threading
# import psutil
# import re
# import matplotlib.pyplot as plt
# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# from matplotlib.animation import FuncAnimation
# import time
# import selectors
# import io
# import threading
# from typing import Set

# log_file_path = os.path.join(os.path.dirname(__file__), "ids_logfile.log")

# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s - %(levelname)s - %(message)s",
#     handlers=[logging.FileHandler(log_file_path), logging.StreamHandler()],
# )

# def signal_handler(sig, frame):
#     logging.info(f"Signal {sig} received. Initiating application shutdown...")
#     try:
#         if app:
#             app.close_application()
#         else:
#             logging.warning("Application instance not available. Exiting without cleanup.")
#     except Exception as e:
#         logging.error(f"Error during signal handling: {e}")
#     finally:
#         logging.info("Application exited.")
#         os._exit(0)

# signal.signal(signal.SIGINT, signal_handler)
# signal.signal(signal.SIGTERM, signal_handler)

# class Firewall:
#     def __init__(self):
#         self.blocked_ips = set()
#         self.whitelisted_ips = {"192.168.1.1", "127.0.0.1"}

#     def block_ip(self, ip):
#         if ip in self.whitelisted_ips or ip in self.blocked_ips:
#             logging.warning(f"Attempted to block whitelisted or already blocked IP: {ip}")
#             return
#         try:
#             subprocess.run(
#                 [
#                     "netsh",
#                     "advfirewall",
#                     "firewall",
#                     "add",
#                     "rule",
#                     f"name=Block_{ip}",
#                     "dir=in",
#                     "action=block",
#                     f"remoteip={ip}",
#                 ],
#                 check=True,
#             )
#             self.blocked_ips.add(ip)
#             logging.info(f"Blocked IP: {ip}")
#             app.refresh_blocked_ips()
#         except subprocess.CalledProcessError as e:
#             logging.error(f"Subprocess error while blocking IP {ip}: {e.stderr}")
#         except Exception as e:
#             logging.error(f"Unexpected error while blocking IP: {ip}: {e}")

#     def unblock_ip(self, ip):
#         if ip not in self.blocked_ips:
#             logging.warning(f"Attempted to unblock non-blocked IP: {ip}")
#             return
#         try:
#             subprocess.run(
#                 ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Block_{ip}"],
#                 check=True,
#             )
#             self.blocked_ips.discard(ip)
#             logging.info(f"Unblocked IP: {ip}")
#         except subprocess.CalledProcessError as e:
#             logging.error(f"Subprocess error while unblocking IP {ip}: {e.stderr}")
#         except Exception as e:
#             logging.error(f"Unexpected error while unblocking IP: {ip}: {e}")

# class Sniffer:
#     def __init__(self, firewall, alert_callback):
#         self.firewall = firewall
#         self.failed_attempts = {}
#         self.alert_threshold = 5
#         self.alert_callback = alert_callback
#         self.running = False
#         self.child_process = None
#         self.stop_event = threading.Event()
#         self.waiting_for_subprocess = False
#         self.sniffer_thread = None


#     def monitor_logs(self):
#         self.running = True
#         self.stop_event.clear()
#         self.monitor_event_logs()

#     def stop_monitoring(self):
#         self.running = False
#         self.stop_event.set()

#         if self.child_process:
#             try:
#                 logging.info("Sending CTRL+C to terminate the PowerShell process...")
#                 os.kill(self.child_process.pid, signal.CTRL_BREAK_EVENT)
#                 self.child_process.wait(timeout=5)
#                 logging.info("PowerShell process terminated successfully.")
#             except subprocess.TimeoutExpired:
#                 logging.warning("PowerShell process did not terminate in time. Killing it.")
#                 self.child_process.kill()
#             except Exception as e:
#                 logging.error(f"Error stopping PowerShell process: {e}")
#             finally:
#                 self.child_process = None
        
#         if self.sniffer_thread and self.sniffer_thread.is_alive():
#             self.sniffer_thread.join(timeout=2)

#         logging.info("Monitoring thread stopped.")

#     def _terminate_and_wait_for_subprocess(self, process):
#         if self.waiting_for_subprocess:
#             logging.warning("Subprocess cleanup already in progress. Skipping duplicate cleanup.")
#             return
        
#         self.waiting_for_subprocess = True
#         try:
#             self.child_process.terminate()
#             self.child_process.wait(timeout=5)
#             logging.info("Child process terminated successfully.")
#         except subprocess.TimeoutExpired:
#             logging.warning("Child process did not terminate in time. Killing it.")
#             self.child_process.kill()
#             self.child_process.wait()
#             logging.info("Child process forcefully killed.")
#         except Exception as e:
#             logging.error(f"Error waiting for child process termination: {e}")
#         finally:
#             if process == self.child_process:
#                 self.child_process = None
#             self.waiting_for_subprocess = False
#             self.alert_callback("Brute Force Monitor", "Brute Force Monitoring has stopped.")

#     def monitor_event_logs(self):
#         if self.child_process and self.child_process.poll() is None:
#             logging.warning("Brute force monitoring process is already running. Aborting restart.")
#             return
#         try:
#             command = [
#                 "powershell",
#                 "-Command",
#                 "Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4625 }",
#             ]
#             self.child_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
#             logging.info("Monitoring Windows Event Logs via Powershell...")

#             if not self.child_process.stdout:
#                 logging.error("Child process stdout is None. Monitoring cannot proceed.")
#                 return

#             self.stop_event.clear()
#             self.sniffer_thread = threading.Thread(target=self._consume_process_output, daemon=True)
#             self.sniffer_thread.start()

#         except Exception as e:
#             logging.error(f"Error starting event log monitoring: {e}")

#     def _consume_process_output(self):
#         try:
#             while not self.stop_event.is_set() and self.child_process:
#                 line = self.child_process.stdout.readline()
#                 if not line and not self.stop_event.is_set():
#                     time.sleep(0.1)
#                     continue

#                 if "Failure" in line:
#                     src_ip_match = re.search(r"Source Network Adress: (\d+\.\d+\.\d+\.\d+)", line)
#                     if src_ip_match:
#                         src_ip = src_ip_match.group(1)
#                         self.process_failed_attempt(src_ip)
#         except Exception as e:
#             logging.error(f"Error consuming process output: {e}")
#         finally:
#             logging.info("Stopped consuming process output.")

#     def process_failed_attempt(self, src_ip):
#         if src_ip in self.firewall.blocked_ips:
#             logging.info(f"IP {src_ip} is already blocked. Ignoring further attempts.")
#             return
#         self.failed_attempts[src_ip] = self.failed_attempts.get(src_ip, 0) + 1
#         attempt_count = self.failed_attempts[src_ip]
#         if attempt_count > self.alert_threshold:
#             self.firewall.block_ip(src_ip)
#             self.alert_callback(f"Blocked IP {src_ip} after {attempt_count} failed attempts.")
#             self.failed_attempts.pop(src_ip, None)
#             app.refresh_blocked_ips()

# class TextWidgetLogger(logging.Handler):
#     def __init__(self, text_widget):
#         super().__init__()
#         self.text_widget = text_widget
    
#     def emit(self, record):
#         log_entry = self.format(record)
#         self.text_widget.configure(state="normal")

#         if record.levelno == logging.INFO:
#             tag = "info"
#         elif record.levelno == logging.WARNING:
#             tag = "warning"
#         elif record.levelno == logging.ERROR:
#             tag = "error"
#         else:
#             tag = "default"

#         self.text_widget.insert(tk.END, log_entry + "\n")
#         self.text_widget.configure(state="disabled")
#         self.text_widget.yview(tk.END)

#         if record.levelno >= logging.ERROR:
#             self.text_widget.bell()


# def show_alert(title, message):
#     """
#     Display popup alert with information.
#     """
#     logging.info(f"ALERT: {title} - {message}")
#     messagebox.showinfo(title, message)

# def get_valid_interface():
#     """
#     Detects a valid network interface for sniffing.
#     Returns:
#         str: Name of a valid interface or None if no valid interface is found.
#     """
#     try:
#         interfaces = get_if_list()
#         logging.info(f"Available interfaces: {interfaces}")

#         #check the default interface first
#         default_interface = conf.iface
#         if default_interface in interfaces:
#             logging.info(f"Using default interface: {default_interface}")
#             show_alert("Adapter Selected", f"Using default network adapter: {default_interface}")
#             return default_interface

#         #test each interface
#         for iface in interfaces:
#             try:
#                 #test binding to the interface
#                 sniff(iface=iface, count=1, timeout=1, store=0)
#                 logging.info(f"Valid interface found: {iface}")
#                 show_alert("Adapter Selected", f"Valid network adapter selected: {iface}")
#                 return iface
#             except Exception as e:
#                 logging.error(f"Interface {iface} is not valid: {e}")

#         logging.error("No valid interface found.")
#         show_alert("No Valid Adapter", "No valid adapter could be found.")
#         return None
#     except Exception as e:
#         logging.error(f"Error detecting network interfaces: {e}")
#         return None

# class MainWindow(tk.Tk):
#     def __init__(self):
#         super().__init__()
#         self.title("Intrusion Detection System")
#         self.geometry("1280x800")
#         self.configure(bg="#1E1E1E")

#         self.main_frame = tk.Frame(self, bg="#1E1E1E")
#         self.main_frame.pack(fill="both", expand=True)

#         self.left_frame = tk.Frame(self.main_frame, bg="#1E1E1E")
#         self.center_frame = tk.Frame(self.main_frame, bg="#1E1E1E")
#         self.right_frame = tk.Frame(self.main_frame, bg="#2E2E2E", width=300)

#         self.show_logs = tk.BooleanVar(value=False)
#         self.log_widget = None
#         self.log_handler = None

#         self.radio_var = tk.StringVar()
#         self.syn_threshold = tk.IntVar()
#         self.ports_to_monitor = tk.StringVar()
#         self.cpu_threshold = tk.DoubleVar()
#         self.memory_threshold = tk.DoubleVar()

#         self.syn_count = 0
#         self.syn_monitoring = False
#         self.process_monitoring = False
#         self.sniff_thread = None
#         self.process_monitoring_thread = None

#         self.firewall = Firewall()
#         self.sniffer_thread = None
#         self.sniffer = Sniffer(self.firewall, self.show_alert)

#         self.blocked_ips = set()
#         self.ip_count = {}

#         self.protocol("WM_DELETE_WINDOW", self.close_application)

#         self.setup_log_viewer()
#         self.create_tabs()
#         self.update_layout()

#     def setup_log_viewer(self):
#         """
#         Sets up log viewer and integrates with logging system.
#         """
#         tk.Label(
#             self.right_frame, text="Logs", font=("Courier", 18), bg="#2E2E2E", fg="#00FF00"
#         ).pack(pady=5)

#         self.log_widget = tk.Text(
#             self.right_frame, height=30, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12)
#         )
#         self.log_widget.pack(fill="both", expand=True, padx=10, pady=5)
#         self.log_widget.configure(state="disabled")

#         self.log_widget.tag_configure("info", foreground="#00FF00")
#         self.log_widget.tag_configure("warning", foreground="#FFA500")
#         self.log_widget.tag_configure("error", foreground="#FF4500")
#         self.log_widget.tag_configure("default", foreground="#FFFFFF")

#         self.log_handler = TextWidgetLogger(self.log_widget)
#         self.log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
#         logging.getLogger().addHandler(self.log_handler)

#     def toggle_log_viewer(self):
#         """
#         Toggle for log view, dynamically fits the window rsolution.
#         """
#         self.update_layout()

#     def update_layout(self):
#         """
#         Dynamically update the layout based on the checkbox.
#         """
#         if self.show_logs.get():
#             self.center_frame.pack_forget()
#             self.left_frame.pack(side="left", fill="both", expand=True)
#             self.notebook.pack_forget()
#             self.notebook.pack(in_=self.left_frame, pady=10, expand=True, fill="both")
#             self.right_frame.pack(side="right", fill="y")
#         else:
#             self.left_frame.pack_forget()
#             self.right_frame.pack_forget()
#             self.center_frame.pack(fill="both", expand=True)
#             self.notebook.pack_forget()
#             self.notebook.pack(in_=self.center_frame, pady=120, expand=True, fill="both")

#     def create_tabs(self):
#         self.notebook = ttk.Notebook(self)
#         self.notebook.pack(pady=10, expand=True)

#         self.syn_frame = tk.Frame(self.notebook, bg="#1E1E1E")
#         self.process_monitor_frame = tk.Frame(self.notebook, bg="#1E1E1E")
#         self.brute_force_frame = tk.Frame(self.notebook, bg="#1E1E1E")

#         self.notebook.add(self.syn_frame, text="SYN Monitor")
#         self.notebook.add(self.process_monitor_frame, text="Process Monitor")
#         self.notebook.add(self.brute_force_frame, text="Brute Force Monitor")

#         self.create_syn_widgets(self.syn_frame)
#         self.create_process_monitor_widgets(self.process_monitor_frame)
#         self.create_brute_force_widgets(self.brute_force_frame)

#     def add_log_checkbox(self, frame):
#         """
#         Adding the 'show logs' checkbox to each tab.
#         """
#         log_checkbox = tk.Checkbutton(
#             frame,
#             text="Show Logs",
#             variable=self.show_logs,
#             command=self.toggle_log_viewer,
#             bg="#1E1E1E",
#             fg="#00FF00",
#             font=("Courier", 12),
#             activebackground="#1E1E1E",
#             activeforeground="#00FF00",
#             selectcolor="#333333"
#         )
#         log_checkbox.pack(anchor="center", pady=5)

#     def create_syn_widgets(self, frame):
#         header = tk.Label(frame, text="SYN Packet Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
#         header.pack(pady=10)

#         parameters_frame = tk.Frame(frame, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
#         parameters_frame.pack(pady=10, padx=10, fill=tk.X)

#         tk.Label(parameters_frame, text="SYN Packet Threshold:", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
#         self.syn_threshold_entry = tk.Entry(parameters_frame, textvariable=self.syn_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.syn_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
#         self.syn_threshold.set(100)

#         tk.Label(parameters_frame, text="Ports to Monitor (comma-separated):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
#         self.ports_entry = tk.Entry(parameters_frame, textvariable=self.ports_to_monitor, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.ports_entry.grid(row=1, column=1, padx=5, pady=5)
#         self.ports_to_monitor.set("80,443")

#         control_frame = tk.Frame(frame, bg="#1E1E1E")
#         control_frame.pack(pady=10)

#         start_button = tk.Button(control_frame, text="Start SYN Monitoring", bg="#333333", fg="#00FF00", command=self.start_syn_monitor, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
#         start_button.grid(row=0, column=0, padx=5)

#         stop_button = tk.Button(control_frame, text="Stop SYN Monitoring", bg="#333333", fg="#FF4500", command=self.stop_syn_monitor, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
#         stop_button.grid(row=0, column=1, padx=5)

#         view_blocked_ips_button = tk.Button(
#             frame,
#             text="View Blocked IPs",
#             bg="#333333",
#             fg="#00FF00",
#             command=self.view_blocked_ips,
#             font=("Courier", 12),
#             activebackground="#00FF00",
#             activeforeground="#1E1E1E"
#         )
#         view_blocked_ips_button.pack(pady=10)

#         self.add_log_checkbox(frame)

#         self.create_charts(frame)

#     def create_process_monitor_widgets(self, frame):
#         header = tk.Label(frame, text="Process Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
#         header.pack(pady=10)

#         parameters_frame = tk.Frame(frame, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
#         parameters_frame.pack(pady=10, padx=10, fill=tk.X)

#         tk.Label(parameters_frame, text="CPU Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
#         self.cpu_threshold_entry = tk.Entry(parameters_frame, textvariable=self.cpu_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.cpu_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
#         self.cpu_threshold.set(80.0)

#         tk.Label(parameters_frame, text="Memory Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
#         self.memory_threshold_entry = tk.Entry(parameters_frame, textvariable=self.memory_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.memory_threshold_entry.grid(row=1, column=1, padx=5, pady=5)
#         self.memory_threshold.set(80.0)

#         control_frame = tk.Frame(frame, bg="#1E1E1E")
#         control_frame.pack(pady=10)

#         start_button = tk.Button(control_frame, text="Start Process Monitoring", bg="#333333", fg="#00FF00", command=self.start_process_monitor, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
#         start_button.grid(row=0, column=0, padx=5)

#         stop_button = tk.Button(control_frame, text="Stop Process Monitoring", bg="#333333", fg="#FF4500", command=self.stop_process_monitor, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
#         stop_button.grid(row=0, column=1, padx=5)

#         self.process_alert_label = tk.Label(frame, text="", font=("Courier", 14), bg="#1E1E1E", fg="#FF4500")
#         self.process_alert_label.pack(pady=10)

#         self.add_log_checkbox(frame)

#     def create_brute_force_widgets(self, frame):
#         header = tk.Label(frame, text="Brute Force Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
#         header.pack(pady=10)

#         self.brute_force_status = tk.Label(frame, text="Status: Stopped", font=("Courier", 14), bg="#1E1E1E", fg="#FF4500")
#         self.brute_force_status.pack(pady=10)

#         start_button = tk.Button(frame, text="Start Brute Force Monitoring", bg="#333333", fg="#00FF00", font=("Courier", 12), command=self.start_brute_force_monitor)
#         start_button.pack(pady=5)

#         stop_button = tk.Button(frame, text="Stop Brute Force Monitoring", bg="#333333", fg="#FF4500", command=self.stop_brute_force_monitor, font=("Courier", 12))
#         stop_button.pack(pady=5)

#         self.blocked_ips_listbox = tk.Listbox(frame, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12), width=50, height=15)
#         self.blocked_ips_listbox.pack(pady=10)

#         refresh_button = tk.Button(frame, text="Refresh Blocked IP(s)", bg="#333333", fg="#00FF00", font=("Courier", 12), command=self.refresh_blocked_ips)
#         refresh_button.pack(pady=5)

#         view_blocked_ips_button = tk.Button(
#             frame,
#             text="View Blocked IPs",
#             bg="#333333",
#             fg="#00FF00",
#             command=self.view_blocked_ips,
#             font=("Courier", 12),
#             activebackground="#00FF00",
#             activeforeground="#1E1E1E"
#         )
#         view_blocked_ips_button.pack(pady=10)

#         self.add_log_checkbox(frame)

#     def start_brute_force_monitor(self):
#         if self.sniffer_thread and self.sniffer_thread.is_alive():
#             self.show_alert("Error", "Brute Force Monitor is already running.")
#             return
        
#         if self.sniffer.child_process and self.sniffer.child_process.poll() is None:
#             logging.warning("Previous monitoring process is still running. Terminating it.")
#             self.sniffer.stop_monitoring()

#         self.sniffer_thread = threading.Thread(target=self.sniffer.monitor_logs, daemon=True)
#         self.sniffer_thread.start()
#         self.brute_force_status.config(text="Status: Running", fg="#00FF00")
#         self.show_alert("Brute Force Monitor", "Brute Force Monitoring has started.")

#     def stop_brute_force_monitor(self):
#         if self.sniffer_thread and self.sniffer_thread.is_alive():
#             logging.info("Stopping brute force monitoring thread...")

#             self.sniffer.stop_monitoring()
#             self.sniffer_thread.join(timeout=2)
#             self.sniffer_thread = None

#         self.brute_force_status.config(text="Status: Stopped", fg="#FF4500")
#         self.show_alert("Brute Force Monitor", "Brute Force Monitoring has stopped.")
#         logging.info(f"Thread state: {threading.enumerate()}")

#     def refresh_blocked_ips(self):
#         self.blocked_ips_listbox.delete(0, tk.END)
#         blocked_ips = self.firewall.get_blocked_ips()
#         for ip in blocked_ips:
#             self.blocked_ips_listbox.insert(tk.END, ip)

#     def show_alert(self, title, message):
#         logging.info(f"ALERT: {title} - {message}")
#         messagebox.showinfo(title, message)

#     def create_charts(self, frame):
#         chart_frame = tk.Frame(frame, bg="#1E1E1E")
#         chart_frame.pack(pady=10, fill=tk.BOTH, expand=True)

#         self.fig, self.ax = plt.subplots(facecolor="#1E1E1E")
#         self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
#         self.canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

#         self.ax.set_title('SYN Packets Count', color="#00FF00")
#         self.ax.set_xlabel('Time', color="#00FF00")
#         self.ax.set_ylabel('SYN Packets', color="#00FF00")
#         self.ax.tick_params(axis='x', colors='#00FF00')
#         self.ax.tick_params(axis='y', colors='#00FF00')
#         self.ax.spines['bottom'].set_color('#00FF00')
#         self.ax.spines['top'].set_color('#00FF00')
#         self.ax.spines['right'].set_color('#00FF00')
#         self.ax.spines['left'].set_color('#00FF00')

#         self.times = []
#         self.syn_counts = []

#         self.line, = self.ax.plot([], [], color="#00FF00")

#         self.anim = FuncAnimation(self.fig, self.update_chart_animation, interval=1000)

#     def start_syn_monitor(self):
#         self.syn_monitoring = True
#         self.syn_count = 0
#         self.monitor_ports = [int(port.strip()) for port in self.ports_to_monitor.get().split(",") if port.strip().isdigit()] or [80, 443]
#         logging.info(f"Monitoring SYN packets on ports: {self.monitor_ports} with threshold {self.syn_threshold.get()}")
#         show_alert("SYN Monitoring Started", f"Monitoring started on ports: {self.monitor_ports} with threshold: {self.syn_threshold.get()}")

#         self.sniff_thread = threading.Thread(target=self.sniff_packets)
#         self.sniff_thread.daemon = True
#         self.sniff_thread.start()

#     def sniff_packets(self):
#         interface = get_valid_interface()
#         if not interface:
#             logging.error("No valid network interface available for sniffing.")
#             return

#         logging.info(f"Sniffing on interface: {interface}")
#         try:
#             sniff(iface=interface, prn=self.process_packet, store=0, stop_filter=lambda x: not self.syn_monitoring)
#         except Exception as e:
#             logging.error(f"Error in sniffing thread: {e}")

#     def process_packet(self, packet):
#         try:
#             if packet.haslayer(TCP) and packet.haslayer(IP):
#                 src_ip = packet[IP].src
#                 if packet[TCP].flags == 'S' and packet[TCP].dport in self.monitor_ports:
#                     self.syn_count += 1
#                     logging.info(f"SYN packet detected from {src_ip} on port {packet[TCP].dport}. Total SYN count: {self.syn_count}")

#                     self.times.append(len(self.times))
#                     self.syn_counts.append(self.syn_count)

#                     if src_ip not in self.blocked_ips:
#                         self.ip_count[src_ip] = self.ip_count.get(src_ip, 0) + 1

#                         if self.ip_count[src_ip] >= self.syn_threshold.get():
#                             logging.info(f"SYN packet threshold reached for IP {src_ip}! Blocking...")
#                             self.block_ip(src_ip)
#                             self.blocked_ips.add(src_ip)
#                             app.refresh_blocked_ips()
#                             show_alert("SYN Threshold Reached", f"SYN packet threshold reached for IP: {src_ip}. This IP is now blocked.")
#         except Exception as e:
#             logging.error(f"Error processing packet: {e}")
#             logging.debug(f"Packet summary: {packet.summary()}")

#     def block_ip(self, ip):
#         self.firewall.block_ip(ip)

#     def unblock_ip(self, ip):
#         self.firewall.unblock_ip(ip)

#     def view_blocked_ips(self):
#         unblock_window = tk.Toplevel(self)
#         unblock_window.title("Blocked IPs")
#         unblock_window.geometry("600x500")
#         unblock_window.configure(bg="#1E1E1E")
#         unblock_window.pack_propagate(False)

#         tk.Label(unblock_window, text="Blocked IPs", font=("Courier", 18), bg="#1E1E1E", fg="#00FF00").pack(pady=10)

#         listbox_frame = tk.Frame(unblock_window, bg="#1E1E1E")
#         listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

#         scrollbar = tk.Scrollbar(listbox_frame)
#         scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

#         listbox = tk.Listbox(
#             listbox_frame, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12), selectmode=tk.SINGLE, width=50, height=15, yscrollcommand=scrollbar.set
#         )
#         listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
#         scrollbar.config(command=listbox.yview)

#         blocked_ips = self.firewall.get_blocked_ips()
#         for ip in blocked_ips:
#             listbox.insert(tk.END, ip)

#         def unblock_selected():
#             """
#             Unblock the selected IP from the listbox.
#             """
#             selected_ip = listbox.get(tk.ACTIVE)
#             if selected_ip:
#                 def unblock_task():
#                     self.firewall.unblock_ip(selected_ip)
#                     messagebox.showinfo("Success", f"IP {selected_ip} unblocked successfully.")
#                     refresh_listbox()

#                 threading.Thread(target=unblock_task, daemon=True).start()

#         def refresh_listbox():
#             """
#             Refresh the listbox to display the updated list of blocked IPs.
#             """
#             listbox.delete(0, tk.END)
#             updated_blocked_ips = self.firewall.get_blocked_ips()
#             for ip in updated_blocked_ips:
#                 listbox.insert(tk.END, ip)

#         unblock_button = tk.Button(
#             unblock_window,
#             text="Unblock Selected",
#             bg="#333333",
#             fg="#FF4500",
#             command=unblock_selected,
#             font=("Courier", 12),
#             activebackground="#FF4500",
#             activeforeground="#1E1E1E",
#         )
#         unblock_button.pack(pady=10, fill=tk.X, expand=True)

#     def create_blocked_ips_widgets(self, frame):
#         header = tk.Label(frame, text="Blocked IPs", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
#         header.pack(pady=10)

#         self.blocked_ips_listbox = tk.Listbox(frame, bg="#2E2E2E", fg="#00FF00", font=("Courier", 12), width=50, height=15)
#         self.blocked_ips_listbox.pack(pady=10)

#         unblock_button = tk.Button(frame, text="Unblock Selected IP", bg="#333333", fg="#FF4500", command=self.unblock_ip, font=("Courier", 12))
#         unblock_button.pack(pady=10)

#         self.add_log_checkbox(frame)

#     def start_process_monitor(self):
#         self.process_monitoring = True
#         logging.info(f"Starting process monitoring. CPU threshold: {self.cpu_threshold.get()}%, "f"Memory threshold: {self.memory_threshold.get()}%")
#         show_alert("Process Monitoring Started", f"Process monitoring started with CPU threshold: {self.cpu_threshold.get()}% and Memory Threshold: {self.memory_threshold.get()}%.")

#         self.process_monitoring_thread = threading.Thread(target=self.monitor_processes)
#         self.process_monitoring_thread.daemon = True
#         self.process_monitoring_thread.start()

#     def stop_syn_monitor(self):
#         self.syn_monitoring = False
#         if self.sniff_thread and self.sniff_thread.is_alive():
#             self.sniff_thread.join(timeout=1)
#             self.sniff_thread = None
#         logging.info("Stopped SYN monitoring.")
#         show_alert("SYN Monitoring Stopped", "SYN monitoring has been stopped.")

#     def stop_process_monitor(self):
#         self.process_monitoring = False
#         if self.process_monitoring_thread and self.process_monitoring_thread.is_alive():
#             self.process_monitoring_thread.join(timeout=1)
#             self.process_monitoring_thread = None
#         logging.info("Stopped Process monitoring.")
#         show_alert("Process Monitoring Stopped", "Process monitoring has been stopped.")

#     def close_application(self):
#         """Gracefully close the application by stopping threads and destroying the window."""
#         logging.info("Closing application...")

#         try:
#             if self.sniff_thread and self.sniff_thread.is_alive():
#                 logging.info("Stopped sniffer thread...")
#                 self.syn_monitoring = False
#                 self.sniff_thread.join(timeout=1)

#             if self.process_monitoring_thread and self.process_monitoring_thread.is_alive():
#                 logging.info("Stopping process monitoring thread...")
#                 self.process_monitoring = False
#                 self.process_monitoring_thread.join(timeout=1)

#             if self.sniffer.child_process:
#                 logging.info("Terminating any running subprocess...")
#                 self.sniffer.stop_monitoring()
#         except Exception as e:
#             logging.error(f"Error during application shutdown: {e}")
#         finally:
#             self.destroy()

#     def stop_all_monitoring(self, monitor_type=None):
#         """
#         Stop the specified monitor. Either SYN or Process or Brute, if none then all.
#         """
#         if monitor_type == "SYN" or monitor_type is None:
#             if self.syn_monitoring:
#                 self.stop_syn_monitor()

#         if monitor_type == "Process" or monitor_type is None:
#             if self.process_monitoring:
#                 self.stop_process_monitor()

#         if monitor_type == "Brute Force" or monitor_type is None:
#             if self.sniffer_thread and self.sniffer_thread.is_alive():
#                 self.sniffer.stop_monitoring()
#                 self.sniffer_thread.join(timeout=1)
#                 self.sniffer_thread = None

#     def monitor_processes(self):
#         current_pid = os.getpid()
#         while self.process_monitoring:
#             for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
#                 try:
#                     if proc.info['pid'] == current_pid:
#                         continue

#                     cpu_usage = proc.info['cpu_percent']
#                     memory_usage = proc.info['memory_percent']

#                     if cpu_usage > self.cpu_threshold.get() or memory_usage > self.memory_threshold.get():
#                         logging.info(f"Killing process {proc.info['name']} (PID: {proc.info['pid']}) for exceeding thresholds. CPU: {cpu_usage}%, Memory: {memory_usage}%")
#                         show_alert(
#                             "Process Killed",
#                             f"Process '{proc.info['name']}' (PID: {proc.info['pid']}) exceeded set threshold.\n"
#                             f"CPU Usage: {cpu_usage}%\nMemory Usage: {memory_usage}%. This process has been killed."
#                         )
#                         proc.terminate()

#                 except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#                     pass

#             time.sleep(5)

#     def update_chart(self):
#         self.times.append(len(self.times))
#         self.syn_counts.append(self.syn_count)
#         self.ax.clear()
#         self.ax.set_title('SYN Packets Count', color="#00FF00")
#         self.ax.set_xlabel('Time', color="#00FF00")
#         self.ax.set_ylabel('SYN Packets', color="#00FF00")
#         self.ax.plot(self.times, self.syn_counts, color="#00FF00")
#         self.canvas.draw()

#     def update_chart_animation(self, frame):
#         if self.syn_counts and self.times:
#             self.line.set_data(self.times, self.syn_counts)
#             self.ax.set_xlim(max(0, self.times[-1] - 20), self.times[-1] + 1)
#             self.ax.set_ylim(0, max(self.syn_counts) + 10)
#         self.canvas.draw()

#     def alert_user(self):
#         alert_label = tk.Label(self.syn_frame, text="ALERT: SYN packet threshold reached!", font=("Courier", 18), bg="#1E1E1E", fg="#FF4500")
#         alert_label.pack(pady=20)


# if __name__ == "__main__":
#     app = MainWindow()
#     signal.signal(signal.SIGINT, signal_handler)
#     signal.signal(signal.SIGTERM, signal_handler)
#     app.mainloop()