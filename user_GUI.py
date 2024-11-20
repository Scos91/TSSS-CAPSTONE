# OLDER VERSION - CURRENTLY WORKING #

# VERSION 3 #

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, TCP
import threading
import psutil 
import time

#define the main GUI window class
class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__() #initialize the parent class (tk.Tk)
        self.title("Intrusion Detection System") #set the window title
        self.geometry("800x680") #set the initial size of the window
        self.configure(bg="#1E1E1E") #set the background color of the window

        #initialize variables for GUI elements
        self.radio_var = tk.StringVar() #variable for holding selected radio button value
        self.syn_threshold = tk.IntVar() #variable for SYN packet threshold
        self.ports_to_monitor = tk.StringVar() #variable for ports to monitor
        self.cpu_threshold = tk.DoubleVar() #variable for CPU usage threshold
        self.memory_threshold = tk.DoubleVar() #variable for memory usage threshold

        #initialize monitoring state and counters
        self.syn_count = 0 #counter for detected SYN packets
        self.monitoring = False #flag to indicate whether monitoring is active
        self.sniff_thread = None #initialize thread for sniffing
        self.process_monitoring_thread = None #initialize thread for process monitoring

        #create the tabbed interface
        self.create_tabs()

    def create_process_monitor_widgets(self, frame):
        header = tk.Label(frame, text="Process Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        # Add widgets for displaying process information
        parameters_frame = tk.Frame(frame, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
        parameters_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(parameters_frame, text="CPU Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.cpu_threshold_entry = tk.Entry(parameters_frame, textvariable=self.cpu_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.cpu_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
        self.cpu_threshold.set(80.0)  # Default CPU threshold

        tk.Label(parameters_frame, text="Memory Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.memory_threshold_entry = tk.Entry(parameters_frame, textvariable=self.memory_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.memory_threshold_entry.grid(row=1, column=1, padx=5, pady=5)
        self.memory_threshold.set(80.0)  # Default memory threshold

        # Add a start/stop button for process monitoring
        control_frame = tk.Frame(frame, bg="#1E1E1E")
        control_frame.pack(pady=10)

        start_button = tk.Button(control_frame, text="Start Process Monitoring", bg="#333333", fg="#00FF00", command=self.start_monitoring, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
        start_button.grid(row=0, column=0, padx=5)

        stop_button = tk.Button(control_frame, text="Stop Process Monitoring", bg="#333333", fg="#FF4500", command=self.stop_monitoring, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
        stop_button.grid(row=0, column=1, padx=5)

        # Add a placeholder for displaying flagged processes
        self.process_alert_label = tk.Label(frame, text="", font=("Courier", 14), bg="#1E1E1E", fg="#FF4500")
        self.process_alert_label.pack(pady=10)

    #method to create tabs in the GUI
    def create_tabs(self):
        #create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, expand=True)

        #create frames for each tab
        self.hids_frame = tk.Frame(self.notebook, bg="#1E1E1E")
        self.nids_frame = tk.Frame(self.notebook, bg="#1E1E1E")
        self.custom_frame = tk.Frame(self.notebook, bg="#1E1E1E")
        self.process_monitor_frame = tk.Frame(self.notebook, bg="#1E1E1E")

        #add frames to notebook (tabs)
        self.notebook.add(self.hids_frame, text="HIDS")
        self.notebook.add(self.nids_frame, text="NIDS")
        self.notebook.add(self.custom_frame, text="Custom")
        self.notebook.add(self.process_monitor_frame, text="Process Monitor")

        #create widgets for each tab
        self.create_hids_widgets(self.hids_frame)
        self.create_nids_widgets(self.nids_frame)
        self.create_custom_widgets(self.custom_frame)
        self.create_process_monitor_widgets(self.process_monitor_frame)

    #method to create widgets for the HIDS tab
    def create_hids_widgets(self, frame):
        header = tk.Label(frame, text="HIDS - SYN Packet Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        parameters_frame = tk.Frame(frame, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
        parameters_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(parameters_frame, text="SYN Packet Threshold:", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.syn_threshold_entry = tk.Entry(parameters_frame, textvariable=self.syn_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.syn_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
        self.syn_threshold.set(100) #set default threshold value

        tk.Label(parameters_frame, text="Ports to Monitor (comma-separated):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ports_entry = tk.Entry(parameters_frame, textvariable=self.ports_to_monitor, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5)
        self.ports_to_monitor.set("80,443") #set default ports to monitor

        #add input fields for CPU and memory usage thresholds
        tk.Label(parameters_frame, text="CPU Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.cpu_threshold_entry = tk.Entry(parameters_frame, textvariable=self.cpu_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.cpu_threshold_entry.grid(row=2, column=1, padx=5, pady=5)
        self.cpu_threshold.set(80.0) #default CPU threshold

        tk.Label(parameters_frame, text="Memory Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.memory_threshold_entry = tk.Entry(parameters_frame, textvariable=self.memory_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.memory_threshold_entry.grid(row=3, column=1, padx=5, pady=5)
        self.memory_threshold.set(80.0) #default memory threshold

        control_frame = tk.Frame(frame, bg="#1E1E1E")
        control_frame.pack(pady=10)

        start_button = tk.Button(control_frame, text="Start Monitoring", bg="#333333", fg="#00FF00", command=self.start_monitoring, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
        start_button.grid(row=0, column=0, padx=5)

        stop_button = tk.Button(control_frame, text="Stop Monitoring", bg="#333333", fg="#FF4500", command=self.stop_monitoring, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
        stop_button.grid(row=0, column=1, padx=5)

        self.create_charts(frame)

    #method to create widgets for the NIDS tab
    def create_nids_widgets(self, frame):
        header = tk.Label(frame, text="NIDS - Network Intrusion Detection", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        #add more NIDS-specific input fields and controls here

    #method to create widgets for the Custom tab
    def create_custom_widgets(self, frame):
        header = tk.Label(frame, text="Custom Mode", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack(pady=10)

        #add more custom mode input fields and controls here

    #method to create charts for displaying SYN packet counts
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

    #method to start monitoring SYN packets and process usage
    def start_monitoring(self):
        self.monitoring = True
        self.syn_count = 0
        self.monitor_ports = [int(port.strip()) for port in self.ports_to_monitor.get().split(",") if port.strip().isdigit()]
        print(f"Monitoring SYN packets on ports: {self.monitor_ports} with threshold {self.syn_threshold.get()}")
        
        #start packet sniffing in a new thread
        self.sniff_thread = threading.Thread(target=self.start_packet_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

        #start process monitoring in a new thread
        self.process_monitoring_thread = threading.Thread(target=self.monitor_processes)
        self.process_monitoring_thread.daemon = True
        self.process_monitoring_thread.start()

    #method to stop monitoring SYN packets and processes
    def stop_monitoring(self):
        self.monitoring = False
        print("Stopped monitoring.")

    #method to start sniffing network packets using Scapy
    def start_packet_sniffing(self):
        def process_packet(packet):
            if not self.monitoring:
                return False

            if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet[TCP].dport in self.monitor_ports:
                self.syn_count += 1
                print(f"SYN packet detected on port {packet[TCP].dport}. Total SYN count: {self.syn_count}")
                self.update_chart()

                if self.syn_count >= self.syn_threshold.get():
                    print("SYN packet threshold reached!")
                    self.alert_user()
                    self.stop_monitoring()

        # Run sniff in a separate thread
        def sniff_packets():
            sniff(prn=process_packet, store=0, stop_filter=lambda x: not self.monitoring)

        sniff_thread = threading.Thread(target=sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()

    #method to monitor system processes and kill those over threshold
    def monitor_processes(self):
        while self.monitoring:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    cpu_usage = proc.info['cpu_percent']
                    memory_usage = proc.info['memory_percent']

                    if cpu_usage > self.cpu_threshold.get() or memory_usage > self.memory_threshold.get():
                        print(f"Killing process {proc.info['name']} (PID: {proc.info['pid']}) for exceeding thresholds. CPU: {cpu_usage}%, Memory: {memory_usage}%")
                        proc.terminate() #terminate the process

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            time.sleep(5) #check processes every 5 seconds

    #method to update the chart with new data
    def update_chart(self):
        self.times.append(len(self.times))
        self.syn_counts.append(self.syn_count)
        self.ax.clear()
        self.ax.set_title('SYN Packets Count', color="#00FF00")
        self.ax.set_xlabel('Time', color="#00FF00")
        self.ax.set_ylabel('SYN Packets', color="#00FF00")
        self.ax.plot(self.times, self.syn_counts, color="#00FF00")
        self.canvas.draw()

    #method to update the chart dynamically using animation
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

    #method to display an alert when SYN packet threshold is reached
    def alert_user(self):
        alert_label = tk.Label(self.hids_frame, text="ALERT: SYN packet threshold reached!", font=("Courier", 18), bg="#1E1E1E", fg="#FF4500")
        alert_label.pack(pady=20)

#entry point of the program
if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()




# LATEST AND UNTESTED  - includes process monitor capabilities #

# VERSION 4 #

# import tkinter as tk
# from tkinter import ttk, messagebox
# import matplotlib.pyplot as plt
# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# from matplotlib.animation import FuncAnimation
# import threading
# import psutil
# import time

# #define the main GUI window class
# class MainWindow(tk.Tk):
#     def __init__(self):
#         super().__init__() #initialize the parent class (tk.Tk)
#         self.title("Intrusion Detection System") #set the window title
#         self.geometry("800x680") #set the initial size of the window
#         self.configure(bg="#1E1E1E") #set the background color of the window

#         #initialize variables for GUI elements
#         self.radio_var = tk.StringVar() #variable for holding selected radio button value
#         self.syn_threshold = tk.IntVar() #variable for SYN packet threshold
#         self.ports_to_monitor = tk.StringVar() #variable for ports to monitor
#         self.cpu_threshold = tk.DoubleVar() #variable for CPU usage threshold
#         self.memory_threshold = tk.DoubleVar() #variable for memory usage threshold

#         #initialize monitoring state and counters
#         self.syn_count = 0 #counter for detected SYN packets
#         self.monitoring = False #flag to indicate whether monitoring is active
#         self.sniff_thread = None #initialize thread for sniffing
#         self.process_monitoring_thread = None #initialize thread for process monitoring

#         #create the tabbed interface
#         self.create_tabs()

#     #method to create tabs in the GUI
#     def create_tabs(self):
#         #create a notebook (tabbed interface)
#         self.notebook = ttk.Notebook(self)
#         self.notebook.pack(pady=10, expand=True)

#         #create frames for each tab
#         self.hids_frame = tk.Frame(self.notebook, bg="#1E1E1E")
#         self.nids_frame = tk.Frame(self.notebook, bg="#1E1E1E")
#         self.custom_frame = tk.Frame(self.notebook, bg="#1E1E1E")
#         self.process_monitor_frame = tk.Frame(self.notebook, bg="#1E1E1E")  # New Process Monitor Tab

#         #add frames to notebook (tabs)
#         self.notebook.add(self.hids_frame, text="HIDS")
#         self.notebook.add(self.nids_frame, text="NIDS")
#         self.notebook.add(self.custom_frame, text="Custom")
#         self.notebook.add(self.process_monitor_frame, text="Process Monitor")  # Add new tab

#         #create widgets for each tab
#         self.create_hids_widgets(self.hids_frame)
#         self.create_nids_widgets(self.nids_frame)
#         self.create_custom_widgets(self.custom_frame)
#         self.create_process_monitor_widgets(self.process_monitor_frame)  # Create Process Monitor tab widgets

#     #method to create widgets for the HIDS tab
#     def create_hids_widgets(self, frame):
#         header = tk.Label(frame, text="HIDS - SYN Packet Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
#         header.pack(pady=10)

#         parameters_frame = tk.Frame(frame, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
#         parameters_frame.pack(pady=10, padx=10, fill=tk.X)

#         tk.Label(parameters_frame, text="SYN Packet Threshold:", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
#         self.syn_threshold_entry = tk.Entry(parameters_frame, textvariable=self.syn_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.syn_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
#         self.syn_threshold.set(100) #set default threshold value

#         tk.Label(parameters_frame, text="Ports to Monitor (comma-separated):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
#         self.ports_entry = tk.Entry(parameters_frame, textvariable=self.ports_to_monitor, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.ports_entry.grid(row=1, column=1, padx=5, pady=5)
#         self.ports_to_monitor.set("80,443") #set default ports to monitor

#         control_frame = tk.Frame(frame, bg="#1E1E1E")
#         control_frame.pack(pady=10)

#         start_button = tk.Button(control_frame, text="Start Monitoring", bg="#333333", fg="#00FF00", command=self.start_monitoring, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
#         start_button.grid(row=0, column=0, padx=5)

#         stop_button = tk.Button(control_frame, text="Stop Monitoring", bg="#333333", fg="#FF4500", command=self.stop_monitoring, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
#         stop_button.grid(row=0, column=1, padx=5)

#         self.create_charts(frame)

#     #method to create widgets for the Process Monitor tab
#     def create_process_monitor_widgets(self, frame):
#         header = tk.Label(frame, text="Process Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
#         header.pack(pady=10)

#         parameters_frame = tk.Frame(frame, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
#         parameters_frame.pack(pady=10, padx=10, fill=tk.X)

#         # CPU Usage Threshold input
#         tk.Label(parameters_frame, text="CPU Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
#         self.cpu_threshold_entry = tk.Entry(parameters_frame, textvariable=self.cpu_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.cpu_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
#         self.cpu_threshold.set(80.0) #default CPU threshold

#         # Memory Usage Threshold input
#         tk.Label(parameters_frame, text="Memory Usage Threshold (%):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
#         self.memory_threshold_entry = tk.Entry(parameters_frame, textvariable=self.memory_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.memory_threshold_entry.grid(row=1, column=1, padx=5, pady=5)
#         self.memory_threshold.set(80.0) #default memory threshold

#         control_frame = tk.Frame(frame, bg="#1E1E1E")
#         control_frame.pack(pady=10)

#         # Start monitoring button
#         start_button = tk.Button(control_frame, text="Start Process Monitoring", bg="#333333", fg="#00FF00", command=self.start_process_monitoring, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
#         start_button.grid(row=0, column=0, padx=5)

#         stop_button = tk.Button(control_frame, text="Stop Process Monitoring", bg="#333333", fg="#FF4500", command=self.stop_monitoring, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
#         stop_button.grid(row=0, column=1, padx=5)

#     #method to start process monitoring
#     def start_process_monitoring(self):
#         self.monitoring = True
#         self.process_monitoring_thread = threading.Thread(target=self.monitor_processes)
#         self.process_monitoring_thread.daemon = True
#         self.process_monitoring_thread.start()

#     #method to monitor system processes and alert user when threshold exceeded
#     def monitor_processes(self):
#         while self.monitoring:
#             for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
#                 try:
#                     cpu_usage = proc.info['cpu_percent']
#                     memory_usage = proc.info['memory_percent']

#                     # Check if any process exceeds the CPU or memory threshold
#                     if cpu_usage > self.cpu_threshold.get() or memory_usage > self.memory_threshold.get():
#                         self.alert_user_about_process(proc.info['pid'], proc.info['name'], cpu_usage, memory_usage)

#                 except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#                     pass

#             time.sleep(5) #check processes every 5 seconds

#     #method to alert user about the process exceeding thresholds
#     def alert_user_about_process(self, pid, name, cpu, memory):
#         msg = f"Process {name} (PID: {pid}) is exceeding the thresholds.\n"
#         msg += f"CPU Usage: {cpu}%\nMemory Usage: {memory}%\n"
#         msg += "Do you want to terminate this process?"

#         response = messagebox.askyesno("Process Alert", msg)
#         if response:
#             try:
#                 psutil.Process(pid).terminate() #terminate the process
#                 messagebox.showinfo("Process Terminated", f"Process {name} (PID: {pid}) was terminated.")
#             except psutil.NoSuchProcess:
#                 messagebox.showwarning("Process Not Found", "The process no longer exists.")
#         else:
#             messagebox.showinfo("Process Not Terminated", "The process was not terminated.")

#     #method to stop monitoring SYN packets and processes
#     def stop_monitoring(self):
#         self.monitoring = False
#         print("Stopped monitoring.")

#     #method to create charts for displaying SYN packet counts
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

#         self.anim = FuncAnimation(self.fig, self.update_chart_animation, interval=1000, blit=False)

#     #method to start monitoring SYN packets
#     def start_monitoring(self):
#         self.monitoring = True
#         self.syn_count = 0
#         self.monitor_ports = [int(port.strip()) for port in self.ports_to_monitor.get().split(",") if port.strip().isdigit()]
#         print(f"Monitoring SYN packets on ports: {self.monitor_ports} with threshold {self.syn_threshold.get()}")
        
#         #start packet sniffing in a new thread
#         self.sniff_thread = threading.Thread(target=self.start_packet_sniffing)
#         self.sniff_thread.daemon = True
#         self.sniff_thread.start()

#     #method to start sniffing network packets using Scapy
#     def start_packet_sniffing(self):
#         def process_packet(packet):
#             if not self.monitoring:
#                 return False

#             print(packet.summary())

#             if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet[TCP].dport in self.monitor_ports:
#                 self.syn_count += 1
#                 print(f"SYN packet detected on port {packet[TCP].dport}. Total SYN count: {self.syn_count}")
#                 self.update_chart()

#                 if self.syn_count >= self.syn_threshold.get():
#                     print("SYN packet threshold reached!")
#                     self.alert_user()
#                     self.stop_monitoring()

#         sniff(prn=process_packet, store=0, stop_filter=lambda x: not self.monitoring)

#     #method to update the chart with new data
#     def update_chart(self):
#         self.times.append(len(self.times))
#         self.syn_counts.append(self.syn_count)
#         self.ax.clear()
#         self.ax.set_title('SYN Packets Count', color="#00FF00")
#         self.ax.set_xlabel('Time', color="#00FF00")
#         self.ax.set_ylabel('SYN Packets', color="#00FF00")
#         self.ax.plot(self.times, self.syn_counts, color="#00FF00")
#         self.canvas.draw()

#     #method to update the chart dynamically using animation
#     def update_chart_animation(self, i):
#         self.ax.clear()
#         self.ax.set_title('SYN Packets Count', color="#00FF00")
#         self.ax.set_xlabel('Time', color="#00FF00")
#         self.ax.set_ylabel('SYN Packets', color="#00FF00")
#         self.ax.plot(self.times, self.syn_counts, color="#00FF00")
#         self.ax.tick_params(axis='x', colors='#00FF00')
#         self.ax.tick_params(axis='y', colors='#00FF00')
#         self.ax.spines['bottom'].set_color('#00FF00')
#         self.ax.spines['top'].set_color('#00FF00')
#         self.ax.spines['right'].set_color('#00FF00')
#         self.ax.spines['left'].set_color('#00FF00')

#     #method to display an alert when SYN packet threshold is reached
#     def alert_user(self):
#         alert_label = tk.Label(self.hids_frame, text="ALERT: SYN packet threshold reached!", font=("Courier", 18), bg="#1E1E1E", fg="#FF4500")
#         alert_label.pack(pady=20)

# #entry point of the program
# if __name__ == "__main__":
#     app = MainWindow()
#     app.mainloop()










#_____________________________________________________________________________________________________________________________________________________________________________________________________#

# OLDER VERSIONS #

# VERSION 2 #

# import tkinter as tk
# from tkinter import ttk
# import matplotlib.pyplot as plt
# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# import pandas as pd
# import json
# from datetime import datetime
# from scapy.all import sniff, IP, TCP
# from matplotlib.animation import FuncAnimation
# import threading

# #define the main GUI window class
# class MainWindow(tk.Tk):
#     def __init__(self):
#         super().__init__() #initialize the parent class (tk.Tk)
#         self.title("HIDS - SYN Packet Monitor") #set the window title
#         self.geometry("800x680") #set the initial size of the window
#         self.configure(bg="#1E1E1E") #set the background color of the window

#         #define variables for GUI elements
#         self.radio_var = tk.StringVar() #variable for holding selected radio button value
#         self.syn_threshold = tk.IntVar() #variable for SYN packet threshold
#         self.ports_to_monitor = tk.StringVar() #variable for ports to monitor

#         #initialize monitoring state and counters
#         self.syn_count = 0 #counter for detected SYN packets
#         self.monitoring = False #flag to indicate whether monitoring is active
#         self.sniff_thread = None #initialize thread for sniffing

#         #create and display GUI widgets
#         self.create_widgets()
#         self.create_charts()

#     #method to create and organize all widgets in the GUI
#     def create_widgets(self):
#         self.create_header() #create the header section
#         self.create_parameters_box() #create the parameters input section
#         self.create_monitoring_controls() #create start/stop monitoring buttons
#         #self.create_footer() #footer section (commented out for now)

#     #method to create the header section of the GUI
#     def create_header(self):
#         header_frame = tk.Frame(self, bg="#1E1E1E") #frame for the header
#         header_frame.pack(pady=10) #add padding and pack the frame

#         #header label displaying the title
#         header = tk.Label(header_frame, text="HIDS - SYN Packet Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
#         header.pack() #pack the header label

#     #method to create the parameter input section
#     def create_parameters_box(self):
#         parameters_frame = tk.Frame(self, bg="#1E1E1E", bd=2, relief=tk.SUNKEN) #frame for parameters
#         parameters_frame.pack(pady=10, padx=10, fill=tk.X) #pack the frame with padding

#         #label and entry for SYN packet threshold
#         tk.Label(parameters_frame, text="SYN Packet Threshold:", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
#         self.syn_threshold_entry = tk.Entry(parameters_frame, textvariable=self.syn_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.syn_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
#         self.syn_threshold.set(100) #set default threshold value

#         #label and entry for ports to monitor
#         tk.Label(parameters_frame, text="Ports to Monitor (comma-separated):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
#         self.ports_entry = tk.Entry(parameters_frame, textvariable=self.ports_to_monitor, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
#         self.ports_entry.grid(row=1, column=1, padx=5, pady=5)
#         self.ports_to_monitor.set("80,443") #set default ports to monitor

#     #method to create start/stop monitoring controls
#     def create_monitoring_controls(self):
#         control_frame = tk.Frame(self, bg="#1E1E1E") #frame for control buttons
#         control_frame.pack(pady=10) #pack the frame with padding

#         #start monitoring button
#         start_button = tk.Button(control_frame, text="Start Monitoring", bg="#333333", fg="#00FF00", command=self.start_monitoring, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
#         start_button.grid(row=0, column=0, padx=5)

#         #stop monitoring button
#         stop_button = tk.Button(control_frame, text="Stop Monitoring", bg="#333333", fg="#FF4500", command=self.stop_monitoring, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
#         stop_button.grid(row=0, column=1, padx=5)

#     #method to create charts for displaying SYN packet counts
#     def create_charts(self):
#         chart_frame = tk.Frame(self, bg="#1E1E1E") #frame for the chart
#         chart_frame.pack(pady=10, fill=tk.BOTH, expand=True) #pack the frame with padding

#         #create matplotlib figure and axis
#         self.fig, self.ax = plt.subplots(facecolor="#1E1E1E")
#         self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame) #create canvas to embed chart in Tkinter
#         self.canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

#         #set initial chart titles and labels
#         self.ax.set_title('SYN Packets Count', color="#00FF00")
#         self.ax.set_xlabel('Time', color="#00FF00")
#         self.ax.set_ylabel('SYN Packets', color="#00FF00")
#         self.ax.tick_params(axis='x', colors='#00FF00')
#         self.ax.tick_params(axis='y', colors='#00FF00')
#         self.ax.spines['bottom'].set_color('#00FF00')
#         self.ax.spines['top'].set_color('#00FF00')
#         self.ax.spines['right'].set_color('#00FF00')
#         self.ax.spines['left'].set_color('#00FF00')

#         #initialize empty lists to store data for dynamic charting
#         self.times = [] #time points for x-axis
#         self.syn_counts = [] #SYN packet counts for y-axis

#         #start the chart animation for dynamic updates
#         self.anim = FuncAnimation(self.fig, self.update_chart_animation, interval=1000, blit=False)

#     #method to start monitoring SYN packets
#     def start_monitoring(self):
#         self.monitoring = True #set monitoring flag to True
#         self.syn_count = 0 #reset SYN packet count
#         self.monitor_ports = [int(port.strip()) for port in self.ports_to_monitor.get().split(",") if port.strip().isdigit()] #parse ports to monitor
#         print(f"Monitoring SYN packets on ports: {self.monitor_ports} with threshold {self.syn_threshold.get()}") #debug output
        
#         #start packet sniffing in a new thread
#         self.sniff_thread = threading.Thread(target=self.start_packet_sniffing)
#         self.sniff_thread.daemon = True #make the thread a daemon so it exits when the main program exits
#         self.sniff_thread.start()

#     #method to stop monitoring SYN packets
#     def stop_monitoring(self):
#         self.monitoring = False #set monitoring flag to False
#         print("Stopped monitoring.") #debug output

#     #method to start sniffing network packets using Scapy
#     def start_packet_sniffing(self):
#         def process_packet(packet):
#             if not self.monitoring:
#                 return False #stop sniffing if monitoring is not active

#             #check if packet is a TCP SYN packet on monitored ports
#             if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet[TCP].dport in self.monitor_ports:
#                 self.syn_count += 1 #increment SYN packet count
#                 print(f"SYN packet detected on port {packet[TCP].dport}. Total SYN count: {self.syn_count}") #debug output
#                 self.update_chart() #update the chart with new data

#                 #check if SYN packet count exceeds threshold
#                 if self.syn_count >= self.syn_threshold.get():
#                     print("SYN packet threshold reached!") #debug output
#                     self.alert_user() #trigger alert
#                     self.stop_monitoring() #stop monitoring once the threshold is reached

#         #start sniffing packets with Scapy
#         sniff(prn=process_packet, store=0, stop_filter=lambda x: not self.monitoring)

#     #method to update the chart with new data
#     def update_chart(self):
#         self.times.append(len(self.times)) #append current time point
#         self.syn_counts.append(self.syn_count) #append current SYN packet count
#         self.ax.clear() #clear existing chart
#         self.ax.set_title('SYN Packets Count', color="#00FF00")
#         self.ax.set_xlabel('Time', color="#00FF00")
#         self.ax.set_ylabel('SYN Packets', color="#00FF00")
#         self.ax.plot(self.times, self.syn_counts, color="#00FF00") #plot updated data
#         self.canvas.draw() #redraw the canvas with new data

#     #method to update the chart dynamically using animation
#     def update_chart_animation(self, i):
#         #clear the chart and plot updated data
#         self.ax.clear()
#         self.ax.set_title('SYN Packets Count', color="#00FF00")
#         self.ax.set_xlabel('Time', color="#00FF00")
#         self.ax.set_ylabel('SYN Packets', color="#00FF00")
#         self.ax.plot(self.times, self.syn_counts, color="#00FF00")
#         self.ax.tick_params(axis='x', colors='#00FF00')
#         self.ax.tick_params(axis='y', colors='#00FF00')
#         self.ax.spines['bottom'].set_color('#00FF00')
#         self.ax.spines['top'].set_color('#00FF00')
#         self.ax.spines['right'].set_color('#00FF00')
#         self.ax.spines['left'].set_color('#00FF00')

#     #method to display an alert when SYN packet threshold is reached
#     def alert_user(self):
#         alert_label = tk.Label(self, text="ALERT: SYN packet threshold reached!", font=("Courier", 18), bg="#1E1E1E", fg="#FF4500")
#         alert_label.pack(pady=20) #pack the alert label

# #entry point of the program
# if __name__ == "__main__":
#     app = MainWindow() #create an instance of the main window
#     app.mainloop() #start the Tkinter event loop

















# VERSION 1 #

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP
from matplotlib.animation import FuncAnimation


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HIDS - SYN Packet Monitor")
        self.geometry("800x680")
        self.configure(bg="#1E1E1E")

        self.radio_var = tk.StringVar()
        self.syn_threshold = tk.IntVar()
        self.ports_to_monitor = tk.StringVar()

        self.syn_count = 0
        self.monitoring = False

        self.create_widgets()
        self.create_charts()

    def create_widgets(self):
        #header
        self.create_header()

        #parameters box
        self.create_parameters_box()

        #start/Stop Monitoring buttons
        self.create_monitoring_controls()

        #footer
        #self.create_footer()

    def create_header(self):
        header_frame = tk.Frame(self, bg="#1E1E1E")
        header_frame.pack(pady=10)

        header = tk.Label(header_frame, text="HIDS - SYN Packet Monitor", font=("Courier", 24), bg="#1E1E1E", fg="#00FF00")
        header.pack()

    def create_parameters_box(self):
        parameters_frame = tk.Frame(self, bg="#1E1E1E", bd=2, relief=tk.SUNKEN)
        parameters_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(parameters_frame, text="SYN Packet Threshold:", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.syn_threshold_entry = tk.Entry(parameters_frame, textvariable=self.syn_threshold, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.syn_threshold_entry.grid(row=0, column=1, padx=5, pady=5)
        self.syn_threshold.set(100)  #default threshold

        tk.Label(parameters_frame, text="Ports to Monitor (comma-separated):", font=("Courier", 14), bg="#1E1E1E", fg="#00FF00").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ports_entry = tk.Entry(parameters_frame, textvariable=self.ports_to_monitor, width=20, bg="#2E2E2E", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 12))
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5)
        self.ports_to_monitor.set("80,443")  #default ports to monitor

    def create_monitoring_controls(self):
        control_frame = tk.Frame(self, bg="#1E1E1E")
        control_frame.pack(pady=10)

        start_button = tk.Button(control_frame, text="Start Monitoring", bg="#333333", fg="#00FF00", command=self.start_monitoring, font=("Courier", 12), activebackground="#00FF00", activeforeground="#1E1E1E")
        start_button.grid(row=0, column=0, padx=5)

        stop_button = tk.Button(control_frame, text="Stop Monitoring", bg="#333333", fg="#FF4500", command=self.stop_monitoring, font=("Courier", 12), activebackground="#FF4500", activeforeground="#1E1E1E")
        stop_button.grid(row=0, column=1, padx=5)

    def create_charts(self):
        #placeholder frame for charts
        chart_frame = tk.Frame(self, bg="#1E1E1E")
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

        #initialize empty lists to store the data for the dynamic chart
        self.times = []
        self.syn_counts = []

        #start the chart animation
        self.anim = FuncAnimation(self.fig, self.update_chart_animation, interval=1000, blit=False)

    #def create_footer(self):
    #    footer = tk.Label(self, text="© Levi, Ray and Shoup, Inc. 2024", font=("Courier", 18), bg="#1E1E1E", fg="#00FF00")
    #    footer.pack(pady=10)

    def start_monitoring(self):
        self.monitoring = True
        self.syn_count = 0
        self.monitor_ports = [int(port.strip()) for port in self.ports_to_monitor.get().split(",") if port.strip().isdigit()]
        print(f"Monitoring SYN packets on ports: {self.monitor_ports} with threshold {self.syn_threshold.get()}")
        self.start_packet_sniffing()

    def stop_monitoring(self):
        self.monitoring = False
        print("Stopped monitoring.")

    def start_packet_sniffing(self):
        def process_packet(packet):
            if not self.monitoring:
                return False  #stop sniffing

            if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet[TCP].dport in self.monitor_ports:
                self.syn_count += 1
                print(f"SYN packet detected on port {packet[TCP].dport}. Total SYN count: {self.syn_count}")
                self.update_chart()

                if self.syn_count >= self.syn_threshold.get():
                    print("SYN packet threshold reached!")
                    self.alert_user()

        sniff(prn=process_packet, store=0, stop_filter=lambda x: not self.monitoring)

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
        #update the chart with new data (if any)
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
        alert_label = tk.Label(self, text="ALERT: SYN packet threshold reached!", font=("Courier", 18), bg="#1E1E1E", fg="#FF4500")
        alert_label.pack(pady=20)


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
