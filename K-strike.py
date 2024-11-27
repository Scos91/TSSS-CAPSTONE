import subprocess
import logging
import threading
import os
import signal
import re
import ipaddress
from datetime import datetime
from termcolor import colored

# Configured logging with detailed timestamps
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    filename='ids_ips.log'
)

# Print function with colors support
def print_alert(message, color="red"):
    print(colored(message, color))


class Firewall:
    def __init__(self):
        self.blocked_ips = set() # counter for currently blocked ips
        self.whitelisted_ips = self.load_whitelist() # Load IPs that should never be blocked (Needs WORK!!!!)
        self.sync_with_iptables()

    def load_whitelist(self):
        """
        Load a predefined list of whitelisted IPs. These IPs will never be blocked.
        """
        return {"192.168.1.1", "127.0.0.1"}

    def is_valid_ip(self, ip):
        """
        Validate if the given string is a valid IPv4 address.
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def sync_with_iptables(self):
        """
        Dynamically changing the internal list of blocked IPs with the current iptables rules.
        """
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                stdout=subprocess.PIPE,
                text=True
            )
            self.blocked_ips.clear()  # Clear current set to avoid duplicates
            for line in result.stdout.splitlines():
                if "DROP" in line:   # Find DROP rules in iptables
                    parts = line.split()
                    for part in parts:
                        if self.is_valid_ip(part):
                            self.blocked_ips.add(part)
                            logging.info(f"Synchronized blocked IP from iptables: {part}")
        except Exception as e:
            logging.error(f"Failed to synchronize with iptables: {e}")
            print_alert("[ERROR] Failed to synchronize with iptables.", "red")

    def block_ip(self, ip, attempt_count, port):
        """
        Block a specific IP by adding a DROP rule to iptables whenever lotof traffic is coming
        """
        if ip in self.whitelisted_ips: # Skiping whitelisted
            logging.info(f"IP {ip} is whitelisted. Skipping block.")
            print_alert(f"[INFO] IP {ip} is whitelisted. Skipping block.", "yellow")
            return

        if ip not in self.blocked_ips: # Block only if not already blocked
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            self.blocked_ips.add(ip)
            logging.info(f"Blocked IP: {ip}")
            print_alert(f"[ALERT] Blocked IP: {ip} after {attempt_count} failed attempts to port {port} at {datetime.now()}.", "red")

    def unblock_ip(self):
        """
        Dynamically unblock an IP. If no IP is provided, display a list for user selection.
        """
        self.sync_with_iptables()  # Ensure the blocked IPs are up-to-date

        if not self.blocked_ips:
            print_alert("[INFO] No blocked IPs to unblock.", "cyan")
            return

         # Showing blocked IPs for user to select
        print_alert("[INFO] Select an IP to unblock:", "cyan")
        blocked_list = list(self.blocked_ips)
        for index, blocked_ip in enumerate(blocked_list, start=1):
            print(colored(f"{index}. {blocked_ip}", "yellow"))

        try:
            choice = int(input(colored("Enter the number of the IP to unblock: ", "yellow")))
            if 1 <= choice <= len(blocked_list):
                selected_ip = blocked_list[choice - 1]
                subprocess.run(["iptables", "-D", "INPUT", "-s", selected_ip, "-j", "DROP"])
                self.blocked_ips.remove(selected_ip)
                logging.info(f"Unblocked IP: {selected_ip}")
                print_alert(f"[INFO] Unblocked IP: {selected_ip}", "green")
            else:
                print_alert("[ERROR] Invalid selection.", "red")
        except ValueError:
            print_alert("[ERROR] Invalid input. Please enter a number.", "red")

    def get_blocked_ips(self):
        """
        Return a list of all currently blocked IPs, dynamically updated.
        """
        self.sync_with_iptables()
        return [ip for ip in self.blocked_ips if self.is_valid_ip(ip)]


class Sniffer:
    def __init__(self):
        self.firewall = Firewall() # Firewall instance to handle blocking/unblocking
        self.failed_attempts = {}  # Track failed login attempts per IP
        self.alert_threshold = 5  # Number of failed attempts to trigger alert

    def monitor_journald(self):
        """
        Monitor journald logs for SSH authentication failures.
        """
        try:
            process = subprocess.Popen(
                ["journalctl", "-u", "ssh", "-f", "-n", "0"],
                stdout=subprocess.PIPE,
                text=True
            )
            while True:
                line = process.stdout.readline()
                if not line:
                    continue

                # Match failed login attempts using regex
                failed_match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
                pam_failures_match = re.search(r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)", line)

                if failed_match:
                    src_ip = failed_match.group(1)
                    self.process_failed_attempt(src_ip, 22)

                if pam_failures_match:
                    src_ip = pam_failures_match.group(1)
                    self.process_failed_attempt(src_ip, 22)
        except Exception as e:
            logging.error(f"Error monitoring journald: {e}")
            print_alert(f"[ERROR] Failed to monitor journald: {e}", "red")

    def process_failed_attempt(self, src_ip, port):
        """
        Process a failed SSH login attempt from a IP.
        """
        if src_ip in self.firewall.blocked_ips:
            logging.info(f"IP {src_ip} is already blocked. Ignoring further attempts.")
            return

        self.failed_attempts[src_ip] = self.failed_attempts.get(src_ip, 0) + 1
        attempt_count = self.failed_attempts[src_ip]
        logging.info(f"Failed attempt from {src_ip}. Count: {attempt_count}")

        print_alert(f"[INFO] Failed attempt {attempt_count} from IP {src_ip} to port {port} at {datetime.now()}.", "yellow")

        if attempt_count > self.alert_threshold:
            logging.warning(f"Brute-force detected from IP: {src_ip}")
            print_alert(f"[ALERT] Brute-force detected from IP: {src_ip}. Blocking...", "red")
            self.firewall.block_ip(src_ip, attempt_count, port)

# makes ctrl+C nice and smooth, basically kill -9 signal sent to end the process smoothly
def signal_handler(sig, frame):
    print_alert("\n[INFO] Stopping IDS/IPS gracefully...", "yellow")
    logging.info("Exiting gracefully...")
    os._exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    firewall = Firewall()

    print(colored("==== Zer0dayk's IDS/IPS ====", "blue", attrs=["bold"]))
    print(colored("==== Made by Krishna Tiwadi ====", "blue", attrs=["bold"]))
    print(colored("==== WhiteHat Project ====", "blue", attrs=["bold"]))
    print(colored("Commands:", "cyan"))
    print(colored("1. Type 'unblock' to select and remove an IP from the block list.", "green"))
    print(colored("2. Hit Enter to start SSH network monitoring.", "green"))
    print(colored("3. Type 'show blocked' to list all blocked IPs.", "green"))
    print(colored("4. Type 'quit' to exit.", "green"))

    while True:
        command = input(colored("Command: ", "yellow"))
        if command == "unblock":
            firewall.unblock_ip() # Unblock an IP with interface
        elif command == "show blocked":
            blocked_ips = firewall.get_blocked_ips() # Show currently blocked IPs
            print_alert("[INFO] Blocked IPs:", "cyan")
            for ip in blocked_ips:
                print(colored(f"- {ip}", "red"))
        elif command == "quit":
            print_alert("[INFO] Exiting IDS/IPS...", "yellow")
            logging.info("Stopped IDS/IPS.")
            break
        elif command == "":
            print_alert("[INFO] Starting SSH network monitoring...", "cyan")
            sniffer = Sniffer() # Create a new Sniffer instance
            sniff_thread = threading.Thread(target=sniffer.monitor_journald, daemon=True)
            sniff_thread.start() # Start monitoring logs for SSH failures
        else:
            print_alert("[ERROR] Invalid command. Available commands are 'unblock', '', 'show blocked', and 'quit'.", "red")


if __name__ == "__main__":
    main()
