import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import numpy as np
import socket
import struct
import os
import sys
import time
import threading
import json
import logging
from datetime import datetime
import subprocess
import platform
import requests
import psutil
from collections import deque

# Constants
CONFIG_FILE = "firewall_config.json"
LOG_FILE = "firewall.log"
HISTORY_FILE = "command_history.txt"
MAX_HISTORY = 100
PACKET_BUFFER_SIZE = 65565

class PacketFilteringFirewall:
    def __init__(self):
        self.rules = []
        self.blacklist = []
        self.whitelist = []
        self.logged_packets = []
        self.monitoring = False
        self.socket = None
        self.command_history = deque(maxlen=MAX_HISTORY)
        self.telegram_token = None
        self.telegram_chat_id = None
        self.load_config()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.rules = config.get('rules', [])
                    self.blacklist = config.get('blacklist', [])
                    self.whitelist = config.get('whitelist', [])
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
        except Exception as e:
            logging.error(f"Error loading config: {str(e)}")
            
    def save_config(self):
        try:
            config = {
                'rules': self.rules,
                'blacklist': self.blacklist,
                'whitelist': self.whitelist,
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {str(e)}")
            
    def add_rule(self, rule):
        self.rules.append(rule)
        self.save_config()
        logging.info(f"Added rule: {rule}")
        
    def remove_rule(self, index):
        if 0 <= index < len(self.rules):
            rule = self.rules.pop(index)
            self.save_config()
            logging.info(f"Removed rule: {rule}")
            return True
        return False
        
    def add_to_blacklist(self, ip):
        if ip not in self.blacklist:
            self.blacklist.append(ip)
            self.save_config()
            logging.info(f"Added to blacklist: {ip}")
            
    def remove_from_blacklist(self, ip):
        if ip in self.blacklist:
            self.blacklist.remove(ip)
            self.save_config()
            logging.info(f"Removed from blacklist: {ip}")
            return True
        return False
        
    def add_to_whitelist(self, ip):
        if ip not in self.whitelist:
            self.whitelist.append(ip)
            self.save_config()
            logging.info(f"Added to whitelist: {ip}")
            
    def remove_from_whitelist(self, ip):
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            self.save_config()
            logging.info(f"Removed from whitelist: {ip}")
            return True
        return False
        
    def start_monitoring(self, interface=None):
        if self.monitoring:
            return False, "Already monitoring"
            
        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Bind to interface
            if interface:
                self.socket.bind((interface, 0))
            else:
                self.socket.bind(('0.0.0.0', 0))
                
            # Include IP headers
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Enable promiscuous mode
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.monitoring = True
            threading.Thread(target=self._packet_capture_loop, daemon=True).start()
            logging.info("Started packet monitoring")
            return True, "Monitoring started"
        except Exception as e:
            logging.error(f"Error starting monitoring: {str(e)}")
            return False, str(e)
            
    def stop_monitoring(self):
        if not self.monitoring:
            return False, "Not currently monitoring"
            
        try:
            self.monitoring = False
            if self.socket:
                # Disable promiscuous mode
                if platform.system() == 'Windows':
                    self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.socket.close()
                self.socket = None
            logging.info("Stopped packet monitoring")
            return True, "Monitoring stopped"
        except Exception as e:
            logging.error(f"Error stopping monitoring: {str(e)}")
            return False, str(e)
            
    def _packet_capture_loop(self):
        while self.monitoring and self.socket:
            try:
                packet, addr = self.socket.recvfrom(PACKET_BUFFER_SIZE)
                self._process_packet(packet, addr)
            except Exception as e:
                if self.monitoring:  # Only log if we're supposed to be monitoring
                    logging.error(f"Error in packet capture: {str(e)}")
                break
                
    def _process_packet(self, packet, addr):
        try:
            # Extract IP header (first 20 bytes)
            ip_header = packet[:20]
            
            # Unpack IP header
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            # Create packet info dict
            packet_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': self._protocol_to_str(protocol),
                'action': 'ALLOW',  # Default to allow unless a rule blocks it
                'size': len(packet)
            }
            
            # Check rules
            action = self._check_rules(src_ip, dst_ip, protocol)
            packet_info['action'] = action
            
            # Log packet
            self.logged_packets.append(packet_info)
            logging.info(f"Packet: {src_ip} -> {dst_ip} {packet_info['protocol']} - {action}")
            
            # Send alert if blocked
            if action == 'BLOCK' and self.telegram_token and self.telegram_chat_id:
                self._send_telegram_alert(packet_info)
                
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")
            
    def _check_rules(self, src_ip, dst_ip, protocol):
        # Check whitelist first
        if src_ip in self.whitelist:
            return 'ALLOW'
            
        # Check blacklist
        if src_ip in self.blacklist:
            return 'BLOCK'
            
        # Check rules
        for rule in self.rules:
            if self._matches_rule(rule, src_ip, dst_ip, protocol):
                return rule.get('action', 'BLOCK')
                
        # Default allow (could be changed to default deny)
        return 'ALLOW'
        
    def _matches_rule(self, rule, src_ip, dst_ip, protocol):
        # Check source IP
        if 'src_ip' in rule and rule['src_ip'] != '*' and rule['src_ip'] != src_ip:
            return False
            
        # Check destination IP
        if 'dst_ip' in rule and rule['dst_ip'] != '*' and rule['dst_ip'] != dst_ip:
            return False
            
        # Check protocol
        if 'protocol' in rule and rule['protocol'] != '*' and rule['protocol'] != self._protocol_to_str(protocol):
            return False
            
        return True
        
    def _protocol_to_str(self, protocol_num):
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            # Add more as needed
        }
        return protocols.get(protocol_num, str(protocol_num))
        
    def _send_telegram_alert(self, packet_info):
        try:
            message = (
                f"🚨 Firewall Alert 🚨\n"
                f"Blocked packet detected:\n"
                f"Source: {packet_info['src_ip']}\n"
                f"Destination: {packet_info['dst_ip']}\n"
                f"Protocol: {packet_info['protocol']}\n"
                f"Time: {packet_info['timestamp']}"
            )
            
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            params = {
                'chat_id': self.telegram_chat_id,
                'text': message
            }
            
            response = requests.post(url, params=params)
            if response.status_code != 200:
                logging.error(f"Telegram alert failed: {response.text}")
        except Exception as e:
            logging.error(f"Error sending Telegram alert: {str(e)}")
            
    def ping(self, ip):
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return True, output
        except subprocess.CalledProcessError as e:
            return False, e.output
        except Exception as e:
            return False, str(e)
            
    def get_status(self):
        status = {
            'monitoring': self.monitoring,
            'rules_count': len(self.rules),
            'blacklist_count': len(self.blacklist),
            'whitelist_count': len(self.whitelist),
            'logged_packets': len(self.logged_packets),
            'telegram_configured': bool(self.telegram_token and self.telegram_chat_id)
        }
        return status
        
    def get_network_stats(self):
        try:
            stats = psutil.net_io_counters(pernic=True)
            return stats
        except Exception as e:
            logging.error(f"Error getting network stats: {str(e)}")
            return {}
            
    def clear_logs(self):
        self.logged_packets = []
        logging.info("Cleared packet logs")
        
    def save_command_history(self):
        try:
            with open(HISTORY_FILE, 'w') as f:
                for cmd in self.command_history:
                    f.write(f"{cmd}\n")
        except Exception as e:
            logging.error(f"Error saving command history: {str(e)}")
            
    def load_command_history(self):
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, 'r') as f:
                    for line in f:
                        self.command_history.append(line.strip())
        except Exception as e:
            logging.error(f"Error loading command history: {str(e)}")

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.firewall = PacketFilteringFirewall()
        self.firewall.load_command_history()
        
        # Configure main window
        self.root.title("Advanced Packet Filtering Firewall")
        self.root.geometry("1200x800")
        self.root.configure(bg='black')
        
        # Set dark theme
        self._setup_dark_theme()
        
        # Create menu
        self._create_menu()
        
        # Create main frames
        self._create_main_frames()
        
        # Initialize tabs
        self._setup_tabs()
        
        # Status bar
        self._create_status_bar()
        
        # Start with dashboard
        self.show_dashboard()
        
        # Update status periodically
        self._update_status()
        
    def _setup_dark_theme(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Background colors
        style.configure('.', background='black', foreground='white')
        style.configure('TFrame', background='black')
        style.configure('TLabel', background='black', foreground='white')
        style.configure('TButton', background='#333', foreground='white')
        style.configure('TEntry', fieldbackground='#333', foreground='white')
        style.configure('TCombobox', fieldbackground='#333', foreground='white')
        style.configure('TNotebook', background='black', borderwidth=0)
        style.configure('TNotebook.Tab', background='#333', foreground='white', padding=[10, 5])
        style.map('TNotebook.Tab', background=[('selected', '#555')])
        style.configure('Treeview', background='#222', foreground='white', fieldbackground='#222')
        style.map('Treeview', background=[('selected', '#444')])
        style.configure('Vertical.TScrollbar', background='#333', troughcolor='black')
        style.configure('Horizontal.TScrollbar', background='#333', troughcolor='black')
        
    def _create_menu(self):
        menubar = tk.Menu(self.root, bg='black', fg='white')
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg='black', fg='white')
        file_menu.add_command(label="Export Rules", command=self.export_rules)
        file_menu.add_command(label="Import Rules", command=self.import_rules)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg='black', fg='white')
        view_menu.add_command(label="Dashboard", command=self.show_dashboard)
        view_menu.add_command(label="Rules", command=self.show_rules)
        view_menu.add_command(label="Blacklist", command=self.show_blacklist)
        view_menu.add_command(label="Whitelist", command=self.show_whitelist)
        view_menu.add_command(label="Logs", command=self.show_logs)
        view_menu.add_command(label="Statistics", command=self.show_stats)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0, bg='black', fg='white')
        settings_menu.add_command(label="Telegram Config", command=self.show_telegram_config)
        settings_menu.add_command(label="Interface Settings", command=self.show_interface_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg='black', fg='white')
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def _create_main_frames(self):
        # Main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Command frame at top
        self.command_frame = ttk.Frame(self.main_container)
        self.command_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Command entry
        self.cmd_label = ttk.Label(self.command_frame, text="Command:")
        self.cmd_label.pack(side=tk.LEFT, padx=5)
        
        self.cmd_entry = ttk.Entry(self.command_frame, width=50)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind('<Return>', self.execute_command)
        
        self.cmd_button = ttk.Button(self.command_frame, text="Execute", command=self.execute_command)
        self.cmd_button.pack(side=tk.LEFT, padx=5)
        
        # Tab container
        self.tab_container = ttk.Notebook(self.main_container)
        self.tab_container.pack(fill=tk.BOTH, expand=True)
        
    def _setup_tabs(self):
        # Dashboard tab
        self.dashboard_tab = ttk.Frame(self.tab_container)
        self.tab_container.add(self.dashboard_tab, text="Dashboard")
        
        # Rules tab
        self.rules_tab = ttk.Frame(self.tab_container)
        self.tab_container.add(self.rules_tab, text="Rules")
        
        # Blacklist tab
        self.blacklist_tab = ttk.Frame(self.tab_container)
        self.tab_container.add(self.blacklist_tab, text="Blacklist")
        
        # Whitelist tab
        self.whitelist_tab = ttk.Frame(self.tab_container)
        self.tab_container.add(self.whitelist_tab, text="Whitelist")
        
        # Logs tab
        self.logs_tab = ttk.Frame(self.tab_container)
        self.tab_container.add(self.logs_tab, text="Logs")
        
        # Stats tab
        self.stats_tab = ttk.Frame(self.tab_container)
        self.tab_container.add(self.stats_tab, text="Statistics")
        
        # Console tab
        self.console_tab = ttk.Frame(self.tab_container)
        self.tab_container.add(self.console_tab, text="Console")
        
        # Initialize each tab's content
        self._init_dashboard()
        self._init_rules_tab()
        self._init_blacklist_tab()
        self._init_whitelist_tab()
        self._init_logs_tab()
        self._init_stats_tab()
        self._init_console_tab()
        
    def _create_status_bar(self):
        self.status_bar = ttk.Frame(self.root, height=20)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(self.status_bar, text="Ready", relief=tk.SUNKEN)
        self.status_label.pack(fill=tk.X)
        
    def _update_status(self):
        status = self.firewall.get_status()
        status_text = (
            f"Monitoring: {'ON' if status['monitoring'] else 'OFF'} | "
            f"Rules: {status['rules_count']} | "
            f"Blacklist: {status['blacklist_count']} | "
            f"Whitelist: {status['whitelist_count']} | "
            f"Logged Packets: {status['logged_packets']} | "
            f"Telegram: {'ON' if status['telegram_configured'] else 'OFF'}"
        )
        self.status_label.config(text=status_text)
        self.root.after(5000, self._update_status)  # Update every 5 seconds
        
    def _init_dashboard(self):
        # Left frame for stats
        left_frame = ttk.Frame(self.dashboard_tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Quick stats
        stats_frame = ttk.LabelFrame(left_frame, text="Quick Stats")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.rules_count_label = ttk.Label(stats_frame, text="Rules: 0")
        self.rules_count_label.pack(anchor=tk.W)
        
        self.blacklist_count_label = ttk.Label(stats_frame, text="Blacklist: 0")
        self.blacklist_count_label.pack(anchor=tk.W)
        
        self.whitelist_count_label = ttk.Label(stats_frame, text="Whitelist: 0")
        self.whitelist_count_label.pack(anchor=tk.W)
        
        self.logged_packets_label = ttk.Label(stats_frame, text="Logged Packets: 0")
        self.logged_packets_label.pack(anchor=tk.W)
        
        # Controls frame
        controls_frame = ttk.LabelFrame(left_frame, text="Controls")
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.monitor_button = ttk.Button(controls_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.monitor_button.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(controls_frame, text="Clear Logs", command=self.clear_logs).pack(fill=tk.X, padx=5, pady=2)
        
        # Right frame for charts
        right_frame = ttk.Frame(self.dashboard_tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packet chart
        self.packet_chart_frame = ttk.Frame(right_frame)
        self.packet_chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Update dashboard data
        self.update_dashboard()
        
    def update_dashboard(self):
        status = self.firewall.get_status()
        self.rules_count_label.config(text=f"Rules: {status['rules_count']}")
        self.blacklist_count_label.config(text=f"Blacklist: {status['blacklist_count']}")
        self.whitelist_count_label.config(text=f"Whitelist: {status['whitelist_count']}")
        self.logged_packets_label.config(text=f"Logged Packets: {status['logged_packets']}")
        
        # Update monitor button text
        self.monitor_button.config(text="Stop Monitoring" if status['monitoring'] else "Start Monitoring")
        
        # Update charts
        self.update_packet_chart()
        
        # Schedule next update
        self.root.after(10000, self.update_dashboard)
        
    def update_packet_chart(self):
        # Clear previous chart
        for widget in self.packet_chart_frame.winfo_children():
            widget.destroy()
            
        if not self.firewall.logged_packets:
            ttk.Label(self.packet_chart_frame, text="No packet data available").pack(fill=tk.BOTH, expand=True)
            return
            
        # Create figure
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(6, 8))
        fig.patch.set_facecolor('#222222')
        fig.subplots_adjust(hspace=0.5)
        
        # Prepare data
        df = pd.DataFrame(self.firewall.logged_packets)
        
        # Protocol distribution pie chart
        protocol_counts = df['protocol'].value_counts()
        colors = plt.cm.Dark2(range(len(protocol_counts)))
        ax1.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', 
                startangle=90, colors=colors, textprops={'color': 'white'})
        ax1.set_title('Protocol Distribution', color='white')
        
        # Action distribution bar chart
        action_counts = df['action'].value_counts()
        colors = ['#4CAF50' if a == 'ALLOW' else '#F44336' for a in action_counts.index]
        ax2.bar(action_counts.index, action_counts.values, color=colors)
        ax2.set_title('Action Distribution', color='white')
        ax2.set_ylabel('Count', color='white')
        ax2.tick_params(axis='x', colors='white')
        ax2.tick_params(axis='y', colors='white')
        ax2.set_facecolor('#222222')
        
        # Add to Tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.packet_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def _init_rules_tab(self):
        # Top frame for controls
        controls_frame = ttk.Frame(self.rules_tab)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add rule button
        ttk.Button(controls_frame, text="Add Rule", command=self.show_add_rule_dialog).pack(side=tk.LEFT, padx=5)
        
        # Remove rule button
        self.remove_rule_button = ttk.Button(controls_frame, text="Remove Rule", command=self.remove_selected_rule)
        self.remove_rule_button.pack(side=tk.LEFT, padx=5)
        
        # Rules treeview
        self.rules_tree = ttk.Treeview(self.rules_tab, columns=('src_ip', 'dst_ip', 'protocol', 'action'), show='headings')
        self.rules_tree.heading('src_ip', text='Source IP')
        self.rules_tree.heading('dst_ip', text='Destination IP')
        self.rules_tree.heading('protocol', text='Protocol')
        self.rules_tree.heading('action', text='Action')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.rules_tab, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rules_tree.pack(fill=tk.BOTH, expand=True)
        
        # Load rules
        self.update_rules_list()
        
    def update_rules_list(self):
        self.rules_tree.delete(*self.rules_tree.get_children())
        for rule in self.firewall.rules:
            self.rules_tree.insert('', tk.END, values=(
                rule.get('src_ip', '*'),
                rule.get('dst_ip', '*'),
                rule.get('protocol', '*'),
                rule.get('action', 'BLOCK')
            ))
            
    def show_add_rule_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Rule")
        dialog.geometry("400x300")
        dialog.configure(bg='black')
        
        # Source IP
        ttk.Label(dialog, text="Source IP:").pack(pady=(10, 0))
        src_ip_entry = ttk.Entry(dialog)
        src_ip_entry.pack(fill=tk.X, padx=20, pady=5)
        src_ip_entry.insert(0, '*')
        
        # Destination IP
        ttk.Label(dialog, text="Destination IP:").pack(pady=(10, 0))
        dst_ip_entry = ttk.Entry(dialog)
        dst_ip_entry.pack(fill=tk.X, padx=20, pady=5)
        dst_ip_entry.insert(0, '*')
        
        # Protocol
        ttk.Label(dialog, text="Protocol:").pack(pady=(10, 0))
        protocol_var = tk.StringVar()
        protocol_combobox = ttk.Combobox(dialog, textvariable=protocol_var, values=['*', 'TCP', 'UDP', 'ICMP'])
        protocol_combobox.pack(fill=tk.X, padx=20, pady=5)
        protocol_combobox.set('*')
        
        # Action
        ttk.Label(dialog, text="Action:").pack(pady=(10, 0))
        action_var = tk.StringVar(value='BLOCK')
        ttk.Radiobutton(dialog, text="Allow", variable=action_var, value='ALLOW').pack(anchor=tk.W, padx=20)
        ttk.Radiobutton(dialog, text="Block", variable=action_var, value='BLOCK').pack(anchor=tk.W, padx=20)
        
        # Add button
        ttk.Button(dialog, text="Add Rule", command=lambda: self.add_rule_from_dialog(
            src_ip_entry.get(),
            dst_ip_entry.get(),
            protocol_var.get(),
            action_var.get(),
            dialog
        )).pack(pady=20)
        
    def add_rule_from_dialog(self, src_ip, dst_ip, protocol, action, dialog):
        if not src_ip and not dst_ip and protocol == '*':
            messagebox.showerror("Error", "At least one field must be specified")
            return
            
        rule = {
            'src_ip': src_ip if src_ip else '*',
            'dst_ip': dst_ip if dst_ip else '*',
            'protocol': protocol,
            'action': action
        }
        
        self.firewall.add_rule(rule)
        self.update_rules_list()
        dialog.destroy()
        
    def remove_selected_rule(self):
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to remove")
            return
            
        index = self.rules_tree.index(selected[0])
        if self.firewall.remove_rule(index):
            self.update_rules_list()
            
    def _init_blacklist_tab(self):
        # Top frame for controls
        controls_frame = ttk.Frame(self.blacklist_tab)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add IP button
        ttk.Button(controls_frame, text="Add IP", command=self.show_add_blacklist_dialog).pack(side=tk.LEFT, padx=5)
        
        # Remove IP button
        self.remove_blacklist_button = ttk.Button(controls_frame, text="Remove IP", command=self.remove_selected_blacklist)
        self.remove_blacklist_button.pack(side=tk.LEFT, padx=5)
        
        # Blacklist listbox
        self.blacklist_tree = ttk.Treeview(self.blacklist_tab, columns=('ip',), show='headings')
        self.blacklist_tree.heading('ip', text='IP Address')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.blacklist_tab, orient=tk.VERTICAL, command=self.blacklist_tree.yview)
        self.blacklist_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.blacklist_tree.pack(fill=tk.BOTH, expand=True)
        
        # Load blacklist
        self.update_blacklist()
        
    def update_blacklist(self):
        self.blacklist_tree.delete(*self.blacklist_tree.get_children())
        for ip in self.firewall.blacklist:
            self.blacklist_tree.insert('', tk.END, values=(ip,))
            
    def show_add_blacklist_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add to Blacklist")
        dialog.geometry("300x150")
        dialog.configure(bg='black')
        
        ttk.Label(dialog, text="IP Address:").pack(pady=(20, 5))
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Button(dialog, text="Add", command=lambda: self.add_to_blacklist_from_dialog(ip_entry.get(), dialog)).pack(pady=10)
        
    def add_to_blacklist_from_dialog(self, ip, dialog):
        if not ip:
            messagebox.showerror("Error", "IP address cannot be empty")
            return
            
        try:
            socket.inet_aton(ip)
            self.firewall.add_to_blacklist(ip)
            self.update_blacklist()
            dialog.destroy()
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address")
            
    def remove_selected_blacklist(self):
        selected = self.blacklist_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an IP to remove")
            return
            
        ip = self.blacklist_tree.item(selected[0])['values'][0]
        if self.firewall.remove_from_blacklist(ip):
            self.update_blacklist()
            
    def _init_whitelist_tab(self):
        # Top frame for controls
        controls_frame = ttk.Frame(self.whitelist_tab)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add IP button
        ttk.Button(controls_frame, text="Add IP", command=self.show_add_whitelist_dialog).pack(side=tk.LEFT, padx=5)
        
        # Remove IP button
        self.remove_whitelist_button = ttk.Button(controls_frame, text="Remove IP", command=self.remove_selected_whitelist)
        self.remove_whitelist_button.pack(side=tk.LEFT, padx=5)
        
        # Whitelist listbox
        self.whitelist_tree = ttk.Treeview(self.whitelist_tab, columns=('ip',), show='headings')
        self.whitelist_tree.heading('ip', text='IP Address')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.whitelist_tab, orient=tk.VERTICAL, command=self.whitelist_tree.yview)
        self.whitelist_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.whitelist_tree.pack(fill=tk.BOTH, expand=True)
        
        # Load whitelist
        self.update_whitelist()
        
    def update_whitelist(self):
        self.whitelist_tree.delete(*self.whitelist_tree.get_children())
        for ip in self.firewall.whitelist:
            self.whitelist_tree.insert('', tk.END, values=(ip,))
            
    def show_add_whitelist_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add to Whitelist")
        dialog.geometry("300x150")
        dialog.configure(bg='black')
        
        ttk.Label(dialog, text="IP Address:").pack(pady=(20, 5))
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Button(dialog, text="Add", command=lambda: self.add_to_whitelist_from_dialog(ip_entry.get(), dialog)).pack(pady=10)
        
    def add_to_whitelist_from_dialog(self, ip, dialog):
        if not ip:
            messagebox.showerror("Error", "IP address cannot be empty")
            return
            
        try:
            socket.inet_aton(ip)
            self.firewall.add_to_whitelist(ip)
            self.update_whitelist()
            dialog.destroy()
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address")
            
    def remove_selected_whitelist(self):
        selected = self.whitelist_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an IP to remove")
            return
            
        ip = self.whitelist_tree.item(selected[0])['values'][0]
        if self.firewall.remove_from_whitelist(ip):
            self.update_whitelist()
            
    def _init_logs_tab(self):
        # Logs text area
        self.logs_text = scrolledtext.ScrolledText(
            self.logs_tab,
            wrap=tk.WORD,
            width=80,
            height=25,
            bg='#222',
            fg='white',
            insertbackground='white'
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Load logs
        self.update_logs()
        
    def update_logs(self):
        self.logs_text.delete(1.0, tk.END)
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                self.logs_text.insert(tk.END, f.read())
        else:
            self.logs_text.insert(tk.END, "No logs available")
            
        # Auto-scroll to bottom
        self.logs_text.see(tk.END)
        
    def _init_stats_tab(self):
        # Stats frame
        stats_frame = ttk.Frame(self.stats_tab)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Network stats
        network_stats_frame = ttk.LabelFrame(stats_frame, text="Network Statistics")
        network_stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.network_stats_text = scrolledtext.ScrolledText(
            network_stats_frame,
            wrap=tk.WORD,
            width=80,
            height=10,
            bg='#222',
            fg='white',
            insertbackground='white'
        )
        self.network_stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Packet stats frame
        packet_stats_frame = ttk.LabelFrame(stats_frame, text="Packet Statistics")
        packet_stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.packet_stats_canvas = tk.Canvas(packet_stats_frame, bg='black', highlightthickness=0)
        self.packet_stats_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Update stats
        self.update_stats()
        
    def update_stats(self):
        # Network stats
        stats = self.firewall.get_network_stats()
        self.network_stats_text.delete(1.0, tk.END)
        
        if stats:
            for interface, data in stats.items():
                self.network_stats_text.insert(tk.END, f"Interface: {interface}\n")
                self.network_stats_text.insert(tk.END, f"  Bytes Sent: {data.bytes_sent}\n")
                self.network_stats_text.insert(tk.END, f"  Bytes Received: {data.bytes_recv}\n")
                self.network_stats_text.insert(tk.END, f"  Packets Sent: {data.packets_sent}\n")
                self.network_stats_text.insert(tk.END, f"  Packets Received: {data.packets_recv}\n\n")
        else:
            self.network_stats_text.insert(tk.END, "No network statistics available")
            
        # Packet stats
        self.update_packet_stats_chart()
        
        # Schedule next update
        self.root.after(5000, self.update_stats)
        
    def update_packet_stats_chart(self):
        # Clear previous chart
        self.packet_stats_canvas.delete('all')
        
        if not self.firewall.logged_packets:
            tk.Label(self.packet_stats_canvas, text="No packet statistics available", 
                    bg='black', fg='white').pack(fill=tk.BOTH, expand=True)
            return
            
        # Create figure
        fig = plt.Figure(figsize=(8, 6))
        fig.patch.set_facecolor('#222222')
        ax = fig.add_subplot(111)
        
        # Prepare data
        df = pd.DataFrame(self.firewall.logged_packets)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        
        # Resample by minute
        resampled = df.resample('1T').size()
        
        # Plot
        resampled.plot(ax=ax, color='cyan', linewidth=2)
        ax.set_title('Packet Traffic Over Time', color='white')
        ax.set_ylabel('Packets per minute', color='white')
        ax.set_xlabel('Time', color='white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        ax.set_facecolor('#222222')
        
        # Add to Tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.packet_stats_canvas)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def _init_console_tab(self):
        # Console output
        self.console_output = scrolledtext.ScrolledText(
            self.console_tab,
            wrap=tk.WORD,
            width=80,
            height=25,
            bg='#222',
            fg='white',
            insertbackground='white'
        )
        self.console_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Disable editing
        self.console_output.config(state=tk.DISABLED)
        
    def execute_command(self, event=None):
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return
            
        # Add to history
        self.firewall.command_history.append(cmd)
        self.firewall.save_command_history()
        
        # Clear entry
        self.cmd_entry.delete(0, tk.END)
        
        # Process command
        self._process_command(cmd)
        
    def _process_command(self, cmd):
        parts = cmd.split()
        if not parts:
            return
            
        command = parts[0].lower()
        args = parts[1:]
        
        self._console_print(f"> {cmd}\n")
        
        try:
            if command == 'help':
                self._show_help()
            elif command == 'ping':
                self._ping_command(args)
            elif command == 'start':
                self._start_command(args)
            elif command == 'stop':
                self._stop_command()
            elif command == 'add':
                self._add_command(args)
            elif command == 'remove':
                self._remove_command(args)
            elif command == 'exit':
                self.root.quit()
            elif command == 'clear':
                self.console_output.config(state=tk.NORMAL)
                self.console_output.delete(1.0, tk.END)
                self.console_output.config(state=tk.DISABLED)
            elif command == 'config':
                self._config_command(args)
            elif command == 'history':
                self._show_history()
            elif command == 'status':
                self._show_status()
            elif command == 'view':
                self._view_command(args)
            else:
                self._console_print(f"Unknown command: {command}\nType 'help' for available commands\n")
        except Exception as e:
            self._console_print(f"Error: {str(e)}\n")
            
    def _console_print(self, text):
        self.console_output.config(state=tk.NORMAL)
        self.console_output.insert(tk.END, text)
        self.console_output.see(tk.END)
        self.console_output.config(state=tk.DISABLED)
        
    def _show_help(self):
        help_text = """
Available commands:
  help                     - Show this help message
  ping <ip>                - Ping an IP address
  start monitoring [ip]    - Start packet monitoring (optional interface IP)
  stop                     - Stop packet monitoring
  add ip <ip>              - Add IP to blacklist
  remove ip <ip>           - Remove IP from blacklist
  exit                     - Exit the application
  clear                    - Clear the console
  config telegram token <token>    - Set Telegram bot token
  config telegram chat_id <id>     - Set Telegram chat ID
  history                  - Show command history
  status                   - Show firewall status
  view <tab>              - Switch to specified tab (dashboard, rules, blacklist, whitelist, logs, stats, console)
"""
        self._console_print(help_text)
        
    def _ping_command(self, args):
        if len(args) < 1:
            self._console_print("Usage: ping <ip>\n")
            return
            
        ip = args[0]
        success, output = self.firewall.ping(ip)
        self._console_print(output + "\n")
        
    def _start_command(self, args):
        if len(args) < 1 or args[0].lower() != 'monitoring':
            self._console_print("Usage: start monitoring [ip]\n")
            return
            
        interface = args[1] if len(args) > 1 else None
        success, message = self.firewall.start_monitoring(interface)
        self._console_print(f"{message}\n")
        
    def _stop_command(self):
        success, message = self.firewall.stop_monitoring()
        self._console_print(f"{message}\n")
        
    def _add_command(self, args):
        if len(args) < 2 or args[0].lower() != 'ip':
            self._console_print("Usage: add ip <ip>\n")
            return
            
        ip = args[1]
        try:
            socket.inet_aton(ip)
            self.firewall.add_to_blacklist(ip)
            self._console_print(f"Added {ip} to blacklist\n")
            self.update_blacklist()
        except socket.error:
            self._console_print(f"Invalid IP address: {ip}\n")
            
    def _remove_command(self, args):
        if len(args) < 2 or args[0].lower() != 'ip':
            self._console_print("Usage: remove ip <ip>\n")
            return
            
        ip = args[1]
        if self.firewall.remove_from_blacklist(ip):
            self._console_print(f"Removed {ip} from blacklist\n")
            self.update_blacklist()
        else:
            self._console_print(f"IP {ip} not found in blacklist\n")
            
    def _config_command(self, args):
        if len(args) < 3:
            self._console_print("Usage: config telegram token <token> OR config telegram chat_id <id>\n")
            return
            
        if args[0].lower() == 'telegram':
            if args[1].lower() == 'token':
                self.firewall.telegram_token = args[2]
                self.firewall.save_config()
                self._console_print("Telegram token configured\n")
            elif args[1].lower() == 'chat_id':
                self.firewall.telegram_chat_id = args[2]
                self.firewall.save_config()
                self._console_print("Telegram chat ID configured\n")
            else:
                self._console_print("Unknown Telegram config option\n")
        else:
            self._console_print("Unknown config section\n")
            
    def _show_history(self):
        self._console_print("Command history:\n")
        for i, cmd in enumerate(self.firewall.command_history, 1):
            self._console_print(f"  {i}. {cmd}\n")
            
    def _show_status(self):
        status = self.firewall.get_status()
        self._console_print("Firewall status:\n")
        self._console_print(f"  Monitoring: {'ON' if status['monitoring'] else 'OFF'}\n")
        self._console_print(f"  Rules: {status['rules_count']}\n")
        self._console_print(f"  Blacklist: {status['blacklist_count']}\n")
        self._console_print(f"  Whitelist: {status['whitelist_count']}\n")
        self._console_print(f"  Logged packets: {status['logged_packets']}\n")
        self._console_print(f"  Telegram alerts: {'ON' if status['telegram_configured'] else 'OFF'}\n")
        
    def _view_command(self, args):
        if len(args) < 1:
            self._console_print("Usage: view <tab>\nAvailable tabs: dashboard, rules, blacklist, whitelist, logs, stats, console\n")
            return
            
        tab = args[0].lower()
        tab_map = {
            'dashboard': 0,
            'rules': 1,
            'blacklist': 2,
            'whitelist': 3,
            'logs': 4,
            'stats': 5,
            'console': 6
        }
        
        if tab in tab_map:
            self.tab_container.select(tab_map[tab])
            self._console_print(f"Switched to {tab} tab\n")
        else:
            self._console_print(f"Unknown tab: {tab}\n")
            
    def toggle_monitoring(self):
        if self.firewall.monitoring:
            success, message = self.firewall.stop_monitoring()
        else:
            success, message = self.firewall.start_monitoring()
            
        if success:
            self.monitor_button.config(text="Stop Monitoring" if self.firewall.monitoring else "Start Monitoring")
            messagebox.showinfo("Info", message)
        else:
            messagebox.showerror("Error", message)
            
    def clear_logs(self):
        self.firewall.clear_logs()
        messagebox.showinfo("Info", "Packet logs cleared")
        
    def export_rules(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump({
                        'rules': self.firewall.rules,
                        'blacklist': self.firewall.blacklist,
                        'whitelist': self.firewall.whitelist
                    }, f, indent=4)
                messagebox.showinfo("Success", "Rules exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export rules: {str(e)}")
                
    def import_rules(self):
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                    self.firewall.rules = data.get('rules', [])
                    self.firewall.blacklist = data.get('blacklist', [])
                    self.firewall.whitelist = data.get('whitelist', [])
                    self.firewall.save_config()
                    
                # Update UI
                self.update_rules_list()
                self.update_blacklist()
                self.update_whitelist()
                messagebox.showinfo("Success", "Rules imported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import rules: {str(e)}")
                
    def show_telegram_config(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Telegram Configuration")
        dialog.geometry("400x250")
        dialog.configure(bg='black')
        
        # Token
        ttk.Label(dialog, text="Bot Token:").pack(pady=(20, 5))
        token_entry = ttk.Entry(dialog, width=40)
        token_entry.pack(padx=20)
        if self.firewall.telegram_token:
            token_entry.insert(0, self.firewall.telegram_token)
            
        # Chat ID
        ttk.Label(dialog, text="Chat ID:").pack(pady=(10, 5))
        chat_id_entry = ttk.Entry(dialog, width=40)
        chat_id_entry.pack(padx=20)
        if self.firewall.telegram_chat_id:
            chat_id_entry.insert(0, self.firewall.telegram_chat_id)
            
        # Save button
        ttk.Button(dialog, text="Save", command=lambda: self.save_telegram_config(
            token_entry.get(),
            chat_id_entry.get(),
            dialog
        )).pack(pady=20)
        
    def save_telegram_config(self, token, chat_id, dialog):
        self.firewall.telegram_token = token if token else None
        self.firewall.telegram_chat_id = chat_id if chat_id else None
        self.firewall.save_config()
        dialog.destroy()
        messagebox.showinfo("Success", "Telegram configuration saved")
        
    def show_interface_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Interface Settings")
        dialog.geometry("400x200")
        dialog.configure(bg='black')
        
        # Get available interfaces
        interfaces = []
        try:
            interfaces = list(psutil.net_if_addrs().keys())
        except Exception as e:
            logging.error(f"Error getting interfaces: {str(e)}")
            
        # Interface selection
        ttk.Label(dialog, text="Monitoring Interface:").pack(pady=(20, 5))
        interface_var = tk.StringVar()
        interface_combobox = ttk.Combobox(dialog, textvariable=interface_var, values=interfaces)
        interface_combobox.pack(fill=tk.X, padx=20, pady=5)
        
        # Save button
        ttk.Button(dialog, text="Save", command=lambda: self.save_interface_settings(
            interface_var.get(),
            dialog
        )).pack(pady=20)
        
    def save_interface_settings(self, interface, dialog):
        # In a real application, you would save this setting
        dialog.destroy()
        messagebox.showinfo("Info", f"Monitoring will use interface: {interface if interface else 'default'}")
        
    def show_about(self):
        messagebox.showinfo(
            "About",
            "Advanced Packet Filtering Firewall\n\n"
            "Version 1.0\n"
            "A comprehensive network security tool with packet filtering capabilities\n"
            "and real-time monitoring features."
        )
        
    def show_documentation(self):
        doc_text = """
Packet Filtering Firewall Documentation

1. Dashboard:
- Overview of firewall status and quick statistics
- Visual representation of packet traffic

2. Rules:
- Define packet filtering rules based on:
  - Source IP
  - Destination IP
  - Protocol (TCP, UDP, ICMP)
  - Action (Allow/Block)

3. Blacklist/Whitelist:
- Manage lists of IP addresses to always block or allow

4. Logs:
- View detailed packet logs and firewall events

5. Statistics:
- Network interface statistics
- Packet traffic analysis

6. Console:
- Command-line interface for advanced operations
"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Documentation")
        dialog.geometry("600x500")
        dialog.configure(bg='black')
        
        text = scrolledtext.ScrolledText(
            dialog,
            wrap=tk.WORD,
            width=70,
            height=30,
            bg='#222',
            fg='white',
            insertbackground='white'
        )
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, doc_text)
        text.config(state=tk.DISABLED)
        
    def show_dashboard(self):
        self.tab_container.select(0)
        
    def show_rules(self):
        self.tab_container.select(1)
        
    def show_blacklist(self):
        self.tab_container.select(2)
        
    def show_whitelist(self):
        self.tab_container.select(3)
        
    def show_logs(self):
        self.tab_container.select(4)
        self.update_logs()
        
    def show_stats(self):
        self.tab_container.select(5)
        self.update_stats()

def main():
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()
    
    # Clean up
    app.firewall.stop_monitoring()
    app.firewall.save_command_history()

if __name__ == "__main__":
    main()