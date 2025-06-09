#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import socket
import threading
import time
from datetime import datetime
import re
import ipaddress
import subprocess
import os
import json
import hashlib
import requests
from urllib.parse import urlparse

class ThreatIntelligence:
    def __init__(self):
        self.malware_hashes = set()
        self.malicious_ips = set()
        self.suspicious_domains = set()
        self.load_threat_data()
    
    def load_threat_data(self):
        try:
            if os.path.exists('threat_data.json'):
                with open('threat_data.json', 'r') as f:
                    data = json.load(f)
                    self.malware_hashes = set(data.get('hashes', []))
                    self.malicious_ips = set(data.get('ips', []))
                    self.suspicious_domains = set(data.get('domains', []))
        except:
            pass
    
    def save_threat_data(self):
        try:
            data = {
                'hashes': list(self.malware_hashes),
                'ips': list(self.malicious_ips),
                'domains': list(self.suspicious_domains)
            }
            with open('threat_data.json', 'w') as f:
                json.dump(data, f)
        except:
            pass
    
    def check_file_hash(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
                return file_hash in self.malware_hashes
        except:
            return False
    
    def check_ip_reputation(self, ip):
        return ip in self.malicious_ips
    
    def add_malicious_ip(self, ip):
        self.malicious_ips.add(ip)
        self.save_threat_data()

class NetworkTroubleshooter:
    def __init__(self):
        self.tools_available = self.check_available_tools()
    
    def check_available_tools(self):
        tools = {}
        commands = {
            'netstat': ['netstat', '-h'],
            'nmap': ['nmap', '--version'],
            'tcpdump': ['tcpdump', '--version'],
            'wireshark': ['tshark', '-v'],
            'ss': ['ss', '--help']
        }
        
        for tool, cmd in commands.items():
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                tools[tool] = True
            except:
                tools[tool] = False
        
        return tools
    
    def ping_host(self, host, count=4):
        try:
            if os.name == 'nt':
                cmd = ['ping', '-n', str(count), host]
            else:
                cmd = ['ping', '-c', str(count), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout
        except:
            return False, "Ping failed"
    
    def traceroute(self, host):
        try:
            if os.name == 'nt':
                cmd = ['tracert', host]
            else:
                cmd = ['traceroute', host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout
        except:
            return "Traceroute failed"
    
    def nslookup(self, host):
        try:
            cmd = ['nslookup', host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except:
            return "Nslookup failed"
    
    def port_scan(self, host, ports):
        if not self.tools_available.get('nmap', False):
            return "Nmap not available"
        
        try:
            port_range = ','.join(map(str, ports[:10]))
            cmd = ['nmap', '-p', port_range, host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout
        except:
            return "Port scan failed"
    
    def get_whois_info(self, ip):
        try:
            if os.name == 'nt':
                return "Whois not available on Windows"
            
            cmd = ['whois', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.stdout
        except:
            return "Whois failed"
    
    def analyze_connection_latency(self, host, port, samples=5):
        latencies = []
        for _ in range(samples):
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                end_time = time.time()
                sock.close()
                
                if result == 0:
                    latencies.append((end_time - start_time) * 1000)
                else:
                    latencies.append(None)
            except:
                latencies.append(None)
            time.sleep(0.1)
        
        valid_latencies = [l for l in latencies if l is not None]
        if valid_latencies:
            return {
                'avg': sum(valid_latencies) / len(valid_latencies),
                'min': min(valid_latencies),
                'max': max(valid_latencies),
                'success_rate': len(valid_latencies) / samples * 100
            }
        return None

class PacketCapture:
    def __init__(self, interface=None):
        self.interface = interface
        self.capturing = False
        self.packets = []
        self.capture_thread = None
    
    def start_capture(self, filter_expr="", max_packets=1000):
        if self.capturing:
            return False
        
        self.capturing = True
        self.packets = []
        self.capture_thread = threading.Thread(
            target=self._capture_packets, 
            args=(filter_expr, max_packets),
            daemon=True
        )
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def _capture_packets(self, filter_expr, max_packets):
        try:
            import scapy.all as scapy
            
            def packet_handler(packet):
                if not self.capturing or len(self.packets) >= max_packets:
                    return False
                
                packet_info = {
                    'timestamp': datetime.now(),
                    'src': packet.get('IP', {}).get('src', 'Unknown'),
                    'dst': packet.get('IP', {}).get('dst', 'Unknown'),
                    'protocol': packet.get('IP', {}).get('proto', 'Unknown'),
                    'size': len(packet),
                    'summary': packet.summary()
                }
                self.packets.append(packet_info)
                return True
            
            scapy.sniff(
                iface=self.interface,
                filter=filter_expr,
                prn=packet_handler,
                stop_filter=lambda x: not self.capturing
            )
        except ImportError:
            pass
        except:
            pass
    
    def get_packets(self):
        return self.packets.copy()
    
    def export_packets(self, filename):
        try:
            with open(filename, 'w') as f:
                for packet in self.packets:
                    f.write(f"{packet['timestamp']} - {packet['summary']}\n")
            return True
        except:
            return False

class ConnectionClassifier:
    def __init__(self):
        self.safe_ports = {
            53, 80, 443, 993, 995, 587, 143, 110, 25, 21, 22, 3389, 5060, 5061,
            123, 161, 162, 389, 636, 88, 135, 139, 445, 1433, 1521, 3306, 5432
        }
        
        self.suspicious_ports = {
            1337, 31337, 12345, 27374, 9999, 4444, 5555, 6666, 7777, 8080,
            1080, 3128, 6667, 6668, 8888, 9000, 9001, 1234, 2222, 4321
        }
        
        self.legitimate_processes = {
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe', 'brave.exe',
            'svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe',
            'lsass.exe', 'services.exe', 'spoolsv.exe', 'wininit.exe',
            'dwm.exe', 'conhost.exe', 'audiodg.exe', 'dllhost.exe',
            'taskhost.exe', 'taskhostw.exe', 'steam.exe', 'discord.exe',
            'skype.exe', 'teams.exe', 'outlook.exe', 'thunderbird.exe',
            'filezilla.exe', 'dropbox.exe', 'onedrive.exe', 'python.exe',
            'java.exe', 'node.exe', 'code.exe', 'devenv.exe'
        }
        
        self.suspicious_processes = {
            'cmd.exe', 'powershell.exe', 'nc.exe', 'netcat.exe', 'ncat.exe',
            'psexec.exe', 'mimikatz.exe', 'meterpreter.exe', 'backdoor.exe',
            'keylogger.exe', 'rat.exe', 'trojan.exe', 'hack.exe'
        }
        
        self.threat_intel = ThreatIntelligence()
    
    def classify_connection(self, conn_info):
        risk_score = 0
        reasons = []
        
        process_name = conn_info['process'].lower()
        local_port = conn_info['local_port']
        remote_addr = conn_info.get('remote_ip', '')
        status = conn_info['status']
        
        if process_name in self.legitimate_processes:
            risk_score -= 2
            reasons.append("Processus légitime connu")
        elif process_name in self.suspicious_processes:
            risk_score += 3
            reasons.append("Processus potentiellement suspect")
        
        if local_port in self.safe_ports:
            risk_score -= 1
            reasons.append("Port de service standard")
        elif local_port in self.suspicious_ports:
            risk_score += 2
            reasons.append("Port suspect/inhabituel")
        elif local_port > 49152:
            risk_score += 1
            reasons.append("Port dynamique")
        
        if remote_addr and remote_addr != "N/A":
            try:
                ip = ipaddress.ip_address(remote_addr.split(':')[0])
                if ip.is_private:
                    risk_score -= 1
                    reasons.append("Connexion locale/privée")
                elif ip.is_loopback:
                    risk_score -= 2
                    reasons.append("Connexion locale (loopback)")
                else:
                    if self.threat_intel.check_ip_reputation(str(ip)):
                        risk_score += 3
                        reasons.append("IP malveillante connue")
                    elif self._is_suspicious_ip(str(ip)):
                        risk_score += 2
                        reasons.append("IP potentiellement suspecte")
            except:
                pass
        
        if status == "LISTEN":
            risk_score += 1
            reasons.append("Port en écoute")
        elif status == "ESTABLISHED":
            if remote_addr == "N/A":
                risk_score += 1
                reasons.append("Connexion établie sans destination claire")
        
        if conn_info.get('process_path'):
            if self.threat_intel.check_file_hash(conn_info['process_path']):
                risk_score += 4
                reasons.append("Fichier malveillant détecté")
        
        if risk_score >= 3:
            return "danger", reasons
        elif risk_score >= 1:
            return "warning", reasons
        else:
            return "safe", reasons
    
    def _is_suspicious_ip(self, ip):
        suspicious_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16'
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in suspicious_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return False
        except:
            pass
        
        return False

class TroubleshooterWindow:
    def __init__(self, parent, conn_info):
        self.parent = parent
        self.conn_info = conn_info
        self.troubleshooter = NetworkTroubleshooter()
        self.packet_capture = PacketCapture()
        
        self.window = tk.Toplevel(parent)
        self.window.title(f"Troubleshooter - {conn_info['process']}")
        self.window.geometry("900x700")
        
        self.setup_ui()
    
    def setup_ui(self):
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.create_basic_tests_tab(notebook)
        self.create_network_analysis_tab(notebook)
        self.create_packet_capture_tab(notebook)
        self.create_security_analysis_tab(notebook)
    
    def create_basic_tests_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Tests de Base")
        
        info_frame = ttk.LabelFrame(frame, text="Informations de Connexion", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, text=f"Processus: {self.conn_info['process']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"PID: {self.conn_info['pid']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Port local: {self.conn_info['local_port']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Adresse distante: {self.conn_info.get('remote_addr', 'N/A')}").pack(anchor=tk.W)
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(control_frame, text="Ping", command=self.run_ping).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Traceroute", command=self.run_traceroute).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="NSLookup", command=self.run_nslookup).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Whois", command=self.run_whois).pack(side=tk.LEFT)
        
        self.basic_results = tk.Text(frame, wrap=tk.WORD, font=("Consolas", 9))
        scrollbar1 = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.basic_results.yview)
        self.basic_results.configure(yscrollcommand=scrollbar1.set)
        
        self.basic_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar1.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_network_analysis_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Analyse Réseau")
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(control_frame, text="Analyser Latence", command=self.analyze_latency).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Scanner Ports", command=self.scan_ports).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Test Bande Passante", command=self.test_bandwidth).pack(side=tk.LEFT)
        
        self.network_results = tk.Text(frame, wrap=tk.WORD, font=("Consolas", 9))
        scrollbar2 = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.network_results.yview)
        self.network_results.configure(yscrollcommand=scrollbar2.set)
        
        self.network_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_packet_capture_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Capture de Paquets")
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(control_frame, text="Filtre:").pack(side=tk.LEFT)
        self.filter_entry = ttk.Entry(control_frame, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=(5, 10))
        
        self.capture_btn = ttk.Button(control_frame, text="Démarrer Capture", command=self.toggle_capture)
        self.capture_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(control_frame, text="Exporter", command=self.export_packets).pack(side=tk.LEFT)
        
        self.packet_tree = ttk.Treeview(frame, columns=('Time', 'Src', 'Dst', 'Protocol', 'Size'), show='headings')
        
        for col in ('Time', 'Src', 'Dst', 'Protocol', 'Size'):
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=150)
        
        scrollbar3 = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar3.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        
        threading.Thread(target=self.update_packet_display, daemon=True).start()
    
    def create_security_analysis_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Analyse Sécurité")
        
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(control_frame, text="Vérifier Réputation IP", command=self.check_ip_reputation).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Analyser Fichier", command=self.analyze_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Bloquer IP", command=self.block_ip).pack(side=tk.LEFT)
        
        self.security_results = tk.Text(frame, wrap=tk.WORD, font=("Consolas", 9))
        scrollbar4 = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.security_results.yview)
        self.security_results.configure(yscrollcommand=scrollbar4.set)
        
        self.security_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar4.pack(side=tk.RIGHT, fill=tk.Y)
    
    def run_ping(self):
        remote_ip = self.get_remote_ip()
        if not remote_ip:
            return
        
        self.basic_results.insert(tk.END, f"=== PING {remote_ip} ===\n")
        self.basic_results.update()
        
        def ping_thread():
            success, output = self.troubleshooter.ping_host(remote_ip)
            self.basic_results.insert(tk.END, output + "\n\n")
            self.basic_results.see(tk.END)
        
        threading.Thread(target=ping_thread, daemon=True).start()
    
    def run_traceroute(self):
        remote_ip = self.get_remote_ip()
        if not remote_ip:
            return
        
        self.basic_results.insert(tk.END, f"=== TRACEROUTE {remote_ip} ===\n")
        self.basic_results.update()
        
        def trace_thread():
            output = self.troubleshooter.traceroute(remote_ip)
            self.basic_results.insert(tk.END, output + "\n\n")
            self.basic_results.see(tk.END)
        
        threading.Thread(target=trace_thread, daemon=True).start()
    
    def run_nslookup(self):
        remote_ip = self.get_remote_ip()
        if not remote_ip:
            return
        
        self.basic_results.insert(tk.END, f"=== NSLOOKUP {remote_ip} ===\n")
        self.basic_results.update()
        
        def nslookup_thread():
            output = self.troubleshooter.nslookup(remote_ip)
            self.basic_results.insert(tk.END, output + "\n\n")
            self.basic_results.see(tk.END)
        
        threading.Thread(target=nslookup_thread, daemon=True).start()
    
    def run_whois(self):
        remote_ip = self.get_remote_ip()
        if not remote_ip:
            return
        
        self.basic_results.insert(tk.END, f"=== WHOIS {remote_ip} ===\n")
        self.basic_results.update()
        
        def whois_thread():
            output = self.troubleshooter.get_whois_info(remote_ip)
            self.basic_results.insert(tk.END, output + "\n\n")
            self.basic_results.see(tk.END)
        
        threading.Thread(target=whois_thread, daemon=True).start()
    
    def analyze_latency(self):
        remote_ip = self.get_remote_ip()
        remote_port = self.get_remote_port()
        if not remote_ip or not remote_port:
            return
        
        self.network_results.insert(tk.END, f"=== ANALYSE LATENCE {remote_ip}:{remote_port} ===\n")
        self.network_results.update()
        
        def latency_thread():
            result = self.troubleshooter.analyze_connection_latency(remote_ip, remote_port)
            if result:
                output = f"Latence moyenne: {result['avg']:.2f}ms\n"
                output += f"Latence min: {result['min']:.2f}ms\n"
                output += f"Latence max: {result['max']:.2f}ms\n"
                output += f"Taux de succès: {result['success_rate']:.1f}%\n"
            else:
                output = "Impossible de mesurer la latence\n"
            
            self.network_results.insert(tk.END, output + "\n")
            self.network_results.see(tk.END)
        
        threading.Thread(target=latency_thread, daemon=True).start()
    
    def scan_ports(self):
        remote_ip = self.get_remote_ip()
        if not remote_ip:
            return
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        self.network_results.insert(tk.END, f"=== SCAN PORTS {remote_ip} ===\n")
        self.network_results.update()
        
        def scan_thread():
            output = self.troubleshooter.port_scan(remote_ip, common_ports)
            self.network_results.insert(tk.END, output + "\n\n")
            self.network_results.see(tk.END)
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def test_bandwidth(self):
        self.network_results.insert(tk.END, "=== TEST BANDE PASSANTE ===\n")
        self.network_results.insert(tk.END, "Fonctionnalité en développement\n\n")
        self.network_results.see(tk.END)
    
    def toggle_capture(self):
        if not self.packet_capture.capturing:
            filter_expr = self.filter_entry.get()
            if self.packet_capture.start_capture(filter_expr):
                self.capture_btn.config(text="Arrêter Capture")
        else:
            self.packet_capture.stop_capture()
            self.capture_btn.config(text="Démarrer Capture")
    
    def update_packet_display(self):
        while True:
            if self.packet_capture.capturing:
                packets = self.packet_capture.get_packets()
                current_count = len(self.packet_tree.get_children())
                
                for packet in packets[current_count:]:
                    self.packet_tree.insert('', tk.END, values=(
                        packet['timestamp'].strftime('%H:%M:%S.%f')[:-3],
                        packet['src'],
                        packet['dst'],
                        packet['protocol'],
                        packet['size']
                    ))
            
            time.sleep(1)
    
    def export_packets(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            if self.packet_capture.export_packets(filename):
                messagebox.showinfo("Export", f"Paquets exportés vers {filename}")
            else:
                messagebox.showerror("Erreur", "Impossible d'exporter les paquets")
    
    def check_ip_reputation(self):
        remote_ip = self.get_remote_ip()
        if not remote_ip:
            return
        
        self.security_results.insert(tk.END, f"=== VÉRIFICATION RÉPUTATION {remote_ip} ===\n")
        
        threat_intel = ThreatIntelligence()
        if threat_intel.check_ip_reputation(remote_ip):
            self.security_results.insert(tk.END, "⚠️ IP MALVEILLANTE DÉTECTÉE ⚠️\n")
        else:
            self.security_results.insert(tk.END, "✅ IP non répertoriée comme malveillante\n")
        
        self.security_results.insert(tk.END, "\n")
        self.security_results.see(tk.END)
    
    def analyze_file(self):
        try:
            process = psutil.Process(self.conn_info['pid'])
            file_path = process.exe()
            
            self.security_results.insert(tk.END, f"=== ANALYSE FICHIER {file_path} ===\n")
            
            threat_intel = ThreatIntelligence()
            if threat_intel.check_file_hash(file_path):
                self.security_results.insert(tk.END, "⚠️ FICHIER MALVEILLANT DÉTECTÉ ⚠️\n")
            else:
                self.security_results.insert(tk.END, "✅ Fichier non répertorié comme malveillant\n")
            
            file_info = f"Taille: {os.path.getsize(file_path)} octets\n"
            file_info += f"Modifié: {datetime.fromtimestamp(os.path.getmtime(file_path))}\n"
            self.security_results.insert(tk.END, file_info)
            
        except Exception as e:
            self.security_results.insert(tk.END, f"Erreur d'analyse: {str(e)}\n")
        
        self.security_results.insert(tk.END, "\n")
        self.security_results.see(tk.END)
    
    def block_ip(self):
        remote_ip = self.get_remote_ip()
        if not remote_ip:
            return
        
        result = messagebox.askyesno(
            "Bloquer IP",
            f"Voulez-vous ajouter {remote_ip} à la liste des IPs malveillantes ?"
        )
        
        if result:
            threat_intel = ThreatIntelligence()
            threat_intel.add_malicious_ip(remote_ip)
            self.security_results.insert(tk.END, f"✅ IP {remote_ip} ajoutée à la liste noire\n\n")
            self.security_results.see(tk.END)
    
    def get_remote_ip(self):
        remote_addr = self.conn_info.get('remote_addr', 'N/A')
        if remote_addr == 'N/A':
            messagebox.showwarning("Attention", "Aucune adresse distante disponible")
            return None
        return remote_addr.split(':')[0]
    
    def get_remote_port(self):
        remote_addr = self.conn_info.get('remote_addr', 'N/A')
        if remote_addr == 'N/A':
            return None
        try:
            return int(remote_addr.split(':')[1])
        except:
            return None

class NetworkMonitor:
    def __init__(self, pid, process_name):
        self.pid = pid
        self.process_name = process_name
        self.monitoring = False
        self.connections_history = []
        self.window = None
        self.bandwidth_data = []
        self.alert_threshold = 1024 * 1024
    
    def start_monitoring(self):
        self.window = tk.Toplevel()
        self.window.title(f"Monitoring - {self.process_name} (PID: {self.pid})")
        self.window.geometry("900x600")
        
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        info_frame = ttk.LabelFrame(main_frame, text="Informations du Processus", padding="5")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, text=f"Processus: {self.process_name}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"PID: {self.pid}").pack(anchor=tk.W)
        
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(control_frame, text="Démarrer", command=self.toggle_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(control_frame, text="Effacer", command=self.clear_history).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Exporter", command=self.export_data).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Alertes", command=self.configure_alerts).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Graphiques", command=self.show_graphs).pack(side=tk.LEFT)
        
        text_frame = ttk.LabelFrame(main_frame, text="Communications en Temps Réel", padding="5")
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.text_area = tk.Text(text_frame, wrap=tk.WORD, font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.text_area.yview)
        self.text_area.configure(yscrollcommand=scrollbar.set)
        
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.text_area.tag_configure("timestamp", foreground="blue")
        self.text_area.tag_configure("new_connection", foreground="green", font=("Consolas", 9, "bold"))
        self.text_area.tag_configure("data_transfer", foreground="orange")
        self.text_area.tag_configure("closed_connection", foreground="red")
        self.text_area.tag_configure("alert", foreground="red", background="yellow", font=("Consolas", 9, "bold"))
        
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.add_log("Monitoring initialisé. Cliquez sur 'Démarrer' pour commencer.")
    
    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.start_btn.config(text="Arrêter")
            self.add_log("=== DÉMARRAGE DU MONITORING ===", "new_connection")
            threading.Thread(target=self.monitor_loop, daemon=True).start()
        else:
            self.monitoring = False
            self.start_btn.config(text="Démarrer")
            self.add_log("=== ARRÊT DU MONITORING ===", "closed_connection")
    
    def monitor_loop(self):
        last_connections = set()
        last_io = None
        suspicious_activity_count = 0
        
        while self.monitoring:
            try:
                if not psutil.pid_exists(self.pid):
                    self.add_log("PROCESSUS TERMINÉ", "closed_connection")
                    break
                
                process = psutil.Process(self.pid)
                current_connections = set()
                
                for conn in process.connections():
                    conn_id = (conn.laddr, conn.raddr if conn.raddr else None, conn.status)
                    current_connections.add(conn_id)
                    
                    if conn_id not in last_connections:
                        self.log_connection_event("NOUVELLE", conn)
                        
                        if self.is_suspicious_connection(conn):
                            suspicious_activity_count += 1
                            self.add_log(f"⚠️ CONNEXION SUSPECTE DÉTECTÉE! (#{suspicious_activity_count})", "alert")
                
                for old_conn in last_connections - current_connections:
                    self.add_log(f"FERMÉE: {old_conn[0]} -> {old_conn[1] or 'N/A'}", "closed_connection")
                
                try:
                    net_io = process.io_counters()
                    if last_io:
                        bytes_sent = net_io.write_bytes - last_io.write_bytes
                        bytes_recv = net_io.read_bytes - last_io.read_bytes
                        
                        if bytes_sent > 0 or bytes_recv > 0:
                            total_traffic = bytes_sent + bytes_recv
                            self.bandwidth_data.append({
                                'timestamp': datetime.now(),
                                'sent': bytes_sent,
                                'received': bytes_recv,
                                'total': total_traffic
                            })
                            
                            if len(self.bandwidth_data) > 100:
                                self.bandwidth_data.pop(0)
                            
                            traffic_msg = f"TRAFIC: ↑{self.format_bytes(bytes_sent)} ↓{self.format_bytes(bytes_recv)}"
                            
                            if total_traffic > self.alert_threshold:
                                traffic_msg += " ⚠️ TRAFIC ÉLEVÉ!"
                                self.add_log(traffic_msg, "alert")
                            else:
                                self.add_log(traffic_msg, "data_transfer")
                    
                    last_io = net_io
                except (psutil.AccessDenied, AttributeError):
                    pass
                
                last_connections = current_connections
                time.sleep(1)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.add_log("ERREUR: Accès au processus perdu", "closed_connection")
                break
            except Exception as e:
                self.add_log(f"ERREUR: {str(e)}", "closed_connection")
        
        self.monitoring = False
        if self.window and self.window.winfo_exists():
            self.start_btn.config(text="Démarrer")
    
    def is_suspicious_connection(self, conn):
        if not conn.raddr:
            return False
        
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        
        suspicious_ports = {1337, 4444, 31337, 12345, 6667}
        if remote_port in suspicious_ports:
            return True
        
        try:
            ip = ipaddress.ip_address(remote_ip)
            if not ip.is_private and not ip.is_loopback:
                threat_intel = ThreatIntelligence()
                if threat_intel.check_ip_reputation(remote_ip):
                    return True
        except:
            pass
        
        return False
    
    def log_connection_event(self, event_type, conn):
        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        
        message = f"{event_type}: {protocol} {local} -> {remote} [{conn.status}]"
        self.add_log(message, "new_connection")
        
        self.connections_history.append({
            'timestamp': datetime.now(),
            'event': event_type,
            'protocol': protocol,
            'local': local,
            'remote': remote,
            'status': conn.status
        })
    
    def add_log(self, message, tag=None):
        if not self.window or not self.window.winfo_exists():
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        
        def update_text():
            self.text_area.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.text_area.insert(tk.END, f"{message}\n", tag)
            self.text_area.see(tk.END)
        
        self.window.after(0, update_text)
    
    def format_bytes(self, bytes_val):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f}TB"
    
    def clear_history(self):
        self.text_area.delete(1.0, tk.END)
        self.connections_history.clear()
        self.bandwidth_data.clear()
        self.add_log("Historique effacé")
    
    def export_data(self):
        try:
            filename = f"network_monitor_{self.process_name}_{self.pid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Monitoring réseau - {self.process_name} (PID: {self.pid})\n")
                f.write(f"Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                
                f.write("HISTORIQUE DES CONNEXIONS:\n")
                for entry in self.connections_history:
                    f.write(f"[{entry['timestamp'].strftime('%H:%M:%S')}] {entry['event']}: "
                           f"{entry['protocol']} {entry['local']} -> {entry['remote']} [{entry['status']}]\n")
                
                f.write("\nSTATISTIQUES DE BANDE PASSANTE:\n")
                for data in self.bandwidth_data:
                    f.write(f"[{data['timestamp'].strftime('%H:%M:%S')}] "
                           f"↑{self.format_bytes(data['sent'])} ↓{self.format_bytes(data['received'])} "
                           f"Total: {self.format_bytes(data['total'])}\n")
            
            messagebox.showinfo("Export", f"Données exportées vers: {filename}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'exporter: {str(e)}")
    
    def configure_alerts(self):
        alert_window = tk.Toplevel(self.window)
        alert_window.title("Configuration des Alertes")
        alert_window.geometry("400x300")
        
        ttk.Label(alert_window, text="Seuil d'alerte trafic (octets):").pack(pady=10)
        
        threshold_var = tk.StringVar(value=str(self.alert_threshold))
        threshold_entry = ttk.Entry(alert_window, textvariable=threshold_var)
        threshold_entry.pack(pady=5)
        
        def save_threshold():
            try:
                self.alert_threshold = int(threshold_var.get())
                messagebox.showinfo("Sauvegardé", f"Seuil configuré à {self.format_bytes(self.alert_threshold)}")
                alert_window.destroy()
            except ValueError:
                messagebox.showerror("Erreur", "Valeur invalide")
        
        ttk.Button(alert_window, text="Sauvegarder", command=save_threshold).pack(pady=10)
    
    def show_graphs(self):
        if not self.bandwidth_data:
            messagebox.showinfo("Info", "Aucune donnée de bande passante disponible")
            return
        
        graph_window = tk.Toplevel(self.window)
        graph_window.title("Graphiques de Trafic")
        graph_window.geometry("800x600")
        
        try:
            import matplotlib.pyplot as plt
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
            
            times = [data['timestamp'] for data in self.bandwidth_data]
            sent_data = [data['sent'] for data in self.bandwidth_data]
            received_data = [data['received'] for data in self.bandwidth_data]
            total_data = [data['total'] for data in self.bandwidth_data]
            
            ax1.plot(times, sent_data, label='Envoyé', color='red')
            ax1.plot(times, received_data, label='Reçu', color='blue')
            ax1.set_title('Trafic Réseau par Seconde')
            ax1.set_ylabel('Octets')
            ax1.legend()
            ax1.grid(True)
            
            ax2.plot(times, total_data, label='Total', color='green')
            ax2.set_title('Trafic Total')
            ax2.set_xlabel('Temps')
            ax2.set_ylabel('Octets')
            ax2.legend()
            ax2.grid(True)
            
            plt.tight_layout()
            
            canvas = FigureCanvasTkAgg(fig, graph_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except ImportError:
            ttk.Label(graph_window, text="Matplotlib non disponible\nInstallez avec: pip install matplotlib").pack(pady=50)
    
    def on_closing(self):
        self.monitoring = False
        self.window.destroy()

class AdvancedPortMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Moniteur de Ports Avancé v2.0")
        self.root.geometry("1400x800")
        
        self.refresh_active = False
        self.auto_refresh = tk.BooleanVar(value=False)
        self.classifier = ConnectionClassifier()
        self.monitors = {}
        self.troubleshooters = {}
        
        self.setup_ui()
        self.setup_menu()
        self.refresh_ports()
    
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Fichier", menu=file_menu)
        file_menu.add_command(label="Exporter tout", command=self.export_all_data)
        file_menu.add_command(label="Importer règles", command=self.import_rules)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.on_closing)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Outils", menu=tools_menu)
        tools_menu.add_command(label="Scanner réseau", command=self.network_scanner)
        tools_menu.add_command(label="Générateur de règles", command=self.rule_generator)
        tools_menu.add_command(label="Analyse forensique", command=self.forensic_analysis)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Aide", menu=help_menu)
        help_menu.add_command(label="À propos", command=self.show_about)
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(title_frame, text="Moniteur de Ports Avancé v2.0", 
                 font=("Arial", 16, "bold")).pack(side=tk.LEFT)
        
        legend_frame = ttk.LabelFrame(title_frame, text="Légende", padding="5")
        legend_frame.pack(side=tk.RIGHT)
        
        legend_items = [("🟢 Sûr", "green"), ("🟠 Douteux", "orange"), ("🔴 Dangereux", "red")]
        
        for i, (text, color) in enumerate(legend_items):
            label = ttk.Label(legend_frame, text=text)
            label.grid(row=0, column=i, padx=5)
        
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(control_frame, text="Actualiser", command=self.refresh_ports).grid(row=0, column=0, padx=(0, 5))
        
        ttk.Checkbutton(control_frame, text="Auto-refresh (3s)", 
                       variable=self.auto_refresh, 
                       command=self.toggle_auto_refresh).grid(row=0, column=1, padx=(0, 10))
        
        ttk.Label(control_frame, text="Filtrer:").grid(row=0, column=2, padx=(10, 5))
        
        self.filter_var = tk.StringVar(value="Tous")
        filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var, 
                                   values=["Tous", "Dangereux", "Douteux", "Sûr", "En écoute", "Établies"], 
                                   state="readonly", width=12)
        filter_combo.grid(row=0, column=3, padx=(0, 10))
        filter_combo.bind('<<ComboboxSelected>>', self.apply_filter)
        
        ttk.Label(control_frame, text="Recherche:").grid(row=0, column=4, padx=(10, 5))
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(control_frame, textvariable=self.search_var, width=15)
        search_entry.grid(row=0, column=5, padx=(0, 5))
        search_entry.bind('<KeyRelease>', self.apply_filter)
        
        ttk.Button(control_frame, text="Effacer", command=self.clear_search).grid(row=0, column=6, padx=(0, 10))
        
        self.status_label = ttk.Label(control_frame, text="")
        self.status_label.grid(row=0, column=7, padx=(10, 0))
        
        tree_frame = ttk.Frame(main_frame)
        tree_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        columns = ('Risque', 'PID', 'Processus', 'Protocole', 'Adresse Locale', 'Port', 'État', 'Adresse Distante', 'Détails', 'Actions')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)
        
        column_widths = {'Risque': 70, 'PID': 80, 'Processus': 120, 'Protocole': 80, 
                        'Adresse Locale': 120, 'Port': 80, 'État': 100, 'Adresse Distante': 150, 
                        'Détails': 200, 'Actions': 100}
        
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            self.tree.column(col, width=column_widths.get(col, 100), minwidth=50)
        
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=3, column=0, pady=(10, 0))
        
        ttk.Button(action_frame, text="Monitorer", command=self.start_network_monitoring).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(action_frame, text="Troubleshooter", command=self.start_troubleshooter).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(action_frame, text="Fermer Processus", command=self.kill_selected_process).grid(row=0, column=2, padx=(0, 5))
        ttk.Button(action_frame, text="Détails", command=self.show_process_details).grid(row=0, column=3, padx=(0, 5))
        ttk.Button(action_frame, text="Bloquer IP", command=self.block_ip).grid(row=0, column=4)
        
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Monitorer", command=self.start_network_monitoring)
        self.context_menu.add_command(label="Troubleshooter", command=self.start_troubleshooter)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Fermer processus", command=self.kill_selected_process)
        self.context_menu.add_command(label="Détails", command=self.show_process_details)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Bloquer IP", command=self.block_ip)
        self.context_menu.add_command(label="Copier PID", command=self.copy_pid)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.start_network_monitoring)
        
        self.all_connections = []
        self.sort_column = None
        self.sort_reverse = False
    
    def get_port_info(self):
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.pid:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                        try:
                            process_path = process.exe()
                        except:
                            process_path = None
                    else:
                        process_name = "Système"
                        process_path = None
                    
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    remote_ip = conn.raddr.ip if conn.raddr else "N/A"
                    
                    protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    status = conn.status if conn.status else "N/A"
                    
                    conn_info = {
                        'pid': conn.pid or 0,
                        'process': process_name,
                        'process_path': process_path,
                        'protocol': protocol,
                        'local_ip': conn.laddr.ip if conn.laddr else "N/A",
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'local_addr': local_addr,
                        'remote_addr': remote_addr,
                        'remote_ip': remote_ip,
                        'status': status
                    }
                    
                    risk_level, reasons = self.classifier.classify_connection(conn_info)
                    conn_info['risk_level'] = risk_level
                    conn_info['risk_reasons'] = reasons
                    
                    connections.append(conn_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except psutil.AccessDenied:
            messagebox.showerror("Erreur", "Accès refusé. Lancez en tant qu'administrateur.")
        
        return connections
    
    def refresh_ports(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.status_label.config(text="Actualisation en cours...")
        self.root.update()
        
        self.all_connections = self.get_port_info()
        self.apply_filter()
    
    def apply_filter(self, event=None):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        filter_value = self.filter_var.get()
        search_text = self.search_var.get().lower()
        
        filtered_connections = self.all_connections
        
        if filter_value != "Tous":
            if filter_value in ["Dangereux", "Douteux", "Sûr"]:
                risk_map = {"Dangereux": "danger", "Douteux": "warning", "Sûr": "safe"}
                filtered_connections = [conn for conn in filtered_connections 
                                      if conn['risk_level'] == risk_map[filter_value]]
            elif filter_value == "En écoute":
                filtered_connections = [conn for conn in filtered_connections if conn['status'] == 'LISTEN']
            elif filter_value == "Établies":
                filtered_connections = [conn for conn in filtered_connections if conn['status'] == 'ESTABLISHED']
        
        if search_text:
            filtered_connections = [conn for conn in filtered_connections 
                                  if search_text in conn['process'].lower() or 
                                     search_text in str(conn['local_port']) or
                                     search_text in conn['remote_addr'].lower()]
        
        if self.sort_column:
            filtered_connections.sort(key=lambda x: self.get_sort_key(x, self.sort_column), reverse=self.sort_reverse)
        else:
            risk_order = {"danger": 0, "warning": 1, "safe": 2}
            filtered_connections.sort(key=lambda x: (risk_order[x['risk_level']], x['local_port']))
        
        for conn in filtered_connections:
            risk_icons = {"danger": "🔴", "warning": "🟠", "safe": "🟢"}
            risk_icon = risk_icons[conn['risk_level']]
            
            details = "; ".join(conn['risk_reasons'][:2])
            actions = "Monitor | Kill"
            
            values = (
                risk_icon,
                conn['pid'],
                conn['process'],
                conn['protocol'],
                conn['local_ip'],
                conn['local_port'],
                conn['status'],
                conn['remote_addr'],
                details,
                actions
            )
            
            self.tree.insert('', tk.END, values=values)
        
        current_time = datetime.now().strftime("%H:%M:%S")
        total = len(self.all_connections)
        filtered = len(filtered_connections)
        
        danger_count = len([c for c in self.all_connections if c['risk_level'] == 'danger'])
        warning_count = len([c for c in self.all_connections if c['risk_level'] == 'warning'])
        safe_count = len([c for c in self.all_connections if c['risk_level'] == 'safe'])
        
        status_text = f"[{current_time}] Total: {total} | Affichées: {filtered} | 🔴{danger_count} 🟠{warning_count} 🟢{safe_count}"
        self.status_label.config(text=status_text)
    
    def sort_by_column(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        
        self.apply_filter()
    
    def get_sort_key(self, conn, column):
        column_map = {
            'Risque': lambda x: {"danger": 0, "warning": 1, "safe": 2}[x['risk_level']],
            'PID': lambda x: x['pid'],
            'Processus': lambda x: x['process'].lower(),
            'Protocole': lambda x: x['protocol'],
            'Port': lambda x: x['local_port'],
            'État': lambda x: x['status']
        }
        
        return column_map.get(column, lambda x: str(x))(conn)
    
    def clear_search(self):
        self.search_var.set("")
        self.apply_filter()
    
    def toggle_auto_refresh(self):
        if self.auto_refresh.get():
            self.start_auto_refresh()
        else:
            self.refresh_active = False
    
    def start_auto_refresh(self):
        if not self.refresh_active:
            self.refresh_active = True
            self.auto_refresh_thread()
    
    def auto_refresh_thread(self):
        def refresh_loop():
            while self.refresh_active and self.auto_refresh.get():
                time.sleep(3)
                if self.refresh_active and self.auto_refresh.get():
                    self.root.after(0, self.refresh_ports)
        
        thread = threading.Thread(target=refresh_loop, daemon=True)
        thread.start()
    
    def get_selected_item(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner un processus.")
            return None
        return selection[0]
    
    def get_selected_connection_info(self):
        item = self.get_selected_item()
        if not item:
            return None
        
        values = self.tree.item(item, 'values')
        pid = int(values[1])
        
        for conn in self.all_connections:
            if conn['pid'] == pid:
                return conn
        return None
    
    def start_network_monitoring(self, event=None):
        item = self.get_selected_item()
        if not item:
            return
        
        values = self.tree.item(item, 'values')
        pid = int(values[1])
        process_name = values[2]
        
        if pid == 0:
            messagebox.showwarning("Attention", "Impossible de monitorer un processus système.")
            return
        
        if pid in self.monitors:
            try:
                self.monitors[pid].window.lift()
                self.monitors[pid].window.focus_force()
                return
            except:
                del self.monitors[pid]
        
        monitor = NetworkMonitor(pid, process_name)
        monitor.start_monitoring()
        self.monitors[pid] = monitor
    
    def start_troubleshooter(self):
        conn_info = self.get_selected_connection_info()
        if not conn_info:
            return
        
        pid = conn_info['pid']
        
        if pid in self.troubleshooters:
            try:
                self.troubleshooters[pid].window.lift()
                self.troubleshooters[pid].window.focus_force()
                return
            except:
                del self.troubleshooters[pid]
        
        troubleshooter = TroubleshooterWindow(self.root, conn_info)
        self.troubleshooters[pid] = troubleshooter
    
    def kill_selected_process(self):
        item = self.get_selected_item()
        if not item:
            return
        
        values = self.tree.item(item, 'values')
        pid = int(values[1])
        process_name = values[2]
        risk_level = values[0]
        
        if pid == 0:
            messagebox.showwarning("Attention", "Impossible de fermer un processus système.")
            return
        
        if "🔴" in risk_level:
            warning_msg = f"⚠️ ATTENTION: Ce processus est classé comme DANGEREUX!\n\n"
        elif "🟠" in risk_level:
            warning_msg = f"⚠️ ATTENTION: Ce processus est classé comme DOUTEUX!\n\n"
        else:
            warning_msg = ""
        
        result = messagebox.askyesno(
            "Confirmation", 
            f"{warning_msg}Voulez-vous vraiment fermer le processus '{process_name}' (PID: {pid}) ?\n\n"
            "Cette action peut causer une perte de données non sauvegardées."
        )
        
        if result:
            try:
                process = psutil.Process(pid)
                process.terminate()
                
                try:
                    process.wait(timeout=3)
                except psutil.TimeoutExpired:
                    process.kill()
                
                if pid in self.monitors:
                    try:
                        self.monitors[pid].on_closing()
                    except:
                        pass
                    del self.monitors[pid]
                
                if pid in self.troubleshooters:
                    try:
                        self.troubleshooters[pid].window.destroy()
                    except:
                        pass
                    del self.troubleshooters[pid]
                
                messagebox.showinfo("Succès", f"Le processus '{process_name}' a été fermé.")
                self.refresh_ports()
                
            except psutil.NoSuchProcess:
                messagebox.showinfo("Information", "Le processus n'existe plus.")
                self.refresh_ports()
            except psutil.AccessDenied:
                messagebox.showerror("Erreur", "Accès refusé. Lancez en tant qu'administrateur.")
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de fermer le processus: {str(e)}")
    
    def show_process_details(self):
        conn_info = self.get_selected_connection_info()
        if not conn_info:
            return
        
        pid = conn_info['pid']
        
        if pid == 0:
            messagebox.showinfo("Détails", "Processus système - Aucun détail disponible")
            return
        
        try:
            process = psutil.Process(pid)
            
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Détails - {process.name()} (PID: {pid})")
            details_window.geometry("700x600")
            
            notebook = ttk.Notebook(details_window)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            info_frame = ttk.Frame(notebook)
            notebook.add(info_frame, text="Informations Générales")
            
            info_text = tk.Text(info_frame, wrap=tk.WORD, font=("Consolas", 10))
            info_scroll = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=info_text.yview)
            info_text.configure(yscrollcommand=info_scroll.set)
            
            info_content = f"=== INFORMATIONS DU PROCESSUS ===\n\n"
            info_content += f"Nom: {process.name()}\n"
            info_content += f"PID: {process.pid}\n"
            info_content += f"PPID: {process.ppid()}\n"
            info_content += f"Statut: {process.status()}\n"
            
            if conn_info:
                risk_text = {"danger": "🔴 DANGEREUX", "warning": "🟠 DOUTEUX", "safe": "🟢 SÛR"}
                info_content += f"Niveau de risque: {risk_text[conn_info['risk_level']]}\n"
                info_content += f"Raisons: {', '.join(conn_info['risk_reasons'])}\n\n"
            
            try:
                info_content += f"Utilisateur: {process.username()}\n"
            except psutil.AccessDenied:
                info_content += "Utilisateur: Accès refusé\n"
            
            try:
                info_content += f"Chemin: {process.exe()}\n"
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info_content += "Chemin: Accès refusé\n"
            
            try:
                cpu_percent = process.cpu_percent()
                memory_info = process.memory_info()
                info_content += f"CPU: {cpu_percent}%\n"
                info_content += f"Mémoire: {memory_info.rss / 1024 / 1024:.1f} MB\n"
                
                if hasattr(process, 'num_threads'):
                    info_content += f"Threads: {process.num_threads()}\n"
                
                if hasattr(process, 'num_fds'):
                    try:
                        info_content += f"Descripteurs de fichiers: {process.num_fds()}\n"
                    except:
                        pass
                
            except psutil.AccessDenied:
                info_content += "CPU/Mémoire: Accès refusé\n"
            
            try:
                create_time = datetime.fromtimestamp(process.create_time())
                info_content += f"Créé le: {create_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            except psutil.AccessDenied:
                info_content += "Date de création: Accès refusé\n"
            
            info_text.insert(tk.END, info_content)
            info_text.configure(state='disabled')
            
            info_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            info_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            
            conn_frame = ttk.Frame(notebook)
            notebook.add(conn_frame, text="Connexions")
            
            conn_tree = ttk.Treeview(conn_frame, columns=('Protocol', 'Local', 'Remote', 'Status'), show='headings')
            for col in ('Protocol', 'Local', 'Remote', 'Status'):
                conn_tree.heading(col, text=col)
                conn_tree.column(col, width=150)
            
            try:
                connections = process.connections()
                for conn in connections:
                    local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    conn_tree.insert('', tk.END, values=(protocol, local, remote, conn.status))
            except psutil.AccessDenied:
                conn_tree.insert('', tk.END, values=("Accès refusé", "", "", ""))
            
            conn_scroll = ttk.Scrollbar(conn_frame, orient=tk.VERTICAL, command=conn_tree.yview)
            conn_tree.configure(yscrollcommand=conn_scroll.set)
            
            conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            conn_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            
        except psutil.NoSuchProcess:
            messagebox.showinfo("Information", "Le processus n'existe plus.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'obtenir les détails: {str(e)}")
    
    def block_ip(self):
        conn_info = self.get_selected_connection_info()
        if not conn_info:
            return
        
        remote_ip = conn_info.get('remote_ip', 'N/A')
        if remote_ip == 'N/A':
            messagebox.showwarning("Attention", "Aucune adresse IP distante à bloquer")
            return
        
        result = messagebox.askyesno(
            "Bloquer IP",
            f"Voulez-vous ajouter {remote_ip} à la liste des IPs malveillantes ?\n\n"
            "Cette IP sera marquée comme dangereuse dans les futures analyses."
        )
        
        if result:
            threat_intel = ThreatIntelligence()
            threat_intel.add_malicious_ip(remote_ip)
            messagebox.showinfo("Succès", f"IP {remote_ip} ajoutée à la liste noire")
            self.refresh_ports()
    
    def copy_pid(self):
        item = self.get_selected_item()
        if not item:
            return
        
        values = self.tree.item(item, 'values')
        pid = values[1]
        
        self.root.clipboard_clear()
        self.root.clipboard_append(str(pid))
        messagebox.showinfo("Copié", f"PID {pid} copié dans le presse-papiers")
    
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def export_all_data(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'total_connections': len(self.all_connections),
                    'connections': []
                }
                
                for conn in self.all_connections:
                    export_data['connections'].append({
                        'pid': conn['pid'],
                        'process': conn['process'],
                        'protocol': conn['protocol'],
                        'local_addr': conn['local_addr'],
                        'remote_addr': conn['remote_addr'],
                        'status': conn['status'],
                        'risk_level': conn['risk_level'],
                        'risk_reasons': conn['risk_reasons']
                    })
                
                if filename.endswith('.json'):
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(export_data, f, indent=2, ensure_ascii=False)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"Export des données - {export_data['timestamp']}\n")
                        f.write("="*60 + "\n\n")
                        for conn in export_data['connections']:
                            f.write(f"PID: {conn['pid']} | {conn['process']} | {conn['protocol']} | "
                                   f"{conn['local_addr']} -> {conn['remote_addr']} | {conn['status']} | "
                                   f"Risque: {conn['risk_level']}\n")
                
                messagebox.showinfo("Export", f"Données exportées vers {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'exporter: {str(e)}")
    
    def import_rules(self):
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                
                if 'malicious_ips' in rules:
                    threat_intel = ThreatIntelligence()
                    for ip in rules['malicious_ips']:
                        threat_intel.add_malicious_ip(ip)
                
                messagebox.showinfo("Import", "Règles importées avec succès")
                self.refresh_ports()
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'importer: {str(e)}")
    
    def network_scanner(self):
        scanner_window = tk.Toplevel(self.root)
        scanner_window.title("Scanner Réseau")
        scanner_window.geometry("600x500")
        
        ttk.Label(scanner_window, text="Scanner de Réseau Local", font=("Arial", 14, "bold")).pack(pady=10)
        
        input_frame = ttk.Frame(scanner_window)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Réseau à scanner:").pack(side=tk.LEFT)
        network_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(input_frame, textvariable=network_var, width=20).pack(side=tk.LEFT, padx=(5, 10))
        
        def start_scan():
            network = network_var.get()
            results_text.insert(tk.END, f"Scan de {network} en cours...\n")
            
            def scan_thread():
                try:
                    import ipaddress
                    net = ipaddress.ip_network(network, strict=False)
                    
                    for ip in list(net.hosts())[:50]:
                        try:
                            result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                                  capture_output=True, timeout=2)
                            if result.returncode == 0:
                                results_text.insert(tk.END, f"✅ {ip} - Actif\n")
                                results_text.see(tk.END)
                                results_text.update()
                        except:
                            pass
                    
                    results_text.insert(tk.END, "Scan terminé.\n")
                except Exception as e:
                    results_text.insert(tk.END, f"Erreur: {str(e)}\n")
            
            threading.Thread(target=scan_thread, daemon=True).start()
        
        ttk.Button(input_frame, text="Scanner", command=start_scan).pack(side=tk.LEFT)
        
        results_text = tk.Text(scanner_window, wrap=tk.WORD, font=("Consolas", 9))
        results_scroll = ttk.Scrollbar(scanner_window, orient=tk.VERTICAL, command=results_text.yview)
        results_text.configure(yscrollcommand=results_scroll.set)
        
        results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
    
    def rule_generator(self):
        rule_window = tk.Toplevel(self.root)
        rule_window.title("Générateur de Règles")
        rule_window.geometry("500x400")
        
        ttk.Label(rule_window, text="Générateur de Règles de Sécurité", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(rule_window, text="Sélectionnez les critères pour générer des règles automatiques:").pack(pady=5)
        
        criteria_frame = ttk.LabelFrame(rule_window, text="Critères", padding="10")
        criteria_frame.pack(fill=tk.X, padx=10, pady=10)
        
        block_unknown = tk.BooleanVar()
        ttk.Checkbutton(criteria_frame, text="Bloquer les processus inconnus", variable=block_unknown).pack(anchor=tk.W)
        
        block_high_ports = tk.BooleanVar()
        ttk.Checkbutton(criteria_frame, text="Alerter sur les ports > 50000", variable=block_high_ports).pack(anchor=tk.W)
        
        block_foreign = tk.BooleanVar()
        ttk.Checkbutton(criteria_frame, text="Surveiller les connexions étrangères", variable=block_foreign).pack(anchor=tk.W)
        
        def generate_rules():
            rules = {
                'block_unknown_processes': block_unknown.get(),
                'alert_high_ports': block_high_ports.get(),
                'monitor_foreign_connections': block_foreign.get(),
                'generated_at': datetime.now().isoformat()
            }
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(rules, f, indent=2)
                messagebox.showinfo("Succès", f"Règles sauvegardées dans {filename}")
        
        ttk.Button(rule_window, text="Générer et Sauvegarder", command=generate_rules).pack(pady=20)
    
    def forensic_analysis(self):
        forensic_window = tk.Toplevel(self.root)
        forensic_window.title("Analyse Forensique")
        forensic_window.geometry("800x600")
        
        ttk.Label(forensic_window, text="Analyse Forensique Réseau", font=("Arial", 14, "bold")).pack(pady=10)
        
        analysis_text = tk.Text(forensic_window, wrap=tk.WORD, font=("Consolas", 9))
        analysis_scroll = ttk.Scrollbar(forensic_window, orient=tk.VERTICAL, command=analysis_text.yview)
        analysis_text.configure(yscrollcommand=analysis_scroll.set)
        
        def run_analysis():
            analysis_text.insert(tk.END, "=== ANALYSE FORENSIQUE RÉSEAU ===\n\n")
            
            danger_count = len([c for c in self.all_connections if c['risk_level'] == 'danger'])
            warning_count = len([c for c in self.all_connections if c['risk_level'] == 'warning'])
            
            analysis_text.insert(tk.END, f"Connexions dangereuses détectées: {danger_count}\n")
            analysis_text.insert(tk.END, f"Connexions douteuses détectées: {warning_count}\n\n")
            
            if danger_count > 0:
                analysis_text.insert(tk.END, "⚠️ PROCESSUS DANGEREUX DÉTECTÉS:\n")
                for conn in self.all_connections:
                    if conn['risk_level'] == 'danger':
                        analysis_text.insert(tk.END, f"- {conn['process']} (PID: {conn['pid']}) - Port: {conn['local_port']}\n")
                analysis_text.insert(tk.END, "\n")
            
            listening_ports = [c for c in self.all_connections if c['status'] == 'LISTEN']
            analysis_text.insert(tk.END, f"Ports en écoute: {len(listening_ports)}\n")
            
            external_connections = [c for c in self.all_connections 
                                  if c['remote_ip'] != 'N/A' and not c['remote_ip'].startswith('192.168') 
                                  and not c['remote_ip'].startswith('10.') and not c['remote_ip'].startswith('172.')]
            analysis_text.insert(tk.END, f"Connexions externes: {len(external_connections)}\n\n")
            
            analysis_text.insert(tk.END, "Recommandations:\n")
            if danger_count > 0:
                analysis_text.insert(tk.END, "- Examiner immédiatement les processus dangereux\n")
            if len(listening_ports) > 10:
                analysis_text.insert(tk.END, "- Réduire le nombre de ports en écoute\n")
            if len(external_connections) > 20:
                analysis_text.insert(tk.END, "- Surveiller les connexions externes\n")
        
        ttk.Button(forensic_window, text="Lancer l'Analyse", command=run_analysis).pack(pady=10)
        
        analysis_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        analysis_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
    
    def show_about(self):
        about_text = """
Moniteur de Ports Avancé v2.0

Un outil de surveillance réseau professionnel avec:
• Classification automatique des risques
• Monitoring temps réel des communications
• Outils de troubleshooting intégrés
• Analyse forensique
• Capture de paquets

Développé avec Python, psutil et tkinter
        """
        messagebox.showinfo("À propos", about_text)
    
    def on_closing(self):
        self.refresh_active = False
        
        for monitor in self.monitors.values():
            try:
                monitor.on_closing()
            except:
                pass
        
        for troubleshooter in self.troubleshooters.values():
            try:
                troubleshooter.window.destroy()
            except:
                pass
        
        self.root.destroy()

def main():
    root = tk.Tk()
    app = AdvancedPortMonitor(root)
    
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    try:
        messagebox.showinfo(
            "Moniteur de Ports Avancé v2.0", 
            "🔴 Rouge = Connexions dangereuses\n"
            "🟠 Orange = Connexions douteuses\n" 
            "🟢 Vert = Connexions légitimes\n\n"
            "Fonctionnalités:\n"
            "• Double-clic: Monitoring temps réel\n"
            "• Clic droit: Menu d'actions\n"
            "• Troubleshooter intégré\n"
            "• Filtres et recherche avancés\n\n"
            "Conseil: Lancez en tant qu'administrateur"
        )
    except:
        pass
    
    root.mainloop()

if __name__ == "__main__":
    main()
