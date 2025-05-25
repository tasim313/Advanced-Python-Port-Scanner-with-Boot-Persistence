"""
Core Scanner Module - Advanced Port Scanner
"""

import nmap
import socket
import threading
import time
import json
import sqlite3
from datetime import datetime
from scapy.all import *
import ipaddress
import concurrent.futures
import random

class AdvancedPortScanner:
    def __init__(self, db_path="database/scan_results.db"):
        self.nm = nmap.PortScanner()
        self.db_path = db_path
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service TEXT,
                version TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS host_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                os_info TEXT,
                device_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        
    def tcp_syn_scan(self, target, ports, timeout=3):
        """TCP SYN Scan implementation"""
        results = {}
        
        def scan_port(port):
            try:
                # Create SYN packet
                response = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 18:  # SYN-ACK
                        # Send RST to close connection
                        send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
                        return port, "open"
                    elif response[TCP].flags == 20:  # RST-ACK
                        return port, "closed"
                return port, "filtered"
            except:
                return port, "filtered"
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, state = future.result()
                results[port] = state
                
        return results
        
    def tcp_connect_scan(self, target, ports, timeout=3):
        """TCP Connect Scan implementation"""
        results = {}
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                return port, "open" if result == 0 else "closed"
            except:
                return port, "filtered"
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, state = future.result()
                results[port] = state
                
        return results
        
    def udp_scan(self, target, ports, timeout=3):
        """UDP Scan implementation"""
        results = {}
        
        def scan_port(port):
            try:
                response = sr1(IP(dst=target)/UDP(dport=port), timeout=timeout, verbose=0)
                if response is None:
                    return port, "open|filtered"
                elif response.haslayer(ICMP):
                    if response[ICMP].type == 3 and response[ICMP].code == 3:
                        return port, "closed"
                return port, "open"
            except:
                return port, "filtered"
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, state = future.result()
                results[port] = state
                
        return results
        
    def service_detection(self, target, port):
        """Detect service and version on open port"""
        try:
            # Use nmap for service detection
            result = self.nm.scan(target, str(port), arguments="-sV")
            
            if target in result['scan']:
                host_info = result['scan'][target]
                if 'tcp' in host_info and port in host_info['tcp']:
                    port_info = host_info['tcp'][port]
                    return {
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', 'unknown'),
                        'product': port_info.get('product', 'unknown')
                    }
        except:
            pass
            
        return {'service': 'unknown', 'version': 'unknown', 'product': 'unknown'}
        
    def os_detection(self, target):
        """Detect operating system"""
        try:
            result = self.nm.scan(target, arguments="-O")
            if target in result['scan']:
                host_info = result['scan'][target]
                if 'osmatch' in host_info and host_info['osmatch']:
                    return {
                        'os': host_info['osmatch'][0]['name'],
                        'accuracy': host_info['osmatch'][0]['accuracy']
                    }
        except:
            pass
            
        return {'os': 'unknown', 'accuracy': 0}
        
    def banner_grab(self, target, port, timeout=5):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send common probes
            probes = [b"\r\n", b"GET / HTTP/1.0\r\n\r\n", b"\0"]
            
            for probe in probes:
                try:
                    sock.send(probe)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if banner.strip():
                        sock.close()
                        return banner.strip()
                except:
                    continue
                    
            sock.close()
        except:
            pass
            
        return None
        
    def comprehensive_scan(self, targets, ports, scan_type="tcp_syn"):
        """Perform comprehensive scan"""
        results = {}
        
        # Parse targets
        target_list = self.parse_targets(targets)
        port_list = self.parse_ports(ports)
        
        print(f"Scanning {len(target_list)} targets on {len(port_list)} ports...")
        
        for target in target_list:
            print(f"Scanning {target}...")
            target_results = {}
            
            # Perform port scan based on type
            if scan_type == "tcp_syn":
                port_results = self.tcp_syn_scan(target, port_list)
            elif scan_type == "tcp_connect":
                port_results = self.tcp_connect_scan(target, port_list)
            elif scan_type == "udp":
                port_results = self.udp_scan(target, port_list)
            else:
                port_results = self.tcp_connect_scan(target, port_list)
                
            # Get additional info for open ports
            open_ports = [port for port, state in port_results.items() if state == "open"]
            
            for port in open_ports:
                service_info = self.service_detection(target, port)
                banner = self.banner_grab(target, port)
                
                target_results[port] = {
                    'state': port_results[port],
                    'service': service_info['service'],
                    'version': service_info['version'],
                    'banner': banner
                }
                
            # OS Detection
            os_info = self.os_detection(target)
            
            results[target] = {
                'ports': target_results,
                'os': os_info,
                'scan_time': datetime.now().isoformat()
            }
            
            # Save to database
            self.save_results(target, target_results, os_info)
            
        return results
        
    def parse_targets(self, targets):
        """Parse target specification"""
        target_list = []
        
        if isinstance(targets, str):
            if ',' in targets:
                targets = [t.strip() for t in targets.split(',')]
            else:
                targets = [targets]
                
        for target in targets:
            if '/' in target:  # CIDR notation
                network = ipaddress.ip_network(target, strict=False)
                target_list.extend([str(ip) for ip in network.hosts()])
            elif '-' in target and '.' in target:  # IP range
                start_ip, end_ip = target.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                current = start
                while current <= end:
                    target_list.append(str(current))
                    current += 1
            else:  # Single IP or hostname
                target_list.append(target)
                
        return target_list
        
    def parse_ports(self, ports):
        """Parse port specification"""
        port_list = []
        
        if isinstance(ports, str):
            if ',' in ports:
                port_specs = [p.strip() for p in ports.split(',')]
            else:
                port_specs = [ports]
        else:
            port_specs = [str(ports)]
            
        for spec in port_specs:
            if '-' in spec:  # Port range
                start, end = map(int, spec.split('-'))
                port_list.extend(range(start, end + 1))
            else:  # Single port
                port_list.append(int(spec))
                
        return sorted(list(set(port_list)))
        
    def save_results(self, target, port_results, os_info):
        """Save scan results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Save port results
        for port, info in port_results.items():
            cursor.execute("""
                INSERT INTO scan_results (target, port, protocol, state, service, version)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (target, port, "tcp", info['state'], info['service'], info['version']))
            
        # Save host info
        cursor.execute("""
            INSERT INTO host_info (ip_address, os_info)
            VALUES (?, ?)
        """, (target, json.dumps(os_info)))
        
        conn.commit()
        conn.close()
        
    def get_scan_history(self):
        """Get scan history from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM scan_results 
            ORDER BY timestamp DESC 
            LIMIT 100
        """)
        
        results = cursor.fetchall()
        conn.close()
        
        return results
