import socket
import select
import struct
import random
import threading
import time
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional
import ipaddress
import logging
from scapy.all import *

# Configure logging
logging.basicConfig(filename='logs/scanner.log', level=logging.INFO)

class ScanType(Enum):
    TCP_SYN = "TCP SYN (Half-Open)"
    TCP_CONNECT = "TCP Connect"
    UDP = "UDP"
    FIN = "FIN"
    XMAS = "XMAS"
    NULL = "NULL"
    ACK = "ACK"
    SCTP = "SCTP"
    IP_PROTOCOL = "IP Protocol"

@dataclass
class ScanResult:
    ip: str
    port: int
    is_open: bool
    scan_type: ScanType
    service: Optional[str] = None
    version: Optional[str] = None
    os_info: Optional[str] = None
    response_time: Optional[float] = None

class AdvancedPortScanner:
    def __init__(self, max_threads=100, timeout=2.0):
        self.max_threads = max_threads
        self.timeout = timeout
        self.active_threads = 0
        self.lock = threading.Lock()
        self.results = []
        self.stop_event = threading.Event()
        
    def _send_syn_packet(self, target_ip: str, port: int) -> bool:
        """Send SYN packet for half-open scanning"""
        try:
            ip_packet = IP(dst=target_ip)
            tcp_packet = TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            packet = ip_packet/tcp_packet
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                flags = response.getlayer(TCP).flags
                if flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = IP(dst=target_ip)/TCP(sport=packet[TCP].sport, 
                                                      dport=port, flags="R")
                    send(rst_packet, verbose=0)
                    return True
                elif flags == 0x14:  # RST-ACK
                    return False
            return False
        except Exception as e:
            logging.error(f"SYN scan error for {target_ip}:{port}: {e}")
            return False

    def _tcp_connect_scan(self, target_ip: str, port: int) -> bool:
        """Standard TCP connect scan"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((target_ip, port))
                return result == 0
        except Exception as e:
            logging.error(f"TCP connect scan error for {target_ip}:{port}: {e}")
            return False

    def _udp_scan(self, target_ip: str, port: int) -> bool:
        """UDP port scanning"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(b'\x00', (target_ip, port))
                data, addr = s.recvfrom(1024)
                return True
        except socket.timeout:
            # Might still be open if no response
            return True
        except Exception as e:
            logging.error(f"UDP scan error for {target_ip}:{port}: {e}")
            return False

    def scan_port(self, target_ip: str, port: int, scan_type: ScanType) -> ScanResult:
        """Scan a single port with specified scan type"""
        start_time = time.time()
        is_open = False
        
        try:
            if scan_type == ScanType.TCP_SYN:
                is_open = self._send_syn_packet(target_ip, port)
            elif scan_type == ScanType.TCP_CONNECT:
                is_open = self._tcp_connect_scan(target_ip, port)
            elif scan_type == ScanType.UDP:
                is_open = self._udp_scan(target_ip, port)
            # Additional scan types would be implemented here
            
            response_time = time.time() - start_time
            result = ScanResult(
                ip=target_ip,
                port=port,
                is_open=is_open,
                scan_type=scan_type,
                response_time=response_time
            )
            
            with self.lock:
                self.results.append(result)
                
            return result
            
        finally:
            with self.lock:
                self.active_threads -= 1

    def scan_target(self, target: str, ports: List[int], scan_type: ScanType) -> List[ScanResult]:
        """Scan multiple ports on a target"""
        self.results = []
        self.stop_event.clear()
        
        # Parse target (could be IP, range, CIDR, etc.)
        target_ips = self._parse_target(target)
        
        # Scan each IP and port combination
        for ip in target_ips:
            for port in ports:
                while self.active_threads >= self.max_threads and not self.stop_event.is_set():
                    time.sleep(0.1)
                
                if self.stop_event.is_set():
                    break
                    
                with self.lock:
                    self.active_threads += 1
                
                threading.Thread(
                    target=self.scan_port,
                    args=(ip, port, scan_type),
                    daemon=True
                ).start()
        
        while self.active_threads > 0 and not self.stop_event.is_set():
            time.sleep(0.1)
            
        return self.results

    def _parse_target(self, target: str) -> List[str]:
        """Parse target specification into list of IPs"""
        try:
            # Handle IP ranges (e.g., 192.168.1.1-10)
            if '-' in target:
                start_ip, end = target.split('-')
                base = '.'.join(start_ip.split('.')[:-1])
                start = int(start_ip.split('.')[-1])
                end = int(end)
                return [f"{base}.{i}" for i in range(start, end+1)]
            
            # Handle CIDR notation
            elif '/' in target:
                return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
            
            # Single IP or hostname
            else:
                return [socket.gethostbyname(target)]
                
        except Exception as e:
            logging.error(f"Error parsing target {target}: {e}")
            return []

    def stop_scan(self):
        """Gracefully stop ongoing scan"""
        self.stop_event.set()