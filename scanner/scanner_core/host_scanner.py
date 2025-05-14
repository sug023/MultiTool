import logging
from tqdm import tqdm
from base_scanner import BaseScanner
from scapy.all import ARP, ICMP, IP, TCP, Ether, srp, sr1
from global_functions.stderr_mgr import exception
from global_functions.network_mgr import get_ipv4_range
from global_functions.thread import thread_scan

class HostScanner(BaseScanner):
    
    def __init__(self):
        super().__init__(self)
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Remove icmp alert
        self.scan_methods = {
            'arp': self.arp_scan,
            'icmp': self.icmp_scan,
            'ttl': self.ttl_scan
        }

    def arp_scan(self, ip, queue=None):
        try:
            packet = Ether(dst=self.scanner_mac / ARP(pdst=ip))# Prepare the ARP packet
            response = srp(packet, timeout=self.timeout_val, verbose=self.verbose) # Send ARP packet
            if response: # Process the response
                return {
                    'status': 'success',
                    'host_status': 'up',
                    'ip': ip
                }
            else:
                return {
                    'status': 'success',
                    'host_status': 'down',
                    'ip': ip
                }

        except Exception as error:
            return exception(error)

    def icmp_scan(self, ip, queue=None):
        try:
            packet = IP(dst=ip) / ICMP() # Prepare the ICMP packet
            response = sr1(packet, timeout=self.timeout_val, verbose=self.verbose) # Send ICMP packet
            if response: # Process the response
                return {
                    'status': 'success',
                    'host_status': 'up',
                    'ip': ip
                }
            else:
                return {
                    'status': 'success',
                    'host_status': 'down',
                    'ip': ip
                }

        except Exception as error:
            return exception(error)

    def ttl_scan(self, ip, queue=None):
        try:
            packet = IP(dst=ip) / TCP() # Prepare the TCP packet
            response = sr1(packet, timeout=self.timeout_val, verbose=self.verbose) # Send the TCP packet
            if response: # Process the response (extract ttl)
                ttl = response[IP].ttl
                if ttl <= 64:
                    os = 'Linux/Mac'
                elif ttl <= 128:
                    os = 'Windows'
                else:
                    os = 'Unknown'
            return {
                'status': 'success',
                'os': os,
                'ip': ip                
            }
            
        except Exception as error:
            return exception(error)
        
    def thread_host_scan(self, ip1, ip2, mode:int):
        ip_range = get_ipv4_range(ip1, ip2)
        scan_method = self.scan_methods[mode]
        return thread_scan(scan_method, ip_range, self.thread_val)