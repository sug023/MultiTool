from base_scanner import BaseScanner
from scapy.all import IP, sr1, conf, TCP, UDP
from global_functions.stderr_mgr import exception
from global_functions.network_mgr import get_port_range
from global_functions.thread import thread_scan


class PortScanner(BaseScanner):

    def __init__(self):
        super().__init__()
        self.scan_methods = {
            'tcp': self.tcp_scan(),
            'udp': self.udp_scan()
        }

    def tcp_scan(self, ip, port, queue=None):
        try:
            packet = IP(dst=ip) / TCP(dport=port, flags='S') # Prepare the TCP packet
            response = sr1(packet, timeout=self.timeout_val, verbose=self.verbose) # Send the TCP packet
            if response and response.haslayer(TCP): # Process the response
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x12: # SYN-ACK packet as response
                    return {
                        'status': 'success',
                        'port_status': 'open',
                        'port': port,
                        'ip': ip
                    }
                elif tcp_layer.flags == 0x14: # RST packet as response
                    return {
                        'status': 'success',
                        'port_status': 'closed',
                        'port': port,
                        'ip': ip
                    }
                else: # Unknown packet as response
                    return {
                        'status': 'success',
                        'port_status': 'unknown',
                        'port': port,
                        'ip': ip
                    }
            else: # Port filtered
                return {
                    'status': 'success',
                    'port_status': 'filtered',
                    'port': port,
                    'ip': ip
                }

        except Exception as error:
            return exception(error)



    def udp_scan(self, ip, port):
        try:
            packet = IP(dst=ip) / UDP(dport=port) # Prepare UDP packet
            response = sr1(packet, timeout=self.timeout_val, verbose=self.verbose) # Send the UDP packet
            if response: # Process the response
                if response.haslayer(UDP):
                    return {
                        'status': 'success',
                        'port_status': 'open',
                        'port': port,
                        'ip': ip
                    }
                else: 
                    return {
                        'status': 'success',
                        'port_status': 'closed',
                        'port': port,
                        'ip': ip
                    }
            else:
                return {        

                    'port': port,
                    'ip': ip 
                }

        except Exception as error:
            return exception(error)
        
    def thread_host_scan(self, ip1, ip2, mode:int):
        ip_range = get_port_range(ip1, ip2)
        scan_method = self.scan_methods[mode]
        return thread_scan(scan_method, ip_range, self.thread_val)