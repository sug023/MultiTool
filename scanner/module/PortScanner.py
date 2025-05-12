from Scanner import Scanner
import threading
from queue import Queue
from scapy.all import IP, sr1, conf, TCP, UDP

class PortScanner(Scanner):
    
    def __init__(self):
        super().__init__()
        self.scan_methods = {
            'tcp': self.tcp_scan,
            'udp': self.udp_scan
        }

    def ip_and_port_validation(self, ip, port):
        """
        Verify that both port and ip are valid.
        """
        # List of errors
        error = []
        # Verfications
        ip_validation_error = self.validate_ip_or_return(ip)
        port_validation_error = self.validate_port_or_return(port)
        # Process verifications results
        if ip_validation_error:
            ip_validation_error.append(error)
        if port_validation_error:
            port_validation_error.append(error)
        if not error:
            return {
                'status': 'success'
            }
        else: 
            return {
                'status': 'error',
                'error': error
            }
        
    def tcp_scan(self, ip, port, queue=None):
        """
        Performs a tcp scan
        Result:
            * Port status
        """
        try:
            # Verification
            validation = self.ip_and_port_validation(ip, port)
            if validation['status'] != 'success':
                return {
                    'status': 'error',
                    'ip': ip,
                    'port': port,
                    'error': validation['error']
                } 
            # Prepare and send the TCP packet
            packet = IP(dst=ip) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=self.scanner_timeout_value, verbose=self.verbose)
            # Process the response
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                # If response is SYN-ACK (open)
                if tcp_layer.flags == 0x12:
                    result =  {
                        'status': 'success',
                        'ip': ip,
                        'port': port,
                        'port_status': 'open'
                    }
                # If response is RST-ACK (close)
                elif tcp_layer.flags == 0x14:
                    result = {
                        'status': 'success',
                        'ip': ip,
                        'port': port,
                        'port_status': 'closed'
                    }
                # If unknown answer
                else:
                    result = {
                        'status': 'success',
                        'ip': ip,
                        'port': port,
                        'port_status': 'unknown'
                    }
            # If not response
            else:
                result = {
                    'status':  'success',
                    'ip': ip,
                    'port': port,
                    'port_status': 'filtered'
                }
            return self.process_result(result, queue)
        # Except error
        except Exception as error:
            result = {
                'status': 'error',
                'error': str(error),
                'ip': ip,
                'port': port
            }
            return self.process_result(result, queue)
        
    def udp_scan(self, ip, port, queue=None):
        """
        Performs an udp scan
        Result:
            * Port status
        """
        try:
            # Verification
            validation = self.ip_and_port_validation(ip, port)
            if validation['status'] != 'success':
                return {
                    'status': 'error',
                    'ip': ip,
                    'port': port,
                    'error': validation['error']
                }
            # Prepare and send the UDP packet
            packet = IP(dst=ip) / UDP(dport=port)
            response = sr1(packet, timeout=self.scanner_timeout_value, verbose=self.verbose)
            # Process the response
            if response:
                if response.haslayer(UDP):
                    result = {
                        'status': 'success',
                        'ip': ip,
                        'port': port,
                        'port_status': 'open'
                    }
                else:
                    result = {
                        'status': 'success',
                        'ip': ip,
                        'port': port,
                        'port_status': 'closed'
                    }
            else:
                result = {
                    'status': 'success',
                    'ip': ip,
                    'port': port,
                    'port_status': 'filtered'
                }
            return self.process_result(result, queue)
        # Except error
        except Exception as error:
            result = {
                'status': 'error',
                'error': str(error),
                'ip': ip,
                'port': port
            }
            return self.process_result(result, queue)
        
    def range_scan(self, mode, ip, port2, port1):
        try:
            """
            Performs a range port scan
            """
            results = []
            threads = []
            queue = Queue()
            # Verfications
            ip_validation_error = self.validate_ip_or_return(ip)
            port1_validation_error = self.validate_port_or_return(port1)
            port2_validation_error = self.validate_port_or_return(port2)
            if ip_validation_error:
                return ip_validation_error
            elif port1_validation_error:
                return port1_validation_error
            elif port2_validation_error:
                return port2_validation_error
            if port2 < port1:
                port1, port2 = port2, port1
            # Perform TCP range scan
            if mode == 'tcp':
                for i in range(port1, port2+1):
                    t = threading.Thread(target=self.tcp_scan, args=(ip, i, queue))              
                    threads.append(t)
                    t.start()
                # Wait for the tcp range scan end
                for t in threads:
                    t.join()
            # Perform UDP range scan
            elif mode == 'udp':
                for i in range (port1, port2+1):
                    t = threading.Thread(target=self.udp_scan, args=(ip, i, queue))              
                    threads.append(t)
                    t.start()
                #Wait for the udp range scan end
                for t in threads:
                    t.join()
            # Process result
            while not queue.empty():
                results.append(queue.get())
            return results
        except Exception as error:
            return {
                'status': 'error',
            'error': str(error),
            'ip': ip,
            'port': f'{port1}-{port2}'
            }