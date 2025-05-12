from Scanner import Scanner
import threading
from queue import Queue
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, TCP

class HostScanner(Scanner):

    def __init__(self):
        super().__init__()
        self.scan_methods = {
            'arp': self.arp_scan,
            'icmp': self.icmp_scan,
            'os': self.os_scan
        }

    def arp_scan(self, ip, queue=None):
        """
        Performs an ARP scan
        Result:
            * Mac
            * Host status
        """
        try:
            # IP verification
            ip_validation_error = self.validate_ip_or_return(ip)
            if ip_validation_error:
                return ip_validation_error
            # Prepare the ARP packet
            packet = Ether(dst=self.scanner_mac_value) / ARP(pdst=ip)
            response = srp(packet, timeout=self.scanner_timeout_value, verbose=self.verbose)

            # Process the response
            if response:
                for _, received in response:
                    result = {
                        'status':'success',
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'host_status':  'up'
                    }
                return self.process_result(result, queue)
            else:
                result = {
                    'status': 'success',
                    'ip': ip,
                    'mac': 'unknown',
                    'host_status': 'down'
                }
                return self.result(result, queue)
        # Except error
        except Exception as error:
            result = {
                'status': 'error',
                'error': error,
                'ip': ip
            }
            return self.process_result(result, queue)

    def icmp_scan(self, ip, queue=None):
        """
        Performs an ICMP scan
        Result:
            * Host status
        """
        try:
            # IP verification
            error_result = self.validate_ip_or_return(ip)
            if error_result:
                return error_result
            # Prepare and send the ICMP packet
            packet = IP(dst=ip) / ICMP()
            response = sr1(packet, timeout=self.scanner_timeout_value, verbose=self.verbose)
            # Process the response
            if response:
                result = {
                    'status': 'success',
                    'ip': ip,
                    'host_status': 'up'
                }
            else:
                result = {
                    'status': 'success',
                    'ip': ip,
                    'host_status': 'down'
                }
            return self.process_result(result, queue)
        # Except error
        except Exception as error:
            result = {
                'status': 'error',
                'error': error,
                'ip': ip
            }
            return self.process_result(result, queue)
        
    def os_scan(self, ip, queue=None):
        """
        Performs an OS scan using TTL
        Result:
            * OS (Linux/Mac, Windows or Unknown)
        """
        try:
            # IP verification
            error_result = self.validate_ip_or_return(ip)
            if error_result:
                return error_result
            # Prepare and send the packet
            packet = IP(dst=ip) / TCP()
            response = sr1(packet, timeout=self.scanner_timeout_value, verbose=self.verbose)
            # Process the response
            if response:
                ttl = response[IP].ttl
                if ttl <= 64:
                    os = "Linux/Mac"
                elif ttl <= 128:
                    os = "Windows"
                else:
                    os = "Unknown"
                result = {
                    'status': 'success',
                    'ip': ip,
                    'os': os
                }
                return self.process_result(result, queue)
            else:
                result = {
                    'status': 'success',
                    'ip': ip,
                    'os': 'No response received'
                }
                return self.process_result(result, queue)
        # Except error
        except Exception as error:
            result = {
                'status': 'error',
                'error': error,
                'ip': ip
            }
            return self.process_result(result, queue)
        
    def range_scan(self, mode, ip1, ip2):
        """
        Performs a range scan using all the available modes with the help of threads
        Result:
            * A list of dictionaries with the results of the scans.
        """
        try:
            # Verifications
            ip1_validation_error = self.validate_ip_or_return(ip1)
            ip2_validation_error = self.validate_ip_or_return(ip2)
            if ip1_validation_error:
                return ip1_validation_error
            elif ip2_validation_error:
                return ip2_validation_error
            elif mode not in self.scan_methods:
                return {
                    'status': 'error',
                    'error': 'ScanModeNotFound',
                    'ip1': ip1,
                    'ip2': ip2
                }
            # Initialize structures
            results = []
            threads = []
            queue = Queue()
            scan_function = self.scan_methods[mode]
            # Last octet
            octet1 = int(ip1.split('.')[-1])
            octet2 = int(ip2.split('.')[-1])
            # Perform scan
            for i in range(int(octet1), int(octet2)+1):
                ip = self.network_id+'.'+str(i)
                t = threading.Thread(target=scan_function, args=(ip, queue))
                threads.append(t)
                t.start()
            # Wait for tasks
            for t in threads:
                t.join()
            # Process scan results
            while not queue.empty():
                results.append(queue.get())
            return results

        except Exception as error:
            result = {
                'status': 'error',
                'error': error,
                'ip1': ip1,
                'ip2': ip2
            }
            return self.port_validation(result, queue)
