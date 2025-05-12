import socket
import logging

class Scanner:

    def __init__(self):
        # Disable ICMP scan warning
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        self.scanner_timeout_value = 1
        self.local_host_ip = self.get_local_host_ip()['ip']
        self.network_id = self.remove_last_octet(self.local_host_ip)['network_id']
        self.scanner_mac_value = 'ff:ff:ff:ff:ff:ff'
        self.verbose = False

    def get_local_host_ip(self):
        """
        Obtain the valid IP address of the valid network interface through an online request. 
        It is necessary to calculate the network ID.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.scanner_timeout_value)
                s.connect(('8.8.8.8', 1))        
                self.local_host_ip = s.getsockname()[0]
            return {
                'status': 'success',
                'local_host_ip': self.local_host_ip
            }
        except Exception as error:
            return {
                'status': 'error',
                'error': error                
            }

    def ip_validation(self, ip):
        """
        Checks if an IP address is valid by:
        1. Checking the number of octets
        2. Checking that the content of the octets are int
        3. Checking that each octet has a value within the valid range 
        4. Checking that the IP can exist within the same network as the host 
        """
        ip_parts = ip.split(".")

        if len(ip_parts) != 4:
            return {
                'status': 'error',
                'error': 'IPAddressOctetCountError'
            }
        for octet in ip_parts:
            if not octet.isdigit():
                return {
                    'status': 'error',
                    'error': 'IPAddressNonNumericError'
                }
            elif not (1 <= int(octet) <= 255):
                return {
                    'status': 'error',
                    'error': 'IPOctetOutOfRangeError',
                    'ip': ip
                }
        if self.remove_last_octet(ip)['network_id'] != self.network_id:
            return {
                'status': 'error',
                'error': 'IPNotInNetworkError', 
                'ip': ip
            }
        return {
            'status': 'success',
            'ip': ip
        }
    
    def validate_ip_or_return(self,ip, queue):
        """
        Validate an ip or return the error
        """
        result = self.ip_validation(ip)
        if result['status'] == 'error':
            return self.process_result({
                'status': 'error',
                'error': 'IpValidationError_'+result['error'],
                'ip': ip
            },queue)
        return None

    def port_validation(self, port):
        """
        Checks if one port is valid by:
        * Checking if the port is an int
        * Checking if the port is in range of ports
        """
        if not isinstance(port, int):
            return {
                'status': 'error',
                'error': 'PortIsNotAnIntError',
                'port': port
            }
        elif not (0 <= port <= 65535):
            return {
                'status': 'error',
                'error': 'PortOutOfRangeError',
                'port': port
            }
        return {
            'status': 'success',
            'port': port
        }
    
    def port_validation_or_return(self, port, queue):
        """
        Validate a port or return an error
        """
        result = self.port_validation(port)
        if result['status'] == 'error':
            return self.process_result({
                'status': 'error',
                'error': 'PortValidationError_'+result['error'],
                'port': port
            }, queue)
        
    def remove_last_octet(self, ip):
        """
        Removes the last octet of an IP. 
        Used to calculate the network ID in small networks.
        """
        try:
            network_id = '.'.join(ip.split('.')[:3])
            return {
                'status': 'success',
                'network_id': network_id
            }
        except Exception as error:
            return {
                'status': 'error',
                'error': error
            }

    def process_result(self, result, queue=None):
        """
        Returns the result of a scan.
        If a queue is provided, it puts the result in the queue.
        """
        if queue:
            queue.put(result)
        else:
            return result
