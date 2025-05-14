from global_functions.network_mgr import get_local_host_ipv4, get_network_id

class BaseScanner():
    
    def __init__(self):
        self.local_host_ip = get_local_host_ipv4()
        self.network_id = get_network_id(self.local_host_ip)
        self.scanner_mac = 'ff:ff:ff:ff:ff:ff'
        self.timeout_val = 1
        self.verbose = False
        self.thread_val = 250