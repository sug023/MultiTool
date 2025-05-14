import socket
import ipaddress

" IP MANAGEMENT "

def get_local_host_ipv4(time_out):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(time_out)
            s.connect(('8.8.8.8', 1))
            local_host_ip = s.getsockname()[0]
        return {
            'status': 'success',
            'local_host_ip': local_host_ip
        }
    except Exception as error:
        return {
            'status': 'error',
            'error': str(error)
        }

def get_network_class(ipv4):
    first_octet = int(ipv4.split('.')[0])
    if 1 <= first_octet <= 127:
        return {
            'status': 'success',
            'network_class': 'A',
            'prefix': 8
        }
    if 128 <= first_octet <= 191:
        return {
            'status': 'success',
            'network_class': 'B',
            'prefix': 16
        }
    if 192 <= first_octet <= 223:
        return {
            'status': 'success',
            'network_class': 'C',
            'prefix': 24
        }

def get_network_id(ipv4):
    network_class = get_network_class(ipv4)['network_class']
    if network_class == 'A':
        network_id = '.'.join(ipv4.split('.')[:1])
    elif network_class == 'B':
        network_id = '.'.join(ipv4.split('.')[:2])
    elif network_class == 'C':
        network_id  = '.'.join(ipv4.split('.')[:3])
    else:
        network_id == "unknown"
    return {
        'status': 'success',
        'network_id': network_id
    }

def validation_ipv4(ipv4, network_id=None):
    ip_parts = ipv4.split('.')
    if len(ip_parts) != 4:
        return False
    for str_octet in ip_parts:
        if not str_octet.isdigit():
            return False
        int_octet = int(str_octet)
        if not (0 <= int_octet <= 255):
            return False
        if str(int_octet) != str_octet:
            return False
    if network_id:
        if get_network_class(ipv4)['network_class'] != get_network_class(network_id)['network_class']:
            return False 
    return True

def check_ipv4(ipv4):
    if validation_ipv4(ipv4):
        return {
            'status': 'success',
            'ip': ipv4
        }
    else:
        return {
            'status': 'error',
            'error': f'Invalid IP -> {ipv4}',
            'ip': ipv4
        }

def create_network_from_ipv4(ipv4):
    prefix = get_network_class(ipv4)['prefix']
    network = ipaddress.IPv4Network(f"{ipv4}/{prefix}", strict=False)
    return network

def get_ipv4_range(ip1, ip2):
    ip_range = []
    network = create_network_from_ipv4(ip1)
    for ip in network.hosts():
        str_ip = str(ip)
        if str_ip <= ip2:
            ip_range.append(ip)

" PORT MANAGEMENT "

def port_validation(port):
    if not isinstance(port, int):
        return False
    elif not (0 <= port <= 65535):
        return False
    else:
        return True
    
def check_port(port):
    if port_validation(port):
        return {
            'status': 'success',
            'port': port
        }
    else:
        return {
            'status': 'error',
            'error': f'Invalid Port -> {port}',
            'port': port
        }
    
def get_port_range(port1:int, port2:int):
    port_range = []
    if port1 > port2: 
        port1, port2 = port2, port1
    for i in range(port1, port2+1):
        port_range.append(i)
    return port_range