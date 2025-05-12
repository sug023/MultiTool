## PyScanner 🐍

**This is the documentation for the scanning module of the multitool.**

Here you will find an overview of each file, along with brief explanations of their functions and how they work.

I hope this will be helpful.


## Files 📁

The module is composed of three files:

1. **Scanner.py**
    
2. **HostScanner.py**
    
3. **PortScanner.py**
    

Together, these files define a parent class and two derived (or subclassed) classes.


### Scanner.py

The parent class handles validation, processing, extraction, and storage of key information.

This module contains 8 functions:

1. **__init__** -> This function is responsible for creating variables associated with the class, such as _timeout_value_, _local_host_ip_, _network_id_, _scanner_mac_value_, and _verbose_.
    
2. **get_local_host_ip** -> This function retrieves the host's IP address by sending a packet over the network. This ensures that the retrieved IP is the one assigned by the network to be scanned.
    
3. **ip_validation** -> It is responsible for verifying the IP address by ensuring that each octet is within the range of 0 to 255, as well as checking if the IP is valid for a Class C network.
    
4. **validate_ip_or_return** -> It checks if the IP is valid using `ip_validation`. If the IP is invalid, it returns an error; if valid, it returns nothing.
    
5. **port_validation** -> Validates whether a port is valid by checking if it is a number within the valid range of port numbers.
    
6. **validate_port_or_return** -> It checks if the port is valid using `port_validation`. If the port is invalid, it returns an error; if valid, it returns nothing.
    
7. **remove_last_octet** -> Removes the last octet of an IP address. This is used to obtain the network ID and to check if the entered IP is within the network.
    
8. **process_result** -> Checks if a queue is available to store the result. If so, it returns the result directly through the queue. This function exists to avoid repeating the same logic across both modules and to simplify the code.


### HostScanner

This subclass focuses on host scanning and performs **ARP**, **ICMP**, and **TTL-based OS** detection scans. It also has its own range scanner.

This module contains 5 functions:

1. **__init__** -> This function simply connects the parent class to the subclass.
    
2. **arp_scan** -> Scans an IP address using ARP mode. The result indicates whether the host is active or not, and if possible, returns its MAC address.
    
3. **icmp_scan** -> Scans an IP address using ICMP mode. The result indicates whether the host is active or not.
    
4. **os_scan** -> Performs an ARP scan and retrieves the TTL value to identify the operating system based on it.
    
5. **range_scan** -> Performs a multithreaded scan using the previously defined modes.
    

### PortScanner

This subclass focuses on port scanning by performing **TCP** and **UDP** scans. It also has its own range scanning.

This module contains 5 functions:

1. **__init__** -> This function simply connects the parent class to the subclass.
    
2. **ip_and_port_validation** -> Uses the port and IP validation functions to avoid code duplication.
    
3. **tcp_scan** -> Performs a TCP scan and returns the port status, which can be _open_, _closed_, or _filtered_.
    
4. **udp_scan** -> Performs a UDP scan and returns the port status, which can be _open_, _closed_, or _filtered_.
    
5. **range_scan** -> Performs a multithreaded scan using the previously mentioned modes.

