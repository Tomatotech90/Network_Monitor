import os
import subprocess
import time
import nmap
import ipaddress
from colorama import Fore, Style
from collections import Counter
from pysnmp.hlapi import *
from netflow_collector import NetFlowCollector

def get_bandwidth_usage(snmp_target):
    data_transmitted = snmp_get(snmp_target, '1.3.6.1.2.1.2.2.1.16')
    data_received = snmp_get(snmp_target, '1.3.6.1.2.1.2.2.1.10')
    return data_transmitted, data_received


def snmp_get(target, oid):
    error_indication, error_status, error_index, var_binds = next(
        getCmd(SnmpEngine(),
               CommunityData('public'),
               UdpTransportTarget((target, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )

    if error_indication:
        print(f"SNMP Error: {error_indication}")
    elif error_status:
        print(f"SNMP Error: {error_status.prettyPrint()}")
    else:
        for var_bind in var_binds:
            return var_bind[1]


def get_packet_drops(snmp_target):
    dropped_packets = snmp_get(snmp_target, '1.3.6.1.2.1.2.2.1.13')
    return dropped_packets


def get_cpu_memory_usage(snmp_target):
    cpu_usage = snmp_get(snmp_target, '1.3.6.1.4.1.9.9.109.1.1.1.1.5')
    memory_usage = snmp_get(snmp_target, '1.3.6.1.4.1.9.9.48.1.1.1.5')
    return cpu_usage, memory_usage


def get_network_errors(snmp_target):
    collisions = snmp_get(snmp_target, '1.3.6.1.2.1.2.2.1.14')
    crc_errors = snmp_get(snmp_target, '1.3.6.1.2.1.16.1.1.1.12')
    return collisions, crc_errors


def netflow_callback(flow_data):
    global flow_counter
    src_ip = flow_data['srcaddr']
    flow_counter[src_ip] += 1


def collect_netflow_data(netflow_target, duration):
    global flow_counter
    flow_counter = Counter()

    collector = NetFlowCollector(netflow_callback)
    collector.start_collection(netflow_target, 2055)

    time.sleep(duration)
    collector.stop_collection()

    return flow_counter


def analyze_netflow_data(flow_counter):
    top_talkers = flow_counter.most_common(5)
    return top_talkers
  
  # New function: Traceroute
def traceroute(target):
    command = ['traceroute', target]
    traceroute_output = subprocess.check_output(command).decode('utf-8')
    return traceroute_output

# New function: Analyze traceroute output
def analyze_traceroute(traceroute_output):
    lines = traceroute_output.split('\n')
    for line in lines:
        if "!" in line:
            print(f"Possible network issue: {line}")

# New function: Perform a DNS lookup
def dns_lookup(target):
    command = ['nslookup', target]
    dns_output = subprocess.check_output(command).decode('utf-8')
    return dns_output
  
  # New function: Port scanning
def port_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-p1-65535')
    return nm[target]['tcp']

# New function: OS Fingerprinting
def os_fingerprint(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-O')
    return nm[target]['osclass']

# New function: IP subnet calculation
def ip_subnet(ip_address, netmask):
    subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    return subnet

  

def save_to_file(filename, content):
    with open(filename, 'w') as file:
        file.write(content)

if __name__ == '__main__':
    target = input("Enter target IP or website: ")

    print(Fore.RED + "MENU:" + Style.RESET_ALL)
    print(Fore.YELLOW + "1. Perform traceroute" + Style.RESET_ALL + ": Find the network path to the target")
    print(Fore.YELLOW + "2. Perform DNS lookup" + Style.RESET_ALL + ": Get DNS information for the target")
    print(Fore.YELLOW + "3. Perform port scanning" + Style.RESET_ALL + ": Scan all TCP ports on the target")
    print(Fore.YELLOW + "4. Perform OS fingerprinting" + Style.RESET_ALL + ": Attempt to identify the target's operating system")
    print(Fore.YELLOW + "5. Calculate IP subnet" + Style.RESET_ALL + ": Calculate the IP subnet for the target")

    option = input("Enter an option number: ")

    if option == '1':
        print("Performing traceroute...")
        traceroute_output = traceroute(target)
        print(traceroute_output)
        save_to_file('traceroute.txt', traceroute_output)

    elif option == '2':
        print("Performing DNS lookup...")
        dns_output = dns_lookup(target)
        print(dns_output)
        save_to_file('dns_lookup.txt', dns_output)

    elif option == '3':
        print("Performing port scanning...")
        open_ports = port_scan(target)
        print("Open ports:")
        for port, info in open_ports.items():
            print(f"{port}/{info['name']} ({info['state']})")
        save_to_file('port_scan.txt', str(open_ports))

    elif option == '4':
        print("Performing OS fingerprinting...")
        os_info = os_fingerprint(target)
        for os_class in os_info:
            print(f"{os_class['osfamily']} {os_class['osgen']} ({os_class['accuracy']}% confidence)")
        save_to_file('os_fingerprint.txt', str(os_info))

    elif option == '5':
        print("Calculating IP subnet...")
        ip_address = socket.gethostbyname(target)
        netmask = "24"  # You may need to adjust this depending on the target network
        subnet = ip_subnet(ip_address, netmask)
        print(f"Subnet: {subnet}")
        save_to_file('ip_subnet.txt', str(subnet))

    else:
        print(Fore.RED + "Invalid option!" + Style.RESET_ALL)
