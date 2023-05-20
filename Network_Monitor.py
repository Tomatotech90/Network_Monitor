import os
import socket
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
               ObjectType(ObjectIdentity(oid))), None
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


def traceroute(target):
    command = ['traceroute', target]
    try:
        traceroute_output = subprocess.check_output(command).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error running traceroute: {str(e)}")
        traceroute_output = ""
    return traceroute_output


def analyze_traceroute(traceroute_output):
    lines = traceroute_output.split('\n')
    for line in lines:
        if "!" in line:
            print(f"Possible network issue: {line}")


def dns_lookup(target):
    command = ['nslookup', target]
    try:
        dns_output = subprocess.check_output(command).decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error running nslookup: {str(e)}")
        dns_output = ""
    return dns_output


def port_scan(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-p1-65535')
    except nmap.PortScannerError as e:
        print(f"Error scanning ports: {str(e)}")
        return None
    return nm[target]['tcp']


def os_fingerprint(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-O')
    except nmap.PortScannerError as e:
        print(f"Error performing OS fingerprint: {str(e)}")
        return None
    return nm[target]['osclass']


def ip_subnet(ip_address, netmask):
    try:
        subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    except ipaddress.AddressValueError as e:
        print(f"Error calculating subnet: {str(e)}")
        return None
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
    print(Fore.YELLOW + "6. Get bandwidth usage" + Style.RESET_ALL + ": Get the amount of bandwidth being used on the network")
    print(Fore.YELLOW + "7. Get packet drops" + Style.RESET_ALL + ": Get the number of dropped packets on the network")
    print(Fore.YELLOW + "8. Get CPU and memory usage" + Style.RESET_ALL + ": Get the CPU and memory usage of the target device")
    print(Fore.YELLOW + "9. Get network errors" + Style.RESET_ALL + ": Get the number of network errors on the target device")
    print(Fore.YELLOW + "10. Collect NetFlow data" + Style.RESET_ALL + ": Collect NetFlow data for the target for a specified duration")
    print(Fore.YELLOW + "11. Analyze traceroute" + Style.RESET_ALL + ": Analyze the traceroute output for potential issues")

    option = input("Enter an option number: ")

    if option == '1':
        print("Performing traceroute...")
        traceroute_output = traceroute(target)
        print(traceroute_output)
        save_to_file('traceroute.txt', traceroute_output)

    # (Include the corresponding elif statements for options 2-5)

    elif option == '6':
        print("Getting bandwidth usage...")
        data_transmitted, data_received = get_bandwidth_usage(target)
        print(f"Data transmitted: {data_transmitted}")
        print(f"Data received: {data_received}")
        save_to_file('bandwidth_usage.txt', f"Data transmitted: {data_transmitted}\nData received: {data_received}")

    elif option == '7':
        print("Getting packet drops...")
        dropped_packets = get_packet_drops(target)
        print(f"Dropped packets: {dropped_packets}")
        save_to_file('packet_drops.txt', f"Dropped packets: {dropped_packets}")
    elif option == '8':
        print("Getting CPU and memory usage...")
        cpu_usage, memory_usage = get_cpu_memory_usage(target)
        print(f"CPU usage: {cpu_usage}%")
        print(f"Memory usage: {memory_usage}%")
        save_to_file('cpu_memory_usage.txt', f"CPU usage: {cpu_usage}%\nMemory usage: {memory_usage}%")

    elif option == '9':
        print("Getting network errors...")
        collisions, crc_errors = get_network_errors(target)
        print(f"Collisions: {collisions}")
        print(f"CRC errors: {crc_errors}")
        save_to_file('network_errors.txt', f"Collisions: {collisions}\nCRC errors: {crc_errors}")

    elif option == '10':
        duration = int(input("Enter collection duration in seconds: "))
        print("Collecting NetFlow data...")
        flow_counter = collect_netflow_data(target, duration)
        print(f"Collected {len(flow_counter)} flows")
        save_to_file('netflow_data.txt', str(flow_counter))

    elif option == '11':
        print("Analyzing traceroute...")
        traceroute_output = traceroute(target)
        analyze_traceroute(traceroute_output)

    else:
        print(Fore.RED + "Invalid option!" + Style.RESET_ALL)

