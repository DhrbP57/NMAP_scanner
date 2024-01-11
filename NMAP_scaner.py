#!/usr/bin/python3

import nmap
import ipaddress

def is_valid_ip(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def manual_port_scan():
    ip_range = input("Please enter the IP aport range you want to scan: ")
    return ip_range

def file_port_scan():
    file_path = input("Please enter the path to the file with port range: ")
    with open(file_path, 'r') as file:
        port_range = file.read().strip()
    return port_range


scanner = nmap.PortScanner()

print("Welcome in simple nmap tool")
print("Nmap Version: ", scanner.nmap_version())
print("<--------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The  IP you entered is: ", ip_addr)

if is_valid_ip(ip_addr):
	
	
			
	resp = input(""" \nPlease choose how you want to specify the target:
                    1) Manual IP entry
                    2) File with port range
                    : """)

	if resp == '1':
		ip_range = manual_port_scan()
	elif resp == '2':
		ip_range = file_port_scan()
		
	resp = input(""" \nPlease enter the type of scan you want to run
			1)SYN ACK Scan
			2)UDP Scan
			3)Comprehensive Scan
			:""")	
		
	print("You have selected option: ",resp)

	if resp == '1':
		scanner.scan(ip_addr, ip_range, '-v -sS')
		print(scanner.scaninfo())
		print("Ip Status: ", scanner[ip_addr].state())
		print(scanner[ip_addr].all_protocols())
		print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

	elif resp == '2':
		scanner.scan(ip_addr, ip_range, '-v -sU')
		print(scanner.scaninfo())
		print("Ip Status: ", scanner[ip_addr].state())
		print(scanner[ip_addr].all_protocols())
		print("Open Ports: ", scanner[ip_addr]['udp'].keys())
		
	elif resp == '3':
		scanner.scan(ip_addr, ip_range, '-v -sS -sV -sC -A -O')
		print(scanner.scaninfo())
		print("IP Status:", scanner[ip_addr].state())
		print(scanner[ip_addr].all_protocols())
		    
		# Access to service information after using -sV
		for port, info in scanner[ip_addr]['tcp'].items():
			print(f"Port {port} - Service: {info['name']}, Version: {info['version']}")

		print("Open Ports:", scanner[ip_addr]['tcp'].keys())
		
		# Wyświetlanie informacji związanych z -sC
		print("Scripts Output:")
		for host, script in scanner[ip_addr].get('script', {}).items():
			print(f"Script for {host}: {script}")

		# WDisplay information related to the -O (operation system)
		os_detection = scanner[ip_addr].get('osclass', [])
		if os_detection:
			print("OS Detection:")
			print(f"Detected OS: {os_detection[0]['osfamily']}")
			print(f"OS Accuracy: {os_detection[0]['accuracy']}")
		else:
			print("OS Detection: Not available")
	elif resp >= '4':
		print("Please enter a valid option")
else:
    print("Invalid IP address. Please enter a valid IP.")








