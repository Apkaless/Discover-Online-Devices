from scapy.all import ARP, Ether, sniff, conf, srp
import socket
import os
import psutil
import re
import ipaddress

def get_iface():
    interfaces = []
    for i in conf.ifaces.values():
        if 'Ethernet' == i.name:
            interfaces.append(i.name)
        elif 'Wi-Fi' == i.name:
            interfaces.append(i.name)
    
    return interfaces

def discover_online(iface, subnet_range):
    online = []
    arp_packet = ARP(pdst=subnet_range)
    ether_frame = Ether(dst='ff:ff:ff:ff:ff:ff')

    stacked_layers = ether_frame / arp_packet

    res = srp(stacked_layers, timeout=5, verbose=False, iface=iface)[0]
    if res:
        for i in res:
            device = i[0][1].pdst
            online.append(device)

    return online

def get_subnet(iface):
    ip_address_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    for i in psutil.net_if_addrs()[iface]:
        res = re.findall(ip_address_pattern, i.address)
        if res:
            netmask = i.netmask
            ip_address = res[0]
            subnet_range = ipaddress.ip_network(f'{ip_address}/{netmask}', strict=False)
            return str(subnet_range)

if __name__ == '__main__':
    os.system('cls')
    ifaces = get_iface()
    if ifaces:
        print('[~] Select Interface:\n')
        for num, available_iface in enumerate(ifaces, start=1):
            print(f'\t\t{num}) {available_iface}')
        iface_num = int(input('>>> '))
        os.system('cls')
        if iface_num:
            iface = ifaces[iface_num-1]
            subnet_range = get_subnet(iface)
            online_devices = discover_online(iface, subnet_range)
            count_devices = len(online_devices)
            if online_devices:
                print(f'[+] Found {count_devices} Connected {"Devices" if count_devices > 1 else "Device"}\n', '-'*50)
                for device in online_devices:
                    print(f'[+] Online Device -> {device}')
            else:
                print('[-] No Online Devices Were Found.')
    else:
        print('[-] No Interfaces Were Found.')

    input('\n')