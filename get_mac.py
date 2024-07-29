from scapy.all import Ether, ARP, srp, conf
import ipaddress
import psutil
import os
import re


def get_mac(ip, iface):
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    res = re.match(ip_pattern, ip)
    if res:
        ip = res.group()
    else:
        print('[-] Not Correct IP Address Format.')
        return False
    
    arp_packet = ARP(pdst=ip)

    ether_frame = Ether(dst='ff:ff:ff:ff:ff:ff')

    request = ether_frame / arp_packet

    response = srp(request, iface=iface, verbose=False, timeout=3)[0]

    if response:
        for i in response:
           mac_address = i[1].hwsrc

        return mac_address
    else:
        print(f'[-] Failed.')


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
                print('[~] Select Device:')
                for item, device in enumerate(online_devices, start=1):
                    print(f'\t\t[{item}] Online Device -> {device}')
                dev_num = int(input('>>> '))
                if dev_num:
                    os.system('cls')
                    dev_ip = online_devices[dev_num-1]
                    mac_address = get_mac(dev_ip, iface)
                    if mac_address:
                        print(f'[+] Mac Address Of {dev_ip} is --> {mac_address}')
            else:
                print('[-] No Online Devices Were Found.')
    else:
        print('[-] No Interfaces Were Found.')

    input('\n')