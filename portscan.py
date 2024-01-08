import scapy.all as scapy
import nmap

def check_port(target, port_list = [22, 80, 443, 8000]):

    open_port_list = []

    for port in port_list:
        # Pakket aanmaken om poort te scannen
        syn_packet = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="S")

        # Pakket versturen 
        response = scapy.sr1(syn_packet, timeout=1, verbose=False)

        # Antwoord controleren
        if response and response.haslayer(scapy.TCP):
            if response[scapy.TCP].flags == 0x12:  
                print(f"Port {port} on {target} is open")
                open_port_list.append(port)
            else:
                print(f"Port {port} on {target} is closed")
        else:
            print(f"Unable to determine the status of port {port} on {target}")

    return(open_port_list)

def identify_service_on_open_ports(target, open_ports):
    # Ensure target is a string
    if not isinstance(target, str):
        raise ValueError("Target should be a string.")

    nm = nmap.PortScanner()

    # Service identification 'sV' scan uitvoeren op de open poorten
    nm.scan(target, arguments=f'-sS -p {",".join(map(str, open_ports))} -sV')
    scan_results = nm.all_hosts(), nm

    identified_services = []

    # Service mooi weergeven
    for host in scan_results[0]:
        for port, info in scan_results[1][host]['tcp'].items():
            if int(port) in open_ports:
                service_name = info.get('product', 'Unknown Service')
                version = info.get('version', 'Unknown Version')

                identified_service = {
                    'host': host,
                    'port': int(port),
                    'service_name': service_name,
                    'version': version
                }

                identified_services.append(identified_service)

    return identified_services

def main():
    # Test instellen
    target_ip = "www.google.com"
    port_list = [21, 80, 443, *range(444,447)]
    identify_service_on_open_ports(target_ip, check_port(target_ip, port_list))
    

if __name__ == "__main__":
    main()
