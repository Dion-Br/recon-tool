import scapy.all as scapy

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
    for port in open_ports:
        # Create a packet to send to the target and port
        packet = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="S")

        # Send the packet and receive the response
        response = scapy.sr1(packet, timeout=1, verbose=False)

        # Checking the response
        print(f"Port {port} on {target} is open")

        # Now, let's try to identify the service
        try:
            service_response = scapy.sr1(scapy.IP(dst=target) / scapy.TCP(dport=port, flags="S"), timeout=1, verbose=False)
            if service_response and service_response.haslayer(scapy.TCP):
                if service_response[scapy.TCP].flags == 0x14:
                    print(f"The service on port {port} is likely closed.")
                elif service_response[scapy.TCP].flags == 0x12:
                    print(f"The service on port {port} is likely open.")
                    # You can further analyze the response to identify the service here
                else:
                    print(f"Unable to determine the service on port {port} on {target}")
            else:
                print(f"Unable to determine the service on port {port} on {target}")
        except Exception as e:
            print(f"Error while identifying service on port {port}: {e}")

def main():
    # Test instellen
    target_ip = "www.google.com"
    port_list = [21, 80, 443, *range(444,447)]
    identify_service_on_open_ports(target_ip, check_port(target_ip, port_list))
    

if __name__ == "__main__":
    main()
