import scapy.all as scapy

def check_port(target, port):
    # Pakket aanmaken om poort te scannen
    syn_packet = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="S")

    # Pakket versturen 
    response = scapy.sr1(syn_packet, timeout=1, verbose=False)

    # Antwoord controleren
    if response and response.haslayer(scapy.TCP):
        if response[scapy.TCP].flags == 0x12:  
            print(f"Port {port} on {target} is open")
        else:
            print(f"Port {port} on {target} is closed")
    else:
        print(f"Unable to determine the status of port {port} on {target}")

def main():
    # Test instellen
    target_ip = "www.google.com"
    target_port = 443
    check_port(target_ip, target_port)
    

if __name__ == "__main__":
    main()
