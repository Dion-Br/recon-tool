import scapy.all as scapy

def check_port(target, port):
    # Creating a TCP SYN packet
    syn_packet = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="S")

    # Sending the packet and waiting for a response
    response = scapy.sr1(syn_packet, timeout=1, verbose=False)

    # Checking the response
    if response and response.haslayer(scapy.TCP):
        if response[scapy.TCP].flags == 0x12:  # TCP flag for SYN-ACK
            print(f"Port {port} on {target} is open")
        else:
            print(f"Port {port} on {target} is closed")
    else:
        print(f"Unable to determine the status of port {port} on {target}")

def main():
    target_ip = "www.google.com"
    target_port = 443
    check_port(target_ip, target_port)
    

if __name__ == "__main__":
    main()
