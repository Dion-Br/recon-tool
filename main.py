from icmp import send_icmp_request

# Volledige recon tool
def main():
    if send_icmp_request(target="99.99.99.99") is not False:
        # Als target online is verder gaan met recon
        print("Hello world")
    

if __name__ == "__main__":
    main()
