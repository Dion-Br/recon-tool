import datetime
from cryptography import x509
from cryptography.hazmat.backends import openssl as openssl_backend
import ssl
import socket
import requests
from bs4 import BeautifulSoup

class SSLCertificateMonitor:
    def __init__(self, domain, port=443):
        self.domain = domain
        self.port = port

    def get_certificate(self):
        try:
            with socket.create_connection((self.domain, self.port), timeout=10) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=self.domain) as sslsock:
                    der_data = sslsock.getpeercert(True)
                    pem_data = ssl.DER_cert_to_PEM_cert(der_data)
                    return x509.load_pem_x509_certificate(pem_data.encode(), openssl_backend)
        except Exception as e:
            print(f"Error retrieving certificate for {self.domain}: {e}")
            print(type(e).__name__)  # Print the exception type for debugging
            return None

    def check_certificate_expiration(self, days_before_expiry=30):
        certificate = self.get_certificate()
        if certificate:
            expiration_date = certificate.not_valid_after
            current_date = datetime.datetime.now()
            remaining_days = (expiration_date - current_date).days

            if remaining_days <= 0:
                print(f"The SSL/TLS certificate for {self.domain} has expired.")
            elif remaining_days <= days_before_expiry:
                print(f"The SSL/TLS certificate for {self.domain} will expire in {remaining_days} days.")
            else:
                print(f"The SSL/TLS certificate for {self.domain} is valid for {remaining_days} more days.")

class LinkExtractor:
    def __init__(self, target_url):
        self.target_url = target_url

    def scan_for_links(self):
        try:
            response = requests.get(self.target_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [a['href'] for a in soup.find_all('a', href=True)]
                return links
            else:
                return f"Error: Unable to fetch the page (HTTP {response.status_code})"
        except Exception as e:
            return f"An error occurred: {str(e)}"

if __name__ == "__main__":
    # Example usage
    domain_to_monitor = "learning.ap.be"
    port_to_monitor = 443

    ssl_monitor = SSLCertificateMonitor(domain_to_monitor, port_to_monitor)
    ssl_monitor.check_certificate_expiration()

    target_url = "http://learning.ap.be"
    
    # Create an instance of SimpleWebScanner
    web_scanner = LinkExtractor(target_url)
    
    # Scan for links
    links = web_scanner.scan_for_links()
    
    # Display the result
    print("Links on the page:")
    for link in links:
        print(link)
