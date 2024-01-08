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

    # Functie die certificaten ophaalt
    def get_certificate(self):
        try:
            with socket.create_connection((self.domain, self.port), timeout=10) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=self.domain) as sslsock:
                    der_data = sslsock.getpeercert(True)
                    pem_data = ssl.DER_cert_to_PEM_cert(der_data)
                    return x509.load_pem_x509_certificate(pem_data.encode(), openssl_backend)
        except Exception as e:
            return(f"Kon certificaat niet terugvinden voor {self.domain}: {e}")

    # Functie die geldigheid controleert
    def check_certificate_expiration(self, days_before_expiry=30):
        certificate = self.get_certificate()
        if certificate:
            expiration_date = certificate.not_valid_after
            current_date = datetime.datetime.now()
            remaining_days = (expiration_date - current_date).days

            if remaining_days <= 0:
                return f"Het SSL/TLS certificaat voor {self.domain} is vervallen."
            elif remaining_days <= days_before_expiry:
                return f"Het SSL/TLS certificaat voor {self.domain} zal vervallen in {remaining_days} dagen."
            else:
                return f"Het SSL/TLS certificaat voor {self.domain} is nog {remaining_days} dagen geldig."

class LinkExtractor:
    def __init__(self, target_url):
        self.target_url = target_url

    # Functie die alle klikbare links op een site ophaalt en meegeeft
    def scan_for_links(self):
        try:
            response = requests.get(self.target_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [a['href'] for a in soup.find_all('a', href=True)]
                return links
            else:
                return f"Error: Kan pagina niet vinden (HTTP {response.status_code})"
        except Exception as e:
            return f"Fout: {str(e)}"

if __name__ == "__main__":
    # Testen
    domain_to_monitor = "learning.ap.be"
    port_to_monitor = 443

    ssl_monitor = SSLCertificateMonitor(domain_to_monitor, port_to_monitor)
    ssl_monitor.check_certificate_expiration()

    target_url = "https://learning.ap.be"
    
    # Linkscanner aanmaken
    web_scanner = LinkExtractor(target_url)
    links = web_scanner.scan_for_links()
    
    for link in links:
        print(link)
