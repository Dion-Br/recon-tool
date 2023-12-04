import datetime
from cryptography import x509
from cryptography.hazmat.backends import openssl as openssl_backend
import ssl
import socket

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
            current_date = datetime.datetime.utcnow()
            remaining_days = (expiration_date - current_date).days

            if remaining_days <= 0:
                print(f"The SSL/TLS certificate for {self.domain} has expired.")
            elif remaining_days <= days_before_expiry:
                print(f"The SSL/TLS certificate for {self.domain} will expire in {remaining_days} days.")
            else:
                print(f"The SSL/TLS certificate for {self.domain} is valid for {remaining_days} more days.")

if __name__ == "__main__":
    # Example usage
    domain_to_monitor = "www.google.com"
    port_to_monitor = 443

    ssl_monitor = SSLCertificateMonitor(domain_to_monitor, port_to_monitor)
    ssl_monitor.check_certificate_expiration()
