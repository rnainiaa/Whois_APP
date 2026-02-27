"""
Module d'analyse DNS pour les domaines
"""
import dns.resolver
import dns.reversename
import socket
import ssl
import OpenSSL
from datetime import datetime
from urllib.parse import urlparse
import requests
import config

class DNSAnalyzer:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = config.REQUEST_TIMEOUT
        self.resolver.lifetime = config.REQUEST_TIMEOUT
    
    def analyze_domain(self, domain):
        """Analyse complète d'un domaine"""
        # Nettoyer le domaine (enlever http://, https://, etc.)
        domain = self._clean_domain(domain)
        
        result = {
            'domain': domain,
            'dns_records': self._get_dns_records(domain),
            'ip_addresses': [],
            'ssl_info': None,
            'whois': None,
            'reputation': {}
        }
        
        # Récupérer les IPs associées
        if result['dns_records'].get('A'):
            result['ip_addresses'] = result['dns_records']['A']
        
        # Analyse SSL/TLS
        try:
            result['ssl_info'] = self._get_ssl_info(domain)
        except Exception as e:
            result['ssl_info'] = {'error': str(e)}
        
        return result
    
    def _clean_domain(self, domain):
        """Nettoie le domaine des préfixes inutiles"""
        domain = domain.strip().lower()
        
        # Enlever http://, https://
        if domain.startswith('http://'):
            domain = domain[7:]
        elif domain.startswith('https://'):
            domain = domain[8:]
        
        # Enlever le chemin
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Enlever le port
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    
    def _get_dns_records(self, domain):
        """Récupère tous les enregistrements DNS"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                if record_type == 'MX':
                    records[record_type] = [f"{r.preference} {r.exchange}" for r in answers]
                elif record_type == 'SOA':
                    records[record_type] = [str(answers[0])]
                else:
                    records[record_type] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                records[record_type] = []
            except Exception as e:
                records[record_type] = [f"Error: {str(e)}"]
        
        return records
    
    def _get_ssl_info(self, domain, port=443):
        """Récupère les informations du certificat SSL/TLS"""
        try:
            # Créer une connexion SSL
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    
                    # Extraire les informations
                    subject = dict(x[0] for x in cert.get_subject().get_components())
                    issuer = dict(x[0] for x in cert.get_issuer().get_components())
                    
                    return {
                        'subject': {k.decode(): v.decode() for k, v in subject.items()},
                        'issuer': {k.decode(): v.decode() for k, v in issuer.items()},
                        'version': cert.get_version(),
                        'serial_number': cert.get_serial_number(),
                        'not_before': datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ').isoformat(),
                        'not_after': datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ').isoformat(),
                        'has_expired': cert.has_expired()
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def reverse_dns(self, ip):
        """Effectue une recherche DNS inversée"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "N/A"
    
    def is_domain(self, query):
        """Vérifie si la requête est un domaine ou une IP"""
        # Vérifier si c'est une IP
        try:
            socket.inet_aton(query.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0])
            return False  # C'est une IP
        except socket.error:
            return True  # C'est probablement un domaine

# Instance globale
dns_analyzer = DNSAnalyzer()
