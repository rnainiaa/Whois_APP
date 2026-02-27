"""
Utilitaires pour la validation et le traitement des données
"""
import re
import socket
import ipaddress

def is_valid_ip(ip):
    """Vérifie si une chaîne est une adresse IP valide"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """Vérifie si une chaîne est un nom de domaine valide"""
    # Pattern pour domaine valide
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'  # Premier caractère
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'  # Sous-domaines
        r'+[a-zA-Z]{2,}$'  # TLD
    )
    return bool(pattern.match(domain))

def extract_ips_from_text(text):
    """Extrait toutes les adresses IP d'un texte"""
    # Pattern pour IPv4
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ipv4_pattern, text)
    
    # Filtrer les IPs valides
    valid_ips = [ip for ip in ips if is_valid_ip(ip)]
    return list(set(valid_ips))

def extract_domains_from_text(text):
    """Extrait tous les domaines d'un texte"""
    # Pattern pour domaines
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, text)
    
    # Filtrer les domaines valides
    valid_domains = [d for d in domains if is_valid_domain(d)]
    return list(set(valid_domains))

def defang_ioc(ioc):
    """Défangue un IOC (Indicator of Compromise) pour éviter les clics accidentels"""
    ioc = ioc.replace('http://', 'hxxp://')
    ioc = ioc.replace('https://', 'hxxps://')
    ioc = ioc.replace('.', '[.]')
    ioc = ioc.replace('@', '[@]')
    return ioc

def refang_ioc(ioc):
    """Refangue un IOC défangué"""
    ioc = ioc.replace('hxxp://', 'http://')
    ioc = ioc.replace('hxxps://', 'https://')
    ioc = ioc.replace('[.]', '.')
    ioc = ioc.replace('[@]', '@')
    return ioc

def classify_ip(ip):
    """Classifie une adresse IP (publique, privée, réservée, etc.)"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        if ip_obj.is_private:
            return 'private'
        elif ip_obj.is_loopback:
            return 'loopback'
        elif ip_obj.is_multicast:
            return 'multicast'
        elif ip_obj.is_reserved:
            return 'reserved'
        elif ip_obj.is_link_local:
            return 'link_local'
        else:
            return 'public'
    except ValueError:
        return 'invalid'

def get_severity_color(severity):
    """Retourne une couleur CSS basée sur la sévérité"""
    colors = {
        'critical': '#dc3545',  # Rouge
        'high': '#fd7e14',      # Orange
        'medium': '#ffc107',    # Jaune
        'low': '#28a745',       # Vert
        'info': '#17a2b8',      # Bleu
        'unknown': '#6c757d'    # Gris
    }
    return colors.get(severity.lower(), colors['unknown'])

def calculate_risk_score(data):
    """Calcule un score de risque basé sur plusieurs facteurs"""
    score = 0
    
    # VirusTotal
    if 'virustotal' in data and 'malicious' in data['virustotal']:
        vt_malicious = data['virustotal']['malicious']
        if vt_malicious > 5:
            score += 50
        elif vt_malicious > 0:
            score += 30
    
    # AbuseIPDB
    if 'abuse_score' in data:
        try:
            abuse = int(data['abuse_score'].replace('%', ''))
            score += min(abuse // 2, 30)
        except:
            pass
    
    # Réputation
    if 'virustotal' in data and 'reputation' in data['virustotal']:
        rep = data['virustotal']['reputation']
        if rep < -50:
            score += 20
        elif rep < 0:
            score += 10
    
    return min(score, 100)

def get_risk_label(score):
    """Retourne un label de risque basé sur le score"""
    if score >= 70:
        return 'Critical', 'critical'
    elif score >= 50:
        return 'High', 'high'
    elif score >= 30:
        return 'Medium', 'medium'
    elif score >= 10:
        return 'Low', 'low'
    else:
        return 'Info', 'info'
