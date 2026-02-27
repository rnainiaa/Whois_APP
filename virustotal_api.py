"""
Module d'intégration avec VirusTotal API
"""
import requests
import time
import config

class VirusTotalAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def _get_headers(self, api_key):
        return {"x-apikey": api_key} if api_key else {}
    
    def check_ip(self, ip, api_key=None):
        """Vérifie la réputation d'une IP sur VirusTotal"""
        api_key = api_key or self.api_key
        if not api_key:
            return {"error": "Clé API VirusTotal non configurée"}
        
        try:
            url = f"{self.base_url}/ip_addresses/{ip}"
            response = requests.get(url, headers=self._get_headers(api_key), timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_ip_response(data)
            elif response.status_code == 404:
                return {"error": "IP non trouvée dans VirusTotal"}
            elif response.status_code == 429:
                return {"error": "Limite de requêtes atteinte"}
            else:
                return {"error": f"Erreur API ({response.status_code})"}
        except Exception as e:
            return {"error": f"Erreur requête: {str(e)}"}
    
    def check_domain(self, domain, api_key=None):
        """Vérifie la réputation d'un domaine sur VirusTotal"""
        api_key = api_key or self.api_key
        if not api_key:
            return {"error": "Clé API VirusTotal non configurée"}
        
        try:
            url = f"{self.base_url}/domains/{domain}"
            response = requests.get(url, headers=self._get_headers(api_key), timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_domain_response(data)
            elif response.status_code == 404:
                return {"error": "Domaine non trouvé dans VirusTotal"}
            elif response.status_code == 429:
                return {"error": "Limite de requêtes atteinte"}
            else:
                return {"error": f"Erreur API ({response.status_code})"}
        except Exception as e:
            return {"error": f"Erreur requête: {str(e)}"}
    
    def _parse_ip_response(self, data):
        """Parse la réponse de l'API pour une IP"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'total_engines': sum(stats.values()),
            'reputation': attributes.get('reputation', 0),
            'country': attributes.get('country', 'N/A'),
            'asn': attributes.get('asn', 'N/A'),
            'as_owner': attributes.get('as_owner', 'N/A'),
            'last_analysis_date': attributes.get('last_analysis_date', 'N/A')
        }
    
    def _parse_domain_response(self, data):
        """Parse la réponse de l'API pour un domaine"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'total_engines': sum(stats.values()),
            'reputation': attributes.get('reputation', 0),
            'categories': attributes.get('categories', {}),
            'creation_date': attributes.get('creation_date', 'N/A'),
            'last_update_date': attributes.get('last_update_date', 'N/A'),
            'last_analysis_date': attributes.get('last_analysis_date', 'N/A'),
            'registrar': attributes.get('registrar', 'N/A')
        }
    
    def get_threat_label(self, vt_data):
        """Génère un label de menace basé sur les résultats VirusTotal"""
        if 'error' in vt_data:
            return 'unknown', 'grey'
        
        malicious = vt_data.get('malicious', 0)
        suspicious = vt_data.get('suspicious', 0)
        
        if malicious > 5:
            return 'malicious', 'red'
        elif malicious > 0 or suspicious > 3:
            return 'suspicious', 'orange'
        elif vt_data.get('reputation', 0) < -50:
            return 'low-reputation', 'yellow'
        else:
            return 'clean', 'green'

# Instance globale
vt_api = VirusTotalAPI()
