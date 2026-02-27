"""
Module pour l'intégration de l'API IPQualityScore
Détection VPN, Proxy, Tor et autres informations de fraude
"""
import requests
import config

class IPQualityScoreAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://ipqualityscore.com/api/json/ip"
    
    def check_ip(self, ip, api_key=None):
        """
        Vérifie une IP avec IPQualityScore pour détecter VPN/Proxy
        
        Args:
            ip: Adresse IP à vérifier
            
        Returns:
            dict: Informations sur l'IP incluant VPN/Proxy/Tor
        """
        api_key = api_key or self.api_key
        if not api_key or api_key == 'VOTRE_CLÉ_API_ICI':
            return {
                'error': 'API key not configured',
                'vpn': None,
                'proxy': None,
                'tor': None
            }
        
        try:
            # Paramètres pour une analyse stricte
            params = {
                'strictness': 1,  # 0-3, 1 est recommandé pour un équilibre
                'allow_public_access_points': 'true',
                'lighter_penalties': 'false',
                'mobile': 'true'
            }
            
            url = f"{self.base_url}/{api_key}/{ip}"
            
            response = requests.get(
                url,
                params=params,
                timeout=config.REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Vérifier si la requête a réussi
                if not data.get('success', False):
                    return {
                        'error': data.get('message', 'Unknown error'),
                        'vpn': None,
                        'proxy': None,
                        'tor': None
                    }
                
                # Extraire les informations pertinentes
                result = {
                    'vpn': data.get('vpn', False),
                    'proxy': data.get('proxy', False),
                    'tor': data.get('tor', False),
                    'active_vpn': data.get('active_vpn', False),
                    'active_tor': data.get('active_tor', False),
                    'recent_abuse': data.get('recent_abuse', False),
                    'bot_status': data.get('bot_status', False),
                    'fraud_score': data.get('fraud_score', 0),
                    'connection_type': data.get('connection_type', 'Unknown'),
                    'abuse_velocity': data.get('abuse_velocity', 'none'),
                    'country_code': data.get('country_code', 'N/A'),
                    'city': data.get('city', 'N/A'),
                    'region': data.get('region', 'N/A'),
                    'isp': data.get('ISP', 'N/A'),
                    'organization': data.get('organization', 'N/A'),
                    'asn': data.get('ASN', 'N/A'),
                    'timezone': data.get('timezone', 'N/A'),
                    'mobile': data.get('mobile', False),
                    'host': data.get('host', 'N/A'),
                    'error': None
                }
                
                return result
            else:
                return {
                    'error': f'API returned status code {response.status_code}',
                    'vpn': None,
                    'proxy': None,
                    'tor': None
                }
                
        except requests.exceptions.Timeout:
            return {
                'error': 'Request timeout',
                'vpn': None,
                'proxy': None,
                'tor': None
            }
        except Exception as e:
            return {
                'error': str(e),
                'vpn': None,
                'proxy': None,
                'tor': None
            }
    
    def get_vpn_proxy_label(self, ipqs_data):
        """
        Génère un label et une couleur basés sur la détection VPN/Proxy
        
        Args:
            ipqs_data: Données retournées par check_ip()
            
        Returns:
            tuple: (label, color_class)
        """
        if ipqs_data.get('error'):
            return 'Unknown', 'secondary'
        
        vpn = ipqs_data.get('vpn', False)
        proxy = ipqs_data.get('proxy', False)
        tor = ipqs_data.get('tor', False)
        active_vpn = ipqs_data.get('active_vpn', False)
        active_tor = ipqs_data.get('active_tor', False)
        
        # Tor est le plus critique
        if tor or active_tor:
            return 'Tor Network', 'danger'
        
        # VPN actif
        if active_vpn:
            return 'Active VPN', 'warning'
        
        # VPN détecté
        if vpn:
            return 'VPN Detected', 'warning'
        
        # Proxy détecté
        if proxy:
            return 'Proxy Detected', 'warning'
        
        # Aucune détection
        return 'Clean', 'success'
    
    def get_fraud_score_label(self, fraud_score):
        """
        Convertit le fraud score en label et couleur
        
        Args:
            fraud_score: Score de fraude (0-100)
            
        Returns:
            tuple: (label, color_class)
        """
        if fraud_score >= 85:
            return 'Critical', 'danger'
        elif fraud_score >= 75:
            return 'High Risk', 'danger'
        elif fraud_score >= 50:
            return 'Medium Risk', 'warning'
        elif fraud_score >= 25:
            return 'Low Risk', 'info'
        else:
            return 'Very Low Risk', 'success'

# Instance globale
ipqs_api = IPQualityScoreAPI()
