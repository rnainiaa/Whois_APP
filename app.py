from flask import Flask, render_template, request, Response, jsonify, send_file, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import ipwhois
import io
import csv
import json
import shutil
import requests
import geoip2.database
import socket
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import os
import gzip
from datetime import datetime

# Import des nouveaux modules
import config
from database import db
from dns_analyzer import dns_analyzer
from virustotal_api import vt_api
from ipqualityscore_api import ipqs_api
import utils
from user_model import User
from forms import LoginForm, RegistrationForm, ProfileForm

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY if hasattr(config, 'SECRET_KEY') else 'dev-secret-key-change-in-prod'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

# --- Initialisation de la base de données GeoLite2 ---
def setup_geolite_db():
    if not os.path.exists(config.GEOLITE_DB):
        print(f"Base de données GeoLite2 non trouvée. Téléchargement...")
        url = "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"
        gz_path = config.GEOLITE_DB + ".gz"
        try:
            with requests.get(url, stream=True) as r:
                r.raise_for_status()
                with open(gz_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            
            print("Décompression...")
            with gzip.open(gz_path, 'rb') as f_in:
                with open(config.GEOLITE_DB, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            os.remove(gz_path)
            print("Base de données GeoLite2 prête.")
        except Exception as e:
            print(f"Erreur lors du téléchargement/décompression de GeoLite2 : {e}")
            return None
    return geoip2.database.Reader(config.GEOLITE_DB)

geoip_reader = setup_geolite_db()

def get_abuseipdb_score(ip, api_key):
    if not api_key or api_key == 'VOTRE_CLÉ_API_ICI':
        return "Clé API manquante"
    try:
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check",
                                headers={'Key': api_key, 'Accept': 'application/json'},
                                params={'ipAddress': ip, 'maxAgeInDays': '90'},
                                timeout=config.REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()['data']
            score = data['abuseConfidenceScore']
            return f"{score}%"
        else:
            return f"Erreur API ({response.status_code})"
    except Exception as e:
        return "Erreur requête"

def get_whois_info(ip, api_keys):
    """Récupère les informations WHOIS pour une IP"""
    # Vérifier le cache d'abord
    cached = db.get_cached_ip(ip)
    if cached:
        cached['from_cache'] = True
        return cached
    
    try:
        obj = ipwhois.IPWhois(ip)
        whois_info = obj.lookup_whois()
        
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            reverse_dns = "N/A"

        # Géolocalisation
        city, region = "N/A", "N/A"
        if geoip_reader:
            try:
                response = geoip_reader.city(ip)
                city = response.city.name or "N/A"
                region = response.subdivisions.most_specific.name or "N/A"
            except geoip2.errors.AddressNotFoundError:
                pass

        # Score AbuseIPDB
        abuse_score = get_abuseipdb_score(ip, api_keys.get('abuseipdb'))
        
        # VirusTotal
        vt_data = vt_api.check_ip(ip, api_key=api_keys.get('virustotal'))
        threat_label, threat_color = vt_api.get_threat_label(vt_data)
        
        # IPQualityScore - Détection VPN/Proxy
        ipqs_data = ipqs_api.check_ip(ip, api_key=api_keys.get('ipqualityscore'))
        vpn_proxy_label, vpn_proxy_color = ipqs_api.get_vpn_proxy_label(ipqs_data)
        fraud_label, fraud_color = ipqs_api.get_fraud_score_label(ipqs_data.get('fraud_score', 0))

        net_info = {}
        if whois_info.get('nets'):
            net = whois_info['nets'][0]
            net_info = {
                'name': net.get('name'),
                'range': net.get('range'),
                'cidr': net.get('cidr'),
                'country': net.get('country'),
                'state': net.get('state'),
                'city': net.get('city'),
                'postal_code': net.get('postal_code'),
                'address': net.get('address'),
                'org': net.get('org'),
                'emails': net.get('emails'),
                'created': net.get('created'),
                'updated': net.get('updated')
            }

        result = {
            'ip': ip,
            'asn': whois_info.get('asn'),
            'asn_description': whois_info.get('asn_description'),
            'asn_country_code': whois_info.get('asn_country_code'),
            'asn_registry': whois_info.get('asn_registry'),
            'asn_cidr': whois_info.get('asn_cidr'),
            'asn_date': whois_info.get('asn_date'),
            'reverse_dns': reverse_dns,
            'city': city,
            'region': region,
            'abuse_score': abuse_score,
            'virustotal': vt_data,
            'threat_label': threat_label,
            'threat_color': threat_color,
            'ip_type': utils.classify_ip(ip),
            'ipqualityscore': ipqs_data,
            'vpn_proxy_label': vpn_proxy_label,
            'vpn_proxy_color': vpn_proxy_color,
            'fraud_label': fraud_label,
            'fraud_color': fraud_color,
            'whois': {
                'net': net_info
            },
            'open_ports': [],
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'from_cache': False
        }
        
        # Calculer le score de risque
        result['risk_score'] = utils.calculate_risk_score(result)
        risk_label, risk_severity = utils.get_risk_label(result['risk_score'])
        result['risk_label'] = risk_label
        result['risk_severity'] = risk_severity
        
        # Mettre en cache
        db.cache_ip(ip, result)
        
        return result
    except Exception as e:
        return {
            'ip': ip,
            'error': str(e)
        }

def analyze_domain(domain, api_keys):
    """Analyse complète d'un domaine"""
    # Vérifier le cache
    cached = db.get_cached_domain(domain)
    if cached:
        cached['from_cache'] = True
        return cached
    
    try:
        # Analyse DNS
        dns_data = dns_analyzer.analyze_domain(domain)
        
        # VirusTotal
        vt_data = vt_api.check_domain(domain, api_key=api_keys.get('virustotal'))
        threat_label, threat_color = vt_api.get_threat_label(vt_data)
        
        result = {
            'domain': domain,
            'dns_records': dns_data['dns_records'],
            'ip_addresses': dns_data['ip_addresses'],
            'ssl_info': dns_data['ssl_info'],
            'virustotal': vt_data,
            'threat_label': threat_label,
            'threat_color': threat_color,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'from_cache': False
        }
        
        # Calculer le score de risque
        result['risk_score'] = utils.calculate_risk_score(result)
        risk_label, risk_severity = utils.get_risk_label(result['risk_score'])
        result['risk_label'] = risk_label
        result['risk_severity'] = risk_severity
        
        # Mettre en cache
        db.cache_domain(domain, result)
        
        return result
    except Exception as e:
        return {
            'domain': domain,
            'error': str(e)
        }

def process_query(query, api_keys):
    """Traite une requête (IP ou domaine)"""
    query = query.strip()
    
    # Déterminer si c'est une IP ou un domaine
    if utils.is_valid_ip(query):
        return get_whois_info(query, api_keys), 'ip'
    elif dns_analyzer.is_domain(query):
        domain = dns_analyzer._clean_domain(query)
        return analyze_domain(domain, api_keys), 'domain'
    else:
        return {'error': f'Format invalide: {query}'}, 'unknown'

# --- Routes d'authentification ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.create(form.username.data, form.email.data, form.password.data)
        if user:
            login_user(user)
            flash('Compte créé avec succès !', 'success')
            return redirect(url_for('index'))
        else:
            flash('Erreur lors de la création du compte. Email ou nom d\'utilisateur déjà utilisé.', 'danger')
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login ou mot de passe incorrect.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        if form.regenerate_api_key.data:
            current_user.regenerate_api_key()
            flash('Clé API régénérée avec succès !', 'success')
            return redirect(url_for('profile'))

        abuseipdb_key = form.abuseipdb_api_key.data or None
        virustotal_key = form.virustotal_api_key.data or None
        shodan_key = form.shodan_api_key.data or None
        ipqualityscore_key = form.ipqualityscore_api_key.data or None

        current_user.update_api_keys(abuseipdb_key, virustotal_key, shodan_key, ipqualityscore_key)
        flash('Clés API mises à jour avec succès !', 'success')
        return redirect(url_for('profile'))
    if request.method == 'GET':
        form.abuseipdb_api_key.data = current_user.abuseipdb_api_key
        form.virustotal_api_key.data = current_user.virustotal_api_key
        form.shodan_api_key.data = current_user.shodan_api_key
        form.ipqualityscore_api_key.data = current_user.ipqualityscore_api_key
    return render_template('profile.html', title='Profile', form=form)

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        query_list = []
        
        # Traitement de la zone de texte
        query_str = request.form.get('ip_list')
        if query_str:
            # Extraire automatiquement les IPs et domaines
            ips = utils.extract_ips_from_text(query_str)
            domains = utils.extract_domains_from_text(query_str)
            
            # Ajouter aussi les lignes brutes pour les domaines non détectés
            raw_lines = [line.strip() for line in query_str.splitlines() if line.strip()]
            query_list.extend(raw_lines)
            query_list.extend(ips)
            query_list.extend(domains)

        # Traitement du fichier importé
        file = request.files.get('file')
        if file and file.filename != '':
            content = file.read().decode('utf-8')
            ips = utils.extract_ips_from_text(content)
            domains = utils.extract_domains_from_text(content)
            query_list.extend(ips)
            query_list.extend(domains)
        
        # Éliminer les doublons
        query_list = sorted(list(set(query_list)))
        
        # Limiter le nombre de requêtes
        if len(query_list) > config.MAX_IPS_PER_BATCH:
            query_list = query_list[:config.MAX_IPS_PER_BATCH]

        api_keys = {
            'abuseipdb': current_user.abuseipdb_api_key,
            'virustotal': current_user.virustotal_api_key,
            'shodan': current_user.shodan_api_key,
            'ipqualityscore': current_user.ipqualityscore_api_key
        }
        results = []
        if query_list:
            with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENT_REQUESTS) as executor:
                results = list(executor.map(lambda q: process_query(q, api_keys), query_list))
            
            # Sauvegarder dans l'historique
            db.add_search_history(
                query=', '.join(query_list[:5]) + ('...' if len(query_list) > 5 else ''),
                query_type='mixed',
                results_count=len(results)
            )
        
        return render_template('index.html', results=results)
    
    # GET - afficher l'historique
    history = db.get_search_history(limit=10)
    return render_template('index.html', results=None, history=history)

@app.route('/export/csv', methods=['POST'])
@login_required
def export_csv():
    results_str = request.form.get('results')
    results = eval(results_str)

    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['Type', 'Target', 'ASN', 'Organization', 'Country', 'City', 'Abuse Score', 'VT Malicious', 'Risk Score', 'Risk Level'])
    
    for result, query_type in results:
        if not result.get('error'):
            if query_type == 'ip':
                vt_mal = result.get('virustotal', {}).get('malicious', 'N/A')
                writer.writerow([
                    'IP',
                    result.get('ip'),
                    result.get('asn'),
                    result.get('asn_description'),
                    result.get('asn_country_code'),
                    result.get('city'),
                    result.get('abuse_score'),
                    vt_mal,
                    result.get('risk_score', 0),
                    result.get('risk_label', 'Unknown')
                ])
            elif query_type == 'domain':
                vt_mal = result.get('virustotal', {}).get('malicious', 'N/A')
                ips = ', '.join(result.get('ip_addresses', []))
                writer.writerow([
                    'Domain',
                    result.get('domain'),
                    'N/A',
                    'N/A',
                    'N/A',
                    ips,
                    'N/A',
                    vt_mal,
                    result.get('risk_score', 0),
                    result.get('risk_label', 'Unknown')
                ])

    output.seek(0)
    
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=whois_results.csv"})

@app.route('/export/json', methods=['POST'])
@login_required
def export_json():
    results_str = request.form.get('results')
    results = eval(results_str)
    
    # Créer un export JSON propre
    export_data = {
        'export_date': datetime.now().isoformat(),
        'total_results': len(results),
        'results': [result for result, _ in results]
    }
    
    return Response(
        json.dumps(export_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition":"attachment;filename=whois_results.json"}
    )

@app.route('/api/search', methods=['POST'])
def api_search():
    """API endpoint pour recherche programmatique"""
    data = request.get_json()
    query = data.get('query')
    
    if not query:
        return jsonify({'error': 'Query parameter required'}), 400
    
    result, query_type = process_query(
        query,
        {'abuseipdb': None, 'virustotal': None, 'shodan': None, 'ipqualityscore': None}
    )
    return jsonify({
        'result': result,
        'type': query_type
    })

@app.route('/history')
def history():
    """Affiche l'historique des recherches"""
    history = db.get_search_history(limit=50)
    return render_template('history.html', history=history)

if __name__ == '__main__':
    # Nettoyer le cache au démarrage
    deleted = db.cleanup_old_cache()
    if deleted > 0:
        print(f"Nettoyé {deleted} entrées de cache expirées")
    
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
