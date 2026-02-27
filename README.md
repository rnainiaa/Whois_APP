# WHOIS & Threat Intelligence Dashboard

## Objectif
Ce projet fournit un tableau de bord SOC pour analyser des IP et des domaines, agréger des sources de threat intelligence et produire une vue exploitable des risques (score, réputation, VPN/Proxy, ASN, WHOIS, etc.).

## Fonctionnement
- Interface web protégée par authentification.
- Analyse d’IP et de domaines via API externes et modules internes.
- Mise en cache des résultats dans SQLite pour accélérer les recherches.
- Historique des recherches et exports (CSV/JSON).
- Gestion par utilisateur des clés API (ABUSEIPDB, VIRUSTOTAL, SHODAN, IPQUALITYSCORE) depuis le profil.

## Flux principal
1. Connexion ou inscription.
2. Saisie d’IP/domaines (texte ou fichier).
3. Analyse automatique et affichage des résultats.
4. Consultation des détails enrichis via le bouton More.
5. Export des résultats si besoin.

## Composants clés
- Serveur web Flask.
- Authentification avec sessions et profil utilisateur.
- Collecte de données WHOIS/DNS/GeoIP et enrichissement via API.
- Cache et historique en base SQLite.

## Lancer l’application
1. Installer les dépendances :
   ```bash
   pip install -r requirements.txt
   ```
2. Démarrer le serveur :
   ```bash
   python app.py
   ```
