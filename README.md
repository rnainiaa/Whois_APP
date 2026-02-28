# WHOIS & Threat Intelligence Dashboard

## Objective
This project provides a SOC dashboard to analyze IPs and domains, aggregate threat intelligence sources, and deliver an actionable view of risk (score, reputation, VPN/Proxy, ASN, WHOIS, etc.).

## How It Works
- Authenticated web interface.
- IP and domain analysis via external APIs and internal modules.
- Result caching in SQLite to speed up lookups.
- Search history and exports (CSV/JSON).
- Per-user API key management (ABUSEIPDB, VIRUSTOTAL, SHODAN, IPQUALITYSCORE) from the profile.

## Main Flow
1. Sign in or register.
2. Enter IPs/domains (text or file).
3. Automatic analysis and results display.
4. Review enriched details via the More button.
5. Export results if needed.

## Key Components
- Flask web server.
- Session-based authentication and user profile.
- WHOIS/DNS/GeoIP data collection and API enrichment.
- SQLite cache and history.

## Run the Application
1️⃣ Install virtual environment support (if not already installed):
   ```bash
   pip install virtualenv
   ```
2️⃣ Create a virtual environment:
   ```bash
   virtualenv venv
   ```
3️⃣ Activate the virtual environment:
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
4️⃣ Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5️⃣ Start the server:
   ```bash
   python app.py
   ```
