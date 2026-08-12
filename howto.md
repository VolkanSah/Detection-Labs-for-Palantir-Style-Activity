#### will translate it later in english sorry.. 

# How-To: Palantir-Style Detection Lab in Betrieb nehmen

Praxis-Guide für `Detection-Labs-for-Palantir-Style-Activity`. Kein Grundlagenkurs , direkt zur Sache
!

---

## 1. Setup

```bash
git clone <repo> palantir-lab && cd palantir-lab
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install sigmatools   # separat, ist in requirements.txt auskommentiert
```

`requirements.txt` zieht `requests`, `psutil`, optional `dnspython`, `cryptography`, `scapy`. Für echtes JA3-Fingerprinting brauchst du zusätzlich `pip install ja3er` — die im Repo enthaltene TLS-Prüfung ist nur Cert-Hashing, kein echtes JA3.

---

## 2. Erstlauf: `BasicPalantirDetector.py`

```bash
python3 BasicPalantirDetector.py
```

Macht einen einmaligen Scan-Durchlauf:

| Check | Methode | Output |
|---|---|---|
| Beaconing | `collect_network_data()` → `check_beaconing_patterns()` | Alarm bei >15 Verbindungen/5min, Extra-Flag bei ~300s-Intervall (Government-Pattern) |
| Prozesse | `check_suspicious_processes()` via `psutil` | Matched gegen `indicators['suspicious_processes']` + Stealth-Flags (`--no-log`, `--hidden` etc.) |
| Verbindungen | `check_network_connections()` | Suspicious Ports (8443, 58444, 4789), AWS-Ranges (52.*, 54.*) |
| TLS | `check_tls_fingerprints(host)` | Cert-Hash-Vergleich, Issuer-Check gegen fiktive Gov-CAs |
| DNS | `check_dns_patterns()` | nslookup gegen bekannte Tunneling-Domain |
| Chunking | `check_data_chunking_patterns()` | 131072/262144-Byte-Muster |

Ergebnis landet als JSON (`palantir_scan_<timestamp>.json`) inkl. automatisch generierter Sigma-Rule aus den Alerts. Das Script ist Simulation/Lern-Tool — die Indikatoren (`HessPol/2.0`, `morph-tech.uk` etc.) sind fiktive Platzhalter, keine echten IOCs.

**Wichtig:** `check_dns_patterns()` und `collect_network_data()` machen aktive Requests/Lookups gegen externe Hosts (`example.com`, `gotham.palantir.com`, `morph-tech.uk`). Nur auf Systemen laufen lassen, für die du Berechtigung hast — steht auch so im Repo (ESOL-Lizenz, GPLv3 + Ethical-Use-Zusatz).

---

## 3. Sigma Rules → SIEM

5 fertige Rules im README (`rules/*.yml`):

1. `palantir_beaconing.yml` – >15 Verbindungen zu AWS US-East/443 in 5min
2. `suspicious_gov_process.yml` – White-Label-Binaries mit Stealth-Args aus Temp/Public
3. `hessen_polis.yml` – JA3 + User-Agent + Pfad-Kombo, Beispiel für Agency-spezifische Rule
4. Data-Exfil-Pattern (Chunk-Size-basiert)
5. `morpheus_dns.yml` – Regex auf `*.morph-tech.uk`, Query-Length >60

Convert:

```bash
sigma convert -t es-rule rules/palantir_beaconing.yml     # Elastic
sigma convert -t splunk rules/palantir_beaconing.yml       # Splunk
```

SIEM-Wahl fürs Lab: **Wazuh**, wenn du SIEM+XDR in einem willst und schnell testen. **Elastic**, wenn du eh schon in dem Ökosystem bist. **Splunk Free** nur wegen der 500MB/Tag-Deckelung eher zum Reinschnuppern.

---

## 4. Eigene Rules generieren

```bash
python3 tools/generate_sigma.py
# Prompt: Agency name, Cover name, Unique signature (JA3/path/etc)
```

Baut dir eine Sigma-Rule nach dem Muster der 10 White-Label-Beispiele aus dem README (POLiS, TRITON-X, BERLIN-7 …). Reine Templating-Logik, kein Lookup gegen echte Daten — Signature musst du selbst liefern.

---

## 5. Upgrade: Continuous Monitoring (aus `examples_worklows..md`)

Ersetzt den One-Shot-Scan durch eine Loop, die alle 30s echte System-Connections prüft statt eigene Test-Requests zu feuern:

- `check_system_connections()` ersetzt `collect_network_data()` — liest `psutil.net_connections()` direkt
- `AllowlistManager` (JSON-basiert) filtert bekannte Prozesse/IPs raus, um False Positives zu drücken
- `cleanup_old_logs(retention_minutes=10)` gegen Memory-Bloat im Dauerbetrieb
- Eigener Connection-Log (`real_connection_log`) getrennt vom Detector-eigenen Traffic

Das ist laut Repo-Autor der "nicht-simulierte" Teil — sprich der Baustein, der tatsächlich production-tauglich gedacht ist. Volltext/Code steht in `examples_worklows..md`.

---

## 6. TLS-Fingerprinting (JA3/JA4)

Kurzfassung, Details in `ja3_ja4_guide.md`:

- **JA3**: Hash aus TLS-ClientHello-Feldern (Version, Cipher Suites, Extensions, Elliptic Curves, EC Point Formats)
- **JA4**: Nachfolger, fixt JA3-Schwächen (u.a. TLS 1.3-Handling), lesbareres Format
- Capture-Tools: Suricata (`ja3`-Keyword), Zeek (`JA3`-Script), oder Python via `ja3er`
- Das im Detector eingebaute `check_tls_fingerprints()` ist **kein** echtes JA3 — nur SHA256 über das Zertifikat. Für echtes JA3 brauchst du Paketdaten (ClientHello), nicht das Cert.

---

## 7. Ablauf komplett

```
Setup → BasicPalantirDetector.py (Baseline-Scan)
      → Alerts sichten (JSON-Export)
      → Sigma-Rule daraus generieren/anpassen
      → sigma convert → ins SIEM importieren
      → Continuous-Monitoring-Variante deployen
      → Threat-Hunting-Playbook (README Punkt 11) für manuelle Hunts nutzen
```

---

