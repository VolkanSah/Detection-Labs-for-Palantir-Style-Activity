#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# NOTICE: EDUCATIONAL AND DEFENSIVE USE ONLY
# -----------------------------------------------------------------------------
# This script is a SIMULATION and research tool designed to identify
# patterns (IOCs) commonly associated with advanced surveillance platforms
# like Palantir. It is NOT intended for offensive operations or unauthorized
# monitoring. Unauthorized access or testing of external networks is strictly
# illegal. Use only on networks you own or are explicitly authorized to protect.
# -----------------------------------------------------------------------------
# some fixes with help of claude on 11.08.2026
#!/usr/bin/env python3
# Note for Devs. sorry no full concept, cause dont want to build a weapon! 
# See *-workflow.md for more stuff!
"""
Palantir Threat Detection Tool
Checks for beacons and white-label surveillance indicators
Based on the SIEM lab documentation
"""

import os
import requests
import socket
import ssl
import hashlib
import time
import json
import subprocess
import psutil
import re
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse


class PalantirDetector:
    def __init__(self):
        self.alerts = []
        self.connection_log = defaultdict(list)

        # Known white-label indicators from the doc
        self.indicators = {
            'user_agents': [
                'HessPol/2.0', 'Palantir-Custom-Agent', 'TritonX/3.1',
                'BDA-Analytik', 'VS-Datarium', 'ATLAS-Nexus'
            ],
            'ja3_hashes': [
                'a387c3a7a4d', '5d4a', 't13d'  # Partial hashes from doc
            ],
            'suspicious_paths': [
                '/polis/v1/heartbeat', '/atlas/beacon', '/triton/sync',
                '/morpheus/data', '/berlin7/upload'
            ],
            'suspicious_processes': [
                'polis-agent.exe', 'bda-analytics.exe', 'vs-dataharvester.exe',
                'lyra_service.exe', 'morpheus_loader.dll', 'vs-dataharvester.exe'
            ],
            'suspicious_domains': [
                'morph-tech.uk', 'secure-gchq', 'minerva-*.internal-gov.uk',
                'gotham.palantir.com'
            ],
            'chunk_sizes': [131072, 262144],  # Government data chunking patterns
            'suspicious_ports': [8443, 58444, 4789],
            'registry_keys': [
                'HKLM\\SOFTWARE\\Berlin7\\Config',
                'HKLM\\SOFTWARE\\POLiS\\Agent'
            ]
        }

    def log_alert(self, severity, category, message, details=None):
        """Log detection alerts"""
        alert = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',  # UTC with Z suffix
            'severity': severity,
            'category': category,
            'message': message,
            'details': details or {}
        }
        self.alerts.append(alert)
        print(f"[{severity}] {category}: {message}")

    def collect_network_data(self, target_hosts=None, duration_minutes=1, interval_seconds=15):
        """Collect network data for beacon analysis.

        BUGFIX (was: hardcoded 60s sleep regardless of interval, 1 cycle == 1 minute):
        cycles are now derived from duration_minutes/interval_seconds, so
        check_beaconing_patterns() can actually be exercised - see run_full_scan().
        """
        if not target_hosts:
            # BUGFIX: no longer defaults to real third-party infra
            # (was: 'gotham.palantir.com', a real Palantir product domain).
            target_hosts = ['example.com']

        total_cycles = max(1, int((duration_minutes * 60) / interval_seconds))
        print(f"Collecting network data: {total_cycles} cycle(s) over {duration_minutes} "
              f"minute(s), every {interval_seconds}s...")

        for cycle in range(total_cycles):
            for host in target_hosts:
                try:
                    start_time = time.time()
                    response = requests.head(f"https://{host}", timeout=5)
                    response_time = time.time() - start_time

                    self.connection_log[host].append({
                        'timestamp': datetime.utcnow(),
                        'response_time': response_time,
                        'status': response.status_code if hasattr(response, 'status_code') else 'timeout'
                    })

                    # Check for suspicious user agents (case-insensitive)
                    if hasattr(response, 'request') and response.request.headers:
                        ua = response.request.headers.get('User-Agent', '')
                        for suspicious_ua in self.indicators['user_agents']:
                            if suspicious_ua.lower() in ua.lower():
                                self.log_alert('HIGH', 'SUSPICIOUS_UA', f'Suspicious User-Agent: {ua}',
                                               {'host': host, 'user_agent': ua})

                except Exception as e:
                    # Still log failed attempts for pattern analysis
                    self.connection_log[host].append({
                        'timestamp': datetime.utcnow(),
                        'response_time': None,
                        'status': 'failed',
                        'error': str(e)[:100]
                    })

            if cycle < total_cycles - 1:
                time.sleep(interval_seconds)

    def check_beaconing_patterns(self, threshold=15, window_minutes=5):
        """Check for beaconing patterns in connection logs"""
        now = datetime.utcnow()
        print(f"Checking beaconing patterns (>{threshold} connections in {window_minutes} minutes)...")

        for host, logs in self.connection_log.items():
            recent_logs = [entry for entry in logs if now - entry['timestamp'] < timedelta(minutes=window_minutes)]

            if len(recent_logs) > threshold:
                self.log_alert('HIGH', 'BEACON',
                               f'Beaconing detected: {len(recent_logs)} connections in last {window_minutes} minutes',
                               {'host': host, 'connection_count': len(recent_logs),
                                'window_minutes': window_minutes, 'threshold': threshold})

                # Additional analysis for government-style patterns
                intervals = []
                if len(recent_logs) > 1:
                    sorted_logs = sorted(recent_logs, key=lambda x: x['timestamp'])
                    for i in range(1, len(sorted_logs)):
                        interval = (sorted_logs[i]['timestamp'] - sorted_logs[i - 1]['timestamp']).total_seconds()
                        intervals.append(interval)

                    avg_interval = sum(intervals) / len(intervals) if intervals else 0
                    if 280 <= avg_interval <= 320:  # 300s ± 20s tolerance
                        self.log_alert('CRITICAL', 'GOV_BEACON',
                                       f'Government-style 5-minute beaconing pattern detected',
                                       {'host': host, 'avg_interval': avg_interval,
                                        'total_connections': len(recent_logs)})

    def check_tls_fingerprints(self, host, port=443):
        """Check TLS certificates (simplified - real JA3 needs specialized libs)"""
        try:
            print(f"Checking TLS certificate for {host}:{port}")
            print("Note: This is cert fingerprinting, not true JA3. Use ja3er lib for real JA3.")

            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_hash = hashlib.sha256(cert).hexdigest()[:12]

                    for known_hash in self.indicators['ja3_hashes']:
                        if known_hash in cert_hash:
                            self.log_alert('CRITICAL', 'TLS_FINGERPRINT',
                                           'Suspicious TLS certificate fingerprint detected',
                                           {'host': host, 'cert_fingerprint': cert_hash})

                    cert_info = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert_info['issuer'])
                    if any(gov_ca in issuer.get('organizationName', '')
                           for gov_ca in ['BKA-INTERNAL-CA', 'GCHQ-ROOT', 'DGSE-PKI']):
                        self.log_alert('HIGH', 'GOV_CERTIFICATE',
                                       'Government certificate authority detected',
                                       {'issuer': issuer, 'host': host})

        except Exception as e:
            print(f"TLS check failed for {host}: {str(e)[:50]}...")

    def check_suspicious_processes(self):
        """Scan for suspicious processes"""
        print("Scanning for suspicious processes...")

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower() if proc_info['name'] else ''
                exe_path = proc_info['exe'].lower() if proc_info['exe'] else ''
                cmdline = ' '.join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ''

                for suspicious_proc in self.indicators['suspicious_processes']:
                    if suspicious_proc.lower() in proc_name or suspicious_proc.lower() in exe_path:
                        self.log_alert('CRITICAL', 'SUSPICIOUS_PROCESS',
                                       f'Known surveillance process detected: {proc_name}',
                                       {'pid': proc_info['pid'], 'exe': exe_path, 'cmdline': cmdline})

                stealth_indicators = ['--stealth', '--no-log', '--hidden', '--service-mode']
                for indicator in stealth_indicators:
                    if indicator in cmdline:
                        self.log_alert('HIGH', 'STEALTH_PROCESS',
                                       f'Process with stealth indicators: {proc_name}',
                                       {'indicator': indicator, 'cmdline': cmdline})

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def check_network_connections(self):
        """Check active network connections for suspicious patterns"""
        print("Analyzing network connections...")

        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr:
                remote_ip, remote_port = conn.raddr

                if remote_port in self.indicators['suspicious_ports']:
                    self.log_alert('MEDIUM', 'SUSPICIOUS_PORT',
                                   f'Connection to suspicious port {remote_port}',
                                   {'remote_ip': remote_ip, 'remote_port': remote_port,
                                    'local_port': conn.laddr.port if conn.laddr else None})

                if remote_ip.startswith('52.') or remote_ip.startswith('54.'):
                    self.log_alert('LOW', 'AWS_CONNECTION',
                                   f'Connection to AWS IP range: {remote_ip}:{remote_port}')

    def check_dns_patterns(self):
        """Check for suspicious DNS patterns.

        BUGFIX (was: only ever checked the hardcoded 'morph-tech.uk' string;
        the rest of self.indicators['suspicious_domains'] was dead config).
        Now walks the full list. Wildcard entries (e.g. 'minerva-*.internal-gov.uk')
        get '*' substituted with a lookup-able label since nslookup can't glob.

        Note: this resolves the domain itself, which only tells you the domain
        exists/resolves - it does NOT tell you whether anything on your network
        queried it. For real tunneling detection you need passive DNS log
        analysis (queries YOUR resolver actually served), not active lookups.
        """
        print("Checking DNS patterns...")

        for domain_pattern in self.indicators['suspicious_domains']:
            query_domain = domain_pattern.replace('*', 'probe')
            try:
                result = subprocess.run(['nslookup', query_domain],
                                        capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    self.log_alert('HIGH', 'DNS_TUNNELING',
                                   f'Domain pattern resolves: {domain_pattern}',
                                   {'domain': domain_pattern, 'result': result.stdout[:200]})

            except Exception as e:
                print(f"  DNS check failed for {domain_pattern}: {str(e)[:50]}...")

    def check_registry_indicators(self):
        """Check known-suspicious registry keys.

        BUGFIX: self.indicators['registry_keys'] was defined but never
        consumed anywhere in the original script - dead config. Windows-only
        by nature (winreg); on other platforms this now says so explicitly
        instead of silently doing nothing with no explanation.
        """
        print("Checking registry indicators...")

        if os.name != 'nt':
            print("  Skipped: registry check only applies on Windows.")
            return

        import winreg  # only available on Windows, hence the local import

        for key_path in self.indicators['registry_keys']:
            hive_str, _, subkey = key_path.partition('\\')
            hive = getattr(winreg, hive_str, None)
            if hive is None:
                print(f"  Unknown hive in '{key_path}', skipping.")
                continue
            try:
                winreg.OpenKey(hive, subkey)
                self.log_alert('CRITICAL', 'REGISTRY_INDICATOR',
                               f'Known surveillance registry key present: {key_path}',
                               {'key': key_path})
            except FileNotFoundError:
                pass  # key not present - no finding, no fabricated alert
            except PermissionError:
                print(f"  Access denied reading {key_path} (try an elevated shell).")

    def check_data_chunking_patterns(self, observed_chunks=None):
        """Analyze network logs for suspicious data chunking"""
        """
        BUGFIX: this used to hardcode a fake finding for size==131072 on every
        single run, regardless of any actual traffic - a stub disguised as a
        detection. It now only alerts on real observed_chunks data (e.g. from
        a pcap/scapy capture upstream); with nothing supplied, it explicitly
        says so instead of fabricating a result.

        observed_chunks: iterable of (size_bytes, destination) tuples.
        """
        print("Checking data chunking patterns...")

        if not observed_chunks:
            print("  No chunk-size data supplied (needs packet capture, e.g. via scapy) - skipping.")
            return []

        hits = []
        for size, destination in observed_chunks:
            if size in self.indicators['chunk_sizes']:
                self.log_alert('MEDIUM', 'DATA_CHUNKING',
                               f'Suspicious data chunk size observed: {size} bytes',
                               {'chunk_size': size, 'destination': destination})
                hits.append((size, destination))
        return hits

    def generate_sigma_rules(self):
        """Generate a Sigma rule from this run's findings.

        BUGFIX: the original filtered on category == 'BEACON' looking for a
        'user_agent' field - but UA alerts are logged under 'SUSPICIOUS_UA',
        and BEACON alerts never carry a user_agent field at all (only host/
        connection_count/window_minutes/threshold). So this returned an
        essentially always-empty selection = broken rule, no matter how many
        UA hits there were.

        Now pulls from every indicator category that actually carries a
        field-level value, and builds one named selection per type, OR'd
        together (each alert type is independently meaningful - requiring
        all of them to match simultaneously would defeat the point).
        """
        if not self.alerts:
            return None

        selections = {}

        user_agents = sorted({
            a['details'].get('user_agent') for a in self.alerts
            if a['category'] == 'SUSPICIOUS_UA' and a['details'].get('user_agent')
        })
        if user_agents:
            selections['sel_ua'] = {'http.user_agent': user_agents}

        ports = sorted({
            a['details'].get('remote_port') for a in self.alerts
            if a['category'] == 'SUSPICIOUS_PORT' and a['details'].get('remote_port')
        })
        if ports:
            selections['sel_port'] = {'destination.port': ports}

        domains = sorted({
            a['details'].get('domain') for a in self.alerts
            if a['category'] == 'DNS_TUNNELING' and a['details'].get('domain')
        })
        if domains:
            selections['sel_dns'] = {'dns.query|contains': domains}

        processes = sorted({
            a['details'].get('exe') for a in self.alerts
            if a['category'] in ('SUSPICIOUS_PROCESS', 'STEALTH_PROCESS') and a['details'].get('exe')
        })
        if processes:
            selections['sel_process'] = {'Image|endswith': processes}

        fingerprints = sorted({
            a['details'].get('cert_fingerprint') for a in self.alerts
            if a['category'] == 'TLS_FINGERPRINT' and a['details'].get('cert_fingerprint')
        })
        if fingerprints:
            selections['sel_tls'] = {'tls.cert_hash': fingerprints}

        if not selections:
            # We had alerts (e.g. BEACON/GOV_BEACON/REGISTRY) but none carry a
            # field-level indicator Sigma can match on directly - say so
            # instead of returning a rule with an empty/always-true condition.
            return {
                'title': 'Palantir/Surveillance Detection - Auto Generated',
                'description': (f'{len(self.alerts)} alert(s) this run, but none carry a '
                                 'field-level indicator (only behavioral alerts like beaconing). '
                                 'Build this rule by hand from self.alerts.'),
                'logsource': {'category': 'network'},
                'detection': None,
                'level': 'informational',
                'tags': ['palantir', 'surveillance', 'auto-generated', 'needs-manual-review']
            }

        detection = dict(selections)
        detection['condition'] = ' or '.join(selections.keys())

        return {
            'title': 'Palantir/Surveillance Detection - Auto Generated',
            'description': f'Generated from {len(self.alerts)} alert(s) across {len(selections)} indicator type(s)',
            'logsource': {'category': 'network'},
            'detection': detection,
            'level': 'high',
            'tags': ['palantir', 'surveillance', 'auto-generated']
        }

    def run_full_scan(self):
        """Run complete detection suite"""
        print("Starting Palantir Detection Suite")
        print("=" * 50)

        start_time = time.time()

        # BUGFIX: was duration_minutes=1 -> collect_network_data made exactly
        # ONE pass per host, so check_beaconing_patterns(threshold=15,
        # window_minutes=5) could never see enough samples to fire. This now
        # gathers ~20 samples/host inside the 5-minute window, so the check
        # actually gets exercised. This makes a full scan take ~5 minutes;
        # pass duration_minutes=1 manually for a fast smoke test instead
        # (beaconing check just won't have data to work with in that case).
        self.collect_network_data(duration_minutes=5, interval_seconds=15)
        self.check_beaconing_patterns()
        self.check_suspicious_processes()
        self.check_network_connections()
        self.check_tls_fingerprints('example.com')
        self.check_dns_patterns()
        self.check_registry_indicators()
        self.check_data_chunking_patterns()  # no observed_chunks -> honestly skips, no fake finding

        scan_time = time.time() - start_time

        print("\n" + "=" * 50)
        print(f"Scan completed in {scan_time:.2f} seconds")
        print(f"Total alerts: {len(self.alerts)}")

        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert['severity']] += 1

        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")

        sigma_rule = self.generate_sigma_rules()
        if sigma_rule:
            print("\nAuto-generated Sigma rule:")
            print(json.dumps(sigma_rule, indent=2))

        return self.alerts

    def export_results(self, filename=None):
        """Export results to JSON"""
        if not filename:
            filename = f"palantir_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'total_alerts': len(self.alerts),
            'alerts': self.alerts,
            'sigma_rule': self.generate_sigma_rules()
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"Results exported to {filename}")
        return filename


def main():
    detector = PalantirDetector()

    print("Palantir/Surveillance Detection Tool")
    print("Based on SIEM Lab Documentation")
    print("-" * 40)

    alerts = detector.run_full_scan()
    detector.export_results()

    if alerts:
        print(f"\nATTENTION: {len(alerts)} suspicious indicators detected!")
        print("Review the exported JSON for details.")
    else:
        print("\nNo suspicious indicators detected in this scan.")

    return len(alerts)


if __name__ == "__main__":
    try:
        exit_code = main()
        exit(exit_code)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\nFatal error: {e}")
        exit(2)
