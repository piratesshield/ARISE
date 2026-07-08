#!/usr/bin/env python3
"""
ARISE Dashboard v3.0 - "Summon Every Hidden Exposure."
Complete rewrite with proper data ingestion, caching, and state management
Fixes: Target switching, port data, multi-scan isolation, real-time updates
"""

import os
import json
import glob
import re
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from functools import lru_cache
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import threading
import time
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
CORS(app)

# ===========================================================================
# CONFIGURATION
# ===========================================================================

BASE_SCAN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scans')
CACHE_TIMEOUT = 5  # seconds - refresh cache every 5 seconds
CURRENT_TARGET = {}  # Track per-session target
_SCAN_CACHE = {}
_SCAN_INDEX_CACHE = {'timestamp': 0, 'scans': []}
PORT_MAPPINGS = {
    22: 'SSH', 21: 'FTP', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 587: 'SMTP',
    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5984: 'CouchDB', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9200: 'Elasticsearch', 27017: 'MongoDB'
}
SENSITIVE_PORTS = {22, 21, 23, 25, 445, 1433, 3306, 3389, 5432, 5984, 6379, 9200, 27017}
SEVERITY_WEIGHTS = {'critical': 40, 'high': 20, 'medium': 8, 'low': 2, 'info': 0}


def setup_logging():
    """Configure a central rotating log for the dashboard."""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger('dashboard')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')

        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'dashboard.log'),
            maxBytes=1_000_000,
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger


logger = setup_logging()


def load_json_file(filepath):
    """Load a JSON file safely and log any parse failures."""
    if not filepath or not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r') as handle:
            return json.load(handle)
    except Exception as exc:
        logger.error("Failed to load JSON %s: %s", filepath, exc)
        return {}


def parse_scan_time(value):
    """Parse pipeline timestamps, falling back cleanly when older data is incomplete."""
    if not value:
        return datetime.min
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except Exception:
        return datetime.min


def scan_time_key(value, fallback=0):
    try:
        parsed = parse_scan_time(value)
        return parsed.timestamp() if parsed != datetime.min else fallback
    except Exception:
        return fallback

# ===========================================================================
# CORE DATA PIPELINE
# ===========================================================================

class ScanDataPipeline:
    """Manages data ingestion from easm-pipeline outputs"""
    
    def __init__(self, scan_dir):
        self.scan_dir = scan_dir
        self.manifest_file = os.path.join(scan_dir, 'manifest.json')
        self._cache = {}
        self._cache_time = {}
    
    def load_manifest(self):
        """Load and parse manifest.json"""
        if not os.path.exists(self.manifest_file):
            logger.info("Manifest missing: %s", self.manifest_file)
            return {'pipeline_info': {}, 'statistics': {}, 'hosts': {}}
        
        try:
            with open(self.manifest_file, 'r') as f:
                return json.load(f)
        except Exception as exc:
            logger.error("Failed to parse manifest %s: %s", self.manifest_file, exc)
            return {'pipeline_info': {}, 'statistics': {}, 'hosts': {}}
    
    def load_port_data(self):
        """Extract port data from naabu output"""
        sources = [
            os.path.join(self.scan_dir, '04_http_discovery/all_ports_full.json'),
            os.path.join(self.scan_dir, '04_http_discovery/all_ports_list.txt'),
            os.path.join(self.scan_dir, '14_port_scan/all_ports.jsonl'),
            os.path.join(self.scan_dir, '04_http_discovery/all_ports.json'),
        ]
        ports_data = {}

        for source in sources:
            if not os.path.exists(source):
                continue

            try:
                with open(source, 'r', errors='ignore') as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue

                        host = None
                        port = None

                        if source.endswith('.txt'):
                            parts = line.split(':')
                            if len(parts) == 2 and parts[1].isdigit():
                                host, port = parts[0], int(parts[1])
                        else:
                            try:
                                entry = json.loads(line)
                            except Exception:
                                continue
                            host = entry.get('host') or entry.get('ip')
                            port = entry.get('port')

                        if host and port:
                            ports_data.setdefault(host, [])
                            if port not in ports_data[host]:
                                ports_data[host].append(int(port))
            except Exception as exc:
                logger.error("Failed to read port source %s: %s", source, exc)

        for host in ports_data:
            ports_data[host] = sorted(set(ports_data[host]))

        return ports_data

    def get_port_scan_status(self):
        """Detect whether the port scan succeeded, crashed, or is missing."""
        manifest = self.load_manifest()
        status_from_manifest = manifest.get('statistics', {}).get('port_scan_status')
        if status_from_manifest:
            return status_from_manifest

        jsonl = os.path.join(self.scan_dir, '14_port_scan/all_ports.jsonl')
        stderr = os.path.join(self.scan_dir, '14_port_scan/naabu.stderr')
        scan_dir_exists = os.path.isdir(os.path.join(self.scan_dir, '14_port_scan'))

        if not scan_dir_exists:
            return 'missing'

        has_results = os.path.exists(jsonl) and os.path.getsize(jsonl) > 0
        if has_results:
            return 'ok'

        if os.path.exists(stderr):
            try:
                with open(stderr, 'r', errors='ignore') as f:
                    head = f.read(4096)
                if 'pthread_create failed' in head or 'SIGABRT' in head or 'runtime/cgo' in head:
                    return 'crashed'
            except Exception:
                pass

        return 'no_open_ports'
    
    def load_service_data(self):
        """Load nmap service fingerprinting results"""
        services_json = os.path.join(self.scan_dir, '07_service_fingerprint/services.json')
        services = {}
        
        if os.path.exists(services_json):
            try:
                with open(services_json, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for svc in data:
                            host = svc.get('host')
                            if host:
                                if host not in services:
                                    services[host] = []
                                services[host].append(svc)
            except Exception as exc:
                logger.error("Failed to read service data %s: %s", services_json, exc)
        
        return services
    
    def load_vulnerabilities(self):
        """Load vulnerabilities from all sources"""
        vulns = []
        
        # Nuclei results
        nuclei_dirs = [
            os.path.join(self.scan_dir, '12_nuclei_scanning'),
            os.path.join(self.scan_dir, 'nuclei_scanning')
        ]
        
        for nuclei_dir in nuclei_dirs:
            if os.path.exists(nuclei_dir):
                for root, dirs, files in os.walk(nuclei_dir):
                    for file in files:
                        if file.endswith(('.json', '.txt', '.jsonl')):
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, 'r') as f:
                                    for line in f:
                                        try:
                                            entry = json.loads(line.strip())
                                            vuln = self._parse_nuclei_result(entry)
                                            if vuln:
                                                vulns.append(vuln)
                                        except Exception:
                                            continue
                            except Exception as exc:
                                logger.error("Failed to read nuclei file %s: %s", filepath, exc)
        
        # XSS results
        xss_file = os.path.join(self.scan_dir, '13_xss_testing/xss_results.txt')
        if os.path.exists(xss_file):
            try:
                with open(xss_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            vulns.append({
                                'source': 'XSS Testing',
                                'template': 'XSS Vulnerability',
                                'severity': 'high',
                                'host': 'Unknown',
                                'url': line,
                                'impact': 'Client-side code injection',
                                'remediation': 'Input validation and output encoding'
                            })
            except Exception as exc:
                logger.error("Failed to read XSS results %s: %s", xss_file, exc)
        
        # Secret scan results
        secrets_file = os.path.join(self.scan_dir, '10_secret_scanning/secrets.jsonl')
        if os.path.exists(secrets_file):
            # Load TSV index to map filenames to URLs
            index_tsv = os.path.join(self.scan_dir, '09_crawling/js_downloads/index.tsv')
            js_url_map = {}
            if os.path.exists(index_tsv):
                try:
                    with open(index_tsv, 'r') as f:
                        for line in f:
                            parts = line.strip().split('\t')
                            if len(parts) == 2:
                                js_url_map[parts[1]] = parts[0]
                except Exception as exc:
                    logger.error("Failed to read js index.tsv %s: %s", index_tsv, exc)

            try:
                with open(secrets_file, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            
                            # Parse trufflehog structure
                            detector_name = entry.get('DetectorName', 'Credential')
                            raw_secret = entry.get('Redacted', '')
                            if not raw_secret:
                                raw_secret = entry.get('Raw', '')
                                
                            file_path = entry.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', '')
                            filename = os.path.basename(file_path)
                            
                            # Skip the index file itself as its MD5 hashes cause false positives
                            if filename == 'index.tsv':
                                continue
                                
                            url = js_url_map.get(filename, filename)
                            
                            # Extract host from URL
                            host = 'Unknown'
                            if url.startswith('http'):
                                try:
                                    host = url.split('//')[1].split('/')[0]
                                except Exception:
                                    pass
                                    
                            impact = f"Exposed {detector_name}"
                            if raw_secret:
                                impact += f" (Redacted: {raw_secret[:20]}...)"

                            vulns.append({
                                'source': 'Secret Scan',
                                'template': f'{detector_name} Key',
                                'severity': 'critical',
                                'host': host,
                                'url': url,
                                'impact': impact,
                                'remediation': 'Rotate credential immediately and review access logs'
                            })
                        except Exception as exc:
                            logger.error("Failed to parse secret entry: %s", exc)
                            continue
            except Exception as exc:
                logger.error("Failed to read secrets %s: %s", secrets_file, exc)
        # Deduplicate vulnerabilities to prevent double publishing
        unique_vulns = []
        seen = set()
        for v in vulns:
            # Create a unique key for the vulnerability based on core attributes
            key = (v.get('source'), v.get('template'), v.get('host'), v.get('url'), v.get('impact'))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        
        return unique_vulns
    
    def _parse_nuclei_result(self, data):
        """Parse nuclei JSON output"""
        try:
            info = data.get('info', {})
            severity = info.get('severity', 'info').lower()
            return {
                'source': 'Nuclei',
                'template': info.get('name', 'Unknown'),
                'template_id': data.get('template-id', ''),
                'severity': severity,
                'host': data.get('host', 'Unknown'),
                'url': data.get('matched-at', data.get('url', '')),
                'impact': info.get('impact', ''),
                'remediation': info.get('remediation', ''),
                'cve_id': info.get('classification', {}).get('cve-id'),
                'cwe_id': info.get('classification', {}).get('cwe-id', [])
            }
        except Exception as exc:
            logger.error("Failed to parse nuclei result: %s", exc)
            return None
    
    def load_http_status(self):
        """Backfill http_status from httpx output when manifest is missing it."""
        http_file = os.path.join(self.scan_dir, '04_http_discovery/http_confirmed.json')
        result = {}
        if not os.path.exists(http_file):
            return result
        try:
            with open(http_file, 'r', errors='ignore') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        host = entry.get('host')
                        status = entry.get('status_code')
                        if host and status:
                            result[host] = int(status)
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("Failed to read http_confirmed.json: %s", exc)
        return result

    def aggregate_host_data(self, manifest, ports_data, services, vulns):
        """Merge all data sources for each host"""
        hosts = {}

        for host, host_data in manifest.get('hosts', {}).items():
            hosts[host] = dict(host_data)

        for host, ports in ports_data.items():
            if host not in hosts:
                hosts[host] = {}
            hosts[host]['ports_open'] = sorted(set(ports))

        for host, svc_list in services.items():
            if host not in hosts:
                hosts[host] = {}
            hosts[host]['services'] = svc_list

        # Backfill http_status from httpx output for scans where the manifest is missing it
        http_status_map = self.load_http_status()
        for host, status in http_status_map.items():
            if host in hosts and not hosts[host].get('http_status'):
                hosts[host]['http_status'] = status
                hosts[host]['has_webapp'] = True

        # Compute per-host risk scores
        compute_risk_scores(hosts, vulns)

        return hosts


# ===========================================================================
# RISK SCORING ENGINE
# ===========================================================================

def compute_host_risk(host, host_data, host_vulns):
    """Compute a 0-100 risk score for a single host."""
    score = 0

    # Vulnerability severity (capped at 80 total from vulns alone)
    vuln_score = 0
    for v in host_vulns:
        vuln_score += SEVERITY_WEIGHTS.get(v.get('severity', 'info'), 0)
    score += min(vuln_score, 80)

    # Exposed secrets (+25 each, capped at 50)
    secret_score = sum(25 for v in host_vulns if v.get('source') == 'Secret Scan')
    score += min(secret_score, 50)

    # Sensitive non-HTTP services exposed
    open_ports = set(host_data.get('ports_open', []))
    sensitive_exposed = open_ports & SENSITIVE_PORTS
    score += min(len(sensitive_exposed) * 15, 45)

    # Missing WAF while internet-facing
    has_http = bool(host_data.get('http_status'))
    waf_vendor = host_data.get('waf_vendor', 'none')
    has_waf = waf_vendor not in ('none', '', None)
    if has_http and not has_waf:
        score += 10

    # Low security-header score
    header_score = host_data.get('security_header_score', 0)
    if has_http and header_score < 3:
        score += 5

    return max(0, min(score, 100))


def risk_band(score):
    if score >= 75:
        return 'critical'
    if score >= 50:
        return 'high'
    if score >= 25:
        return 'medium'
    return 'low'


def risk_grade(org_score):
    if org_score <= 10:
        return 'A'
    if org_score <= 25:
        return 'B'
    if org_score <= 40:
        return 'C'
    if org_score <= 60:
        return 'D'
    return 'F'


def compute_risk_scores(hosts, vulns):
    """Mutates hosts dict to add risk_score and risk_band per host."""
    # Index vulns by host
    host_vulns = {}
    for v in vulns:
        h = v.get('host', 'Unknown')
        host_vulns.setdefault(h, []).append(v)
        url = v.get('url', '')
        if url:
            try:
                url_host = url.split('//')[1].split('/')[0].split(':')[0]
                if url_host != h:
                    host_vulns.setdefault(url_host, []).append(v)
            except Exception:
                pass

    for host, host_data in hosts.items():
        hv = host_vulns.get(host, [])
        score = compute_host_risk(host, host_data, hv)
        host_data['risk_score'] = score
        host_data['risk_band'] = risk_band(score)


def compute_org_risk(hosts):
    """Compute org-level aggregate risk (worst-N weighted, not naive average)."""
    scores = sorted([h.get('risk_score', 0) for h in hosts.values()], reverse=True)
    if not scores:
        return 0, 'A'

    top_n = scores[:max(10, len(scores) // 5)]
    base = sum(top_n) / len(top_n) if top_n else 0

    critical_count = sum(1 for s in scores if s >= 75)
    penalty = min(critical_count * 3, 20)

    org_score = max(0, min(int(base + penalty), 100))
    return org_score, risk_grade(org_score)


# ===========================================================================
# DATA ACCESS LAYER
# ===========================================================================

def get_latest_scan_id():
    """Return the newest scan folder id, or None if nothing exists."""
    scans = get_available_scans()
    return scans[0]['id'] if scans else None


def resolve_target(scan_id):
    """Resolve scan folder id from scan id, target name, or empty latest selection."""
    if not scan_id:
        return get_latest_scan_id()

    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    if os.path.isdir(scan_dir):
        return scan_id

    target_scans = get_scans_for_target(scan_id)
    return target_scans[0]['id'] if target_scans else scan_id


def _cache_key(scan_id):
    return scan_id


def get_cached_scan_data(scan_id):
    """Return cached scan data when fresh enough."""
    cache_key = _cache_key(scan_id)
    entry = _SCAN_CACHE.get(cache_key)
    now = time.time()
    if entry and (now - entry.get('timestamp', 0) < CACHE_TIMEOUT):
        return entry['data']

    data = get_scan_data(scan_id, use_cache=False)
    if data:
        _SCAN_CACHE[cache_key] = {'timestamp': now, 'data': data}
    return data


def get_available_scans(use_cache=True):
    """List all completed scans"""
    now = time.time()
    if use_cache and _SCAN_INDEX_CACHE['scans'] and now - _SCAN_INDEX_CACHE['timestamp'] < CACHE_TIMEOUT:
        return _SCAN_INDEX_CACHE['scans']

    scans = []
    
    if not os.path.exists(BASE_SCAN_DIR):
        return scans
    
    for item in sorted(os.listdir(BASE_SCAN_DIR), reverse=True):
        item_path = os.path.join(BASE_SCAN_DIR, item)
        if not os.path.isdir(item_path):
            continue
        
        manifest_file = os.path.join(item_path, 'manifest.json')
        if not os.path.exists(manifest_file):
            continue
        
        try:
            with open(manifest_file, 'r') as f:
                manifest = json.load(f)

            pipeline_info = manifest.get('pipeline_info', {})
            stats = manifest.get('statistics', {})

            start_time = pipeline_info.get('start_time', '')
            target = pipeline_info.get('target', item)
            scans.append({
                'id': item,
                'name': target,
                'target': target,
                'status': pipeline_info.get('status', 'unknown'),
                'start_time': start_time,
                'end_time': stats.get('end_time', pipeline_info.get('end_time', '')),
                'scan_time_sort': scan_time_key(start_time, os.path.getmtime(item_path)),
                'total_hosts': stats.get('total_hosts', 0),
                'http_hosts': stats.get('http_hosts', 0),
                'waf_hosts': stats.get('waf_hosts', 0),
                'total_ports': stats.get('total_ports', stats.get('open_ports', 0))
            })
        except Exception as exc:
            logger.error("Failed to read scan manifest %s: %s", manifest_file, exc)

    scans.sort(key=lambda scan: scan.get('scan_time_sort', 0), reverse=True)
    _SCAN_INDEX_CACHE['timestamp'] = now
    _SCAN_INDEX_CACHE['scans'] = scans
    return scans


def get_scans_for_target(target):
    """Return all scans belonging to a target name, newest first."""
    return [scan for scan in get_available_scans() if scan.get('target') == target or scan.get('name') == target]


def get_target_summaries():
    """Group revisions by target so the UI behaves like an EASM monitor."""
    grouped = {}
    for scan in get_available_scans():
        target = scan.get('target') or scan.get('name') or scan['id']
        grouped.setdefault(target, []).append(scan)

    targets = []
    for target, scans in grouped.items():
        scans.sort(key=lambda scan: scan.get('scan_time_sort', 0), reverse=True)
        latest = scans[0]
        previous = scans[1] if len(scans) > 1 else None
        targets.append({
            'id': target,
            'name': target,
            'target': target,
            'status': latest.get('status', 'unknown'),
            'scan_id': latest['id'],
            'latest_scan_id': latest['id'],
            'previous_scan_id': previous['id'] if previous else None,
            'revision_count': len(scans),
            'start_time': latest.get('start_time', ''),
            'total_hosts': latest.get('total_hosts', 0),
            'http_hosts': latest.get('http_hosts', 0),
            'waf_hosts': latest.get('waf_hosts', 0),
            'total_ports': latest.get('total_ports', 0)
        })

    targets.sort(key=lambda target: scan_time_key(target.get('start_time')), reverse=True)
    return targets

def get_scan_data(scan_id, use_cache=True):
    """Get complete data for a scan"""
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    
    if not os.path.isdir(scan_dir):
        return None

    if use_cache:
        cache_key = _cache_key(scan_id)
        entry = _SCAN_CACHE.get(cache_key)
        now = time.time()
        if entry and (now - entry.get('timestamp', 0) < CACHE_TIMEOUT):
            return entry['data']
    
    pipeline = ScanDataPipeline(scan_dir)
    manifest = pipeline.load_manifest()
    ports_data = pipeline.load_port_data()
    services = pipeline.load_service_data()
    vulns = pipeline.load_vulnerabilities()
    hosts = pipeline.aggregate_host_data(manifest, ports_data, services, vulns)
    
    port_scan_status = pipeline.get_port_scan_status()

    data = {
        'id': scan_id,
        'manifest': manifest,
        'hosts': hosts,
        'ports_data': ports_data,
        'services': services,
        'vulnerabilities': vulns,
        'pipeline_info': manifest.get('pipeline_info', {}),
        'statistics': manifest.get('statistics', {}),
        'port_scan_status': port_scan_status
    }
    if use_cache:
        _SCAN_CACHE[_cache_key(scan_id)] = {'timestamp': time.time(), 'data': data}
    return data


def get_previous_scan_id(scan_id):
    data = get_cached_scan_data(scan_id)
    if not data:
        return None
    target = data.get('pipeline_info', {}).get('target')
    if not target:
        return None
    scans = get_scans_for_target(target)
    for index, scan in enumerate(scans):
        if scan['id'] == scan_id and index + 1 < len(scans):
            return scans[index + 1]['id']
    return None


def _port_set(data):
    ports = set()
    for host, host_data in data.get('hosts', {}).items():
        for port in host_data.get('ports_open', []):
            try:
                ports.add(f"{host}:{int(port)}")
            except Exception:
                continue
    return ports


def _vuln_key(vuln):
    return '|'.join(str(vuln.get(field, '')) for field in ('source', 'template', 'host', 'url', 'severity'))


def compare_scans(current_scan_id, previous_scan_id=None):
    current = get_cached_scan_data(current_scan_id)
    if not current:
        return {}

    previous_scan_id = previous_scan_id or get_previous_scan_id(current_scan_id)
    previous = get_cached_scan_data(previous_scan_id) if previous_scan_id else None

    current_hosts = set(current.get('hosts', {}).keys())
    current_ports = _port_set(current)
    current_vulns = {_vuln_key(v): v for v in current.get('vulnerabilities', [])}

    if not previous:
        return {
            'target': current.get('pipeline_info', {}).get('target', current_scan_id),
            'current_scan_id': current_scan_id,
            'previous_scan_id': None,
            'has_baseline': False,
            'summary': {
                'new_hosts': len(current_hosts),
                'removed_hosts': 0,
                'new_ports': len(current_ports),
                'removed_ports': 0,
                'new_vulnerabilities': len(current_vulns),
                'removed_vulnerabilities': 0
            },
            'hosts': {'added': sorted(current_hosts), 'removed': []},
            'ports': {'added': sorted(current_ports), 'removed': []},
            'vulnerabilities': {'added': list(current_vulns.values()), 'removed': []}
        }

    previous_hosts = set(previous.get('hosts', {}).keys())
    previous_ports = _port_set(previous)
    previous_vulns = {_vuln_key(v): v for v in previous.get('vulnerabilities', [])}

    added_hosts = sorted(current_hosts - previous_hosts)
    removed_hosts = sorted(previous_hosts - current_hosts)
    added_ports = sorted(current_ports - previous_ports)
    removed_ports = sorted(previous_ports - current_ports)
    added_vuln_keys = sorted(set(current_vulns) - set(previous_vulns))
    removed_vuln_keys = sorted(set(previous_vulns) - set(current_vulns))

    return {
        'target': current.get('pipeline_info', {}).get('target', current_scan_id),
        'current_scan_id': current_scan_id,
        'previous_scan_id': previous_scan_id,
        'has_baseline': True,
        'summary': {
            'new_hosts': len(added_hosts),
            'removed_hosts': len(removed_hosts),
            'new_ports': len(added_ports),
            'removed_ports': len(removed_ports),
            'new_vulnerabilities': len(added_vuln_keys),
            'removed_vulnerabilities': len(removed_vuln_keys)
        },
        'hosts': {'added': added_hosts, 'removed': removed_hosts},
        'ports': {'added': added_ports, 'removed': removed_ports},
        'vulnerabilities': {
            'added': [current_vulns[key] for key in added_vuln_keys],
            'removed': [previous_vulns[key] for key in removed_vuln_keys]
        }
    }

# ===========================================================================
# API ROUTES
# ===========================================================================

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/scans')
def api_scans():
    """List all available scans"""
    scans = get_available_scans()
    return jsonify(scans)


@app.route('/api/targets/history')
def api_target_history():
    target = request.args.get('target')
    scan_id = resolve_target(target)
    data = get_cached_scan_data(scan_id) if scan_id else None
    resolved_target = data.get('pipeline_info', {}).get('target') if data else target
    return jsonify(get_scans_for_target(resolved_target) if resolved_target else [])


@app.route('/api/compare')
def api_compare():
    scan_id = resolve_target(request.args.get('target'))
    previous = request.args.get('previous')
    if not scan_id:
        return jsonify({})
    return jsonify(compare_scans(scan_id, previous))

@app.route('/api/scan/<scan_id>')
def api_scan(scan_id):
    """Get complete scan data"""
    data = get_scan_data(scan_id)
    
    if not data:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'id': data['id'],
        'pipeline_info': data['pipeline_info'],
        'statistics': data['statistics'],
        'hosts_count': len(data['hosts']),
        'ports_count': len(data['ports_data']),
        'vulnerabilities_count': len(data['vulnerabilities'])
    })

@app.route('/api/scan/<scan_id>/hosts')
def api_hosts(scan_id):
    """Get hosts for a scan"""
    data = get_scan_data(scan_id)
    
    if not data:
        return jsonify([]), 404
    
    hosts_list = []
    for host, host_data in data['hosts'].items():
        hosts_list.append({
            'name': host,
            'ip': host_data.get('ip', ''),
            'resolved': host_data.get('resolved', False),
            'http_status': host_data.get('http_status', ''),
            'waf_vendor': host_data.get('waf_vendor', 'none'),
            'security_score': host_data.get('security_header_score', 0),
            'ports': sorted(host_data.get('ports_open', [])),
            'services': host_data.get('services', []),
            'cdn': host_data.get('cdn', False),
            'risk_score': host_data.get('risk_score', 0),
            'risk_band': host_data.get('risk_band', 'low')
        })

    return jsonify(hosts_list)

@app.route('/api/scan/<scan_id>/ports')
def api_ports(scan_id):
    """Get ports for a scan"""
    data = get_scan_data(scan_id)
    
    if not data:
        return jsonify([]), 404
    
    # Group by port
    port_map = {}
    for host, ports in data['ports_data'].items():
        for port in ports:
            port_num = int(port)
            if port_num not in port_map:
                port_map[port_num] = {
                    'port': port_num,
                    'service': PORT_MAPPINGS.get(port_num, 'Unknown'),
                    'hosts': []
                }
            port_map[port_num]['hosts'].append({
                'host': host,
                'ip': data['hosts'].get(host, {}).get('ip', ''),
                'http_status': data['hosts'].get(host, {}).get('http_status', '')
            })
    
    # Sort by port number
    result = [port_map[p] for p in sorted(port_map.keys())]
    return jsonify(result)

@app.route('/api/scan/<scan_id>/vulnerabilities')
def api_vulnerabilities(scan_id):
    """Get vulnerabilities for a scan"""
    data = get_scan_data(scan_id)
    
    if not data:
        return jsonify([]), 404
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns = sorted(
        data['vulnerabilities'],
        key=lambda x: severity_order.get(x.get('severity', 'info'), 4)
    )
    
    return jsonify(vulns)

@app.route('/api/scan/<scan_id>/statistics')
def api_statistics(scan_id):
    """Get statistics for a scan"""
    data = get_scan_data(scan_id)
    
    if not data:
        return jsonify({}), 404
    
    hosts = data['hosts']
    
    return jsonify({
        'total_hosts': len(hosts),
        'resolved_hosts': sum(1 for h in hosts.values() if h.get('resolved')),
        'http_hosts': sum(1 for h in hosts.values() if h.get('http_status')),
        'waf_hosts': sum(1 for h in hosts.values() if h.get('waf_vendor') != 'none'),
        'cdn_hosts': sum(1 for h in hosts.values() if h.get('cdn')),
        'total_vulnerabilities': len(data['vulnerabilities']),
        'total_ports': sum(len(h.get('ports_open', [])) for h in hosts.values()),
        'non_http_services': sum(1 for h in hosts.values() if h.get('services')),
        'port_scan_status': data.get('port_scan_status', 'missing')
    })

@app.route('/api/scan/<scan_id>/modules')
def api_modules(scan_id):
    """Get module status for a scan"""
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    
    if not os.path.isdir(scan_dir):
        return jsonify({}), 404
    
    modules = {}
    module_names = {
        '01_asset_discovery': 'Asset Discovery',
        '02_subdomain_enum': 'Subdomain Enumeration',
        '03_dns_resolution': 'DNS Resolution',
        '04_http_discovery': 'HTTP Discovery',
        '05_waf_detection': 'WAF Detection',
        '06_header_analysis': 'Header Analysis',
        '07_service_fingerprint': 'Service Fingerprinting',
        '08_directory_discovery': 'Directory Discovery',
        '09_crawling': 'Web Crawling',
        '10_secret_scanning': 'Secret Scanning',
        '11_param_fuzzing': 'Parameter Fuzzing',
        '12_nuclei_scanning': 'Vulnerability Scanning',
        '13_xss_testing': 'XSS Testing',
        '14_port_scan': 'Port Scanning'
    }
    
    for module_dir, module_name in module_names.items():
        module_path = os.path.join(scan_dir, module_dir)
        completed = False
        data_count = 0
        
        if os.path.isdir(module_path):
            files = glob.glob(os.path.join(module_path, '*'))
            data_count = len([f for f in files if os.path.isfile(f)])
            completed = data_count > 0
        
        modules[module_dir] = {
            'name': module_name,
            'completed': completed,
            'data_count': data_count
        }
    
    return jsonify(modules)


@app.route('/api/scan/<scan_id>/history')
def api_scan_history(scan_id):
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify([]), 404
    target = data.get('pipeline_info', {}).get('target')
    return jsonify(get_scans_for_target(target))


@app.route('/api/scan/<scan_id>/compare')
def api_scan_compare(scan_id):
    if not get_cached_scan_data(scan_id):
        return jsonify({}), 404
    return jsonify(compare_scans(scan_id, request.args.get('previous')))


@app.route('/api/scan/<scan_id>/risk')
def api_risk(scan_id):
    """Per-host and org-level risk scores."""
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({}), 404

    hosts = data.get('hosts', {})
    org_score, grade = compute_org_risk(hosts)

    bands = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    host_scores = []
    for host, hd in hosts.items():
        band = hd.get('risk_band', 'low')
        bands[band] = bands.get(band, 0) + 1
        host_scores.append({
            'host': host,
            'score': hd.get('risk_score', 0),
            'band': band
        })

    host_scores.sort(key=lambda x: x['score'], reverse=True)
    return jsonify({
        'org_score': org_score,
        'grade': grade,
        'band_distribution': bands,
        'host_scores': host_scores
    })


@app.route('/api/scan/<scan_id>/executive')
def api_executive(scan_id):
    """Executive / CXO summary."""
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({}), 404

    hosts = data.get('hosts', {})
    vulns = data.get('vulnerabilities', [])
    org_score, grade = compute_org_risk(hosts)

    total_assets = len(hosts)
    http_hosts = sum(1 for h in hosts.values() if h.get('http_status'))
    resolved = sum(1 for h in hosts.values() if h.get('resolved'))
    waf_covered = sum(1 for h in hosts.values()
                      if h.get('waf_vendor') not in ('none', '', None) and h.get('http_status'))
    waf_uncovered = http_hosts - waf_covered
    waf_coverage_pct = round(waf_covered * 100 / http_hosts) if http_hosts else 0
    cdn_fronted = sum(1 for h in hosts.values() if h.get('cdn'))

    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in vulns:
        s = v.get('severity', 'info')
        sev_counts[s] = sev_counts.get(s, 0) + 1

    secrets_count = sum(1 for v in vulns if v.get('source') == 'Secret Scan')

    sensitive_services = []
    for host, hd in hosts.items():
        exposed = set(hd.get('ports_open', [])) & SENSITIVE_PORTS
        for p in exposed:
            sensitive_services.append({'host': host, 'port': p, 'service': PORT_MAPPINGS.get(p, 'Unknown')})

    delta = compare_scans(scan_id)

    # Top 5 remediation priorities
    scored_items = []
    for v in vulns:
        prio = SEVERITY_WEIGHTS.get(v.get('severity', 'info'), 0)
        if v.get('source') == 'Secret Scan':
            prio += 25
        scored_items.append((prio, v))
    for s in sensitive_services:
        scored_items.append((15, {
            'source': 'Port Scan',
            'template': f"Exposed {s['service']}",
            'severity': 'high',
            'host': s['host'],
            'url': f"{s['host']}:{s['port']}",
            'impact': f"Sensitive service {s['service']} exposed to internet",
            'remediation': 'Restrict access via firewall or VPN'
        }))
    scored_items.sort(key=lambda x: x[0], reverse=True)
    top_priorities = [item[1] for item in scored_items[:5]]

    # Historical trend
    scan_history = get_scans_for_target(data.get('pipeline_info', {}).get('target', ''))
    trend = []
    for s in scan_history[:10]:
        hist_data = get_cached_scan_data(s['id'])
        if hist_data:
            h_score, h_grade = compute_org_risk(hist_data.get('hosts', {}))
            trend.append({
                'scan_id': s['id'],
                'start_time': s.get('start_time', ''),
                'org_score': h_score,
                'grade': h_grade,
                'total_hosts': s.get('total_hosts', 0),
                'vuln_count': len(hist_data.get('vulnerabilities', []))
            })

    return jsonify({
        'org_score': org_score,
        'grade': grade,
        'exposure': {
            'total_assets': total_assets,
            'internet_facing_http': http_hosts,
            'resolved': resolved,
            'waf_covered': waf_covered,
            'waf_uncovered': waf_uncovered,
            'waf_coverage_pct': waf_coverage_pct,
            'cdn_fronted': cdn_fronted
        },
        'findings': {
            'by_severity': sev_counts,
            'secrets': secrets_count,
            'sensitive_services': len(sensitive_services)
        },
        'delta': delta.get('summary', {}),
        'has_baseline': delta.get('has_baseline', False),
        'top_priorities': top_priorities,
        'trend': trend,
        'port_scan_status': data.get('port_scan_status', 'missing')
    })


@app.route('/api/scan/<scan_id>/cves')
def api_cves(scan_id):
    """CVE-grouped vulnerability view."""
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify([]), 404

    cve_map = {}
    for v in data.get('vulnerabilities', []):
        cve_ids = v.get('cve_id') or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids] if cve_ids else []
        for cve_id in cve_ids:
            if not cve_id:
                continue
            if cve_id not in cve_map:
                cve_map[cve_id] = {
                    'cve_id': cve_id,
                    'severity': v.get('severity', 'info'),
                    'template': v.get('template', ''),
                    'cwe_ids': [],
                    'affected_hosts': [],
                    'count': 0
                }
            entry = cve_map[cve_id]
            entry['count'] += 1
            host = v.get('host', 'Unknown')
            if host not in entry['affected_hosts']:
                entry['affected_hosts'].append(host)
            cwe = v.get('cwe_id', [])
            if isinstance(cwe, str):
                cwe = [cwe]
            for c in cwe:
                if c and c not in entry['cwe_ids']:
                    entry['cwe_ids'].append(c)

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    result = sorted(cve_map.values(), key=lambda x: (severity_order.get(x['severity'], 4), -x['count']))
    return jsonify(result)


def _legacy_host_rows(scan_id):
    data = get_cached_scan_data(scan_id)
    if not data:
        return []

    rows = []
    for host, host_data in data['hosts'].items():
        rows.append({
            'host': host,
            'ip': host_data.get('ip', ''),
            'resolved': host_data.get('resolved', False),
            'http_status': host_data.get('http_status', ''),
            'cdn': host_data.get('cdn', False),
            'waf_vendor': host_data.get('waf_vendor', 'none'),
            'skip_bruteforce': host_data.get('skip_bruteforce', False),
            'security_score': host_data.get('security_header_score', 0),
            'server_banner': host_data.get('server_banner', ''),
            'service_type': host_data.get('service_type', 'http'),
            'ports_open': sorted(set(host_data.get('ports_open', []))),
            'cve_count': len(host_data.get('cve_candidates', [])),
            'risk_score': host_data.get('risk_score', 0),
            'risk_band': host_data.get('risk_band', 'low')
        })
    return rows


def _legacy_port_rows(scan_id):
    data = get_cached_scan_data(scan_id)
    if not data:
        return []

    port_map = {}
    for host, host_data in data['hosts'].items():
        ip = host_data.get('ip', '')
        services_list = host_data.get('services', [])
        
        # Build a quick lookup for port -> service name
        port_service_map = {}
        for srv in services_list:
            if 'port' in srv and 'name' in srv:
                port_service_map[int(srv['port'])] = srv['name']
                
        for port in sorted(set(host_data.get('ports_open', []))):
            port = int(port)
            
            # Get service name from Nmap, fallback to HTTP logic if missing
            service_name = port_service_map.get(port)
            if not service_name or service_name == 'unknown':
                if port == 443 or port == 8443:
                    service_name = 'https'
                elif port == 80 or port == 8080:
                    service_name = 'http'
                else:
                    service_name = 'unknown'

            port_map.setdefault(port, {'port': port, 'host_count': 0, 'hosts': []})
            port_map[port]['hosts'].append({
                'host': host,
                'ip': ip,
                'http_status': host_data.get('http_status', ''),
                'waf': host_data.get('waf_vendor', 'none') != 'none',
                'service': service_name
            })
            port_map[port]['host_count'] = len({entry['host'] for entry in port_map[port]['hosts']})

    return [port_map[port] for port in sorted(port_map)]


@app.route('/api/targets')
def api_targets_legacy():
    """Legacy target list for the older frontend."""
    logger.info("API request: /api/targets")
    return jsonify(get_target_summaries())


@app.route('/api/status')
def api_status_legacy():
    """Legacy status endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/status target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    if not data:
        return jsonify({'status': 'no_data', 'target': scan_id or '', 'message': 'No scan data available'})

    pipeline_info = data.get('pipeline_info', {})
    statistics = data.get('statistics', {})
    return jsonify({
        'status': pipeline_info.get('status', 'unknown'),
        'target': pipeline_info.get('target', scan_id),
        'version': pipeline_info.get('version', ''),
        'start_time': pipeline_info.get('start_time', ''),
        'scan_id': scan_id,
        'duration': statistics.get('duration_seconds', 0)
    })


@app.route('/api/statistics')
def api_statistics_legacy():
    """Legacy statistics endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/statistics target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    if not data:
        return jsonify({})

    hosts = data.get('hosts', {})
    statistics = data.get('statistics', {})
    computed_http = sum(1 for h in hosts.values() if h.get('http_status'))
    computed_waf = sum(1 for h in hosts.values() if h.get('waf_vendor') not in ('none', '', None))
    return jsonify({
        'total_hosts': statistics.get('total_hosts', len(hosts)),
        'resolved_hosts': statistics.get('resolved_hosts', sum(1 for h in hosts.values() if h.get('resolved'))),
        'http_hosts': max(statistics.get('http_hosts', 0), computed_http),
        'waf_hosts': max(statistics.get('waf_hosts', 0), computed_waf),
        'cdn_hosts': statistics.get('cdn_hosts', sum(1 for h in hosts.values() if h.get('cdn'))),
        'non_http_services': statistics.get('non_http_services', sum(1 for h in hosts.values() if h.get('service_type') == 'non_http')),
        'total_vulnerabilities': len(data.get('vulnerabilities', [])),
        'total_ports': statistics.get('total_ports', sum(len(h.get('ports_open', [])) for h in hosts.values())),
        'open_ports': statistics.get('open_ports', sum(len(h.get('ports_open', [])) for h in hosts.values())),
        'services_fingerprinted': statistics.get('services_fingerprinted', sum(1 for h in hosts.values() if h.get('services'))),
        'total_urls': statistics.get('total_urls', 0),
        'total_js_files': statistics.get('total_js_files', 0),
        'total_secrets': statistics.get('total_secrets', 0),
        'port_scan_status': data.get('port_scan_status', statistics.get('port_scan_status', 'missing'))
    })


@app.route('/api/hosts')
def api_hosts_legacy():
    """Legacy hosts endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/hosts target=%s", scan_id)
    return jsonify(_legacy_host_rows(scan_id))


@app.route('/api/hosts/search')
def api_hosts_search():
    """Legacy search endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    query = request.args.get('q', '').strip().lower()
    logger.info("API request: /api/hosts/search target=%s query=%s", scan_id, query)
    hosts = _legacy_host_rows(scan_id)
    if query:
        hosts = [h for h in hosts if query in h['host'].lower() or query in h['ip'].lower()]
    return jsonify(hosts)


@app.route('/api/hosts/filter/<filter_type>')
def api_hosts_filter(filter_type):
    """Legacy host filter endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/hosts/filter/%s target=%s", filter_type, scan_id)
    hosts = _legacy_host_rows(scan_id)
    if filter_type == 'waf':
        hosts = [h for h in hosts if h.get('waf_vendor') != 'none']
    elif filter_type == 'http':
        hosts = [h for h in hosts if h.get('http_status')]
    elif filter_type == 'resolved':
        hosts = [h for h in hosts if h.get('resolved')]
    elif filter_type == 'cdn':
        hosts = [h for h in hosts if h.get('cdn')]
    return jsonify(hosts)


@app.route('/api/ports')
def api_ports_legacy():
    """Legacy ports endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/ports target=%s", scan_id)
    return jsonify(_legacy_port_rows(scan_id))


@app.route('/api/dirsearch')
def api_dirsearch():
    """Returns dirsearch results (200, 403, 500)."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/dirsearch target=%s", scan_id)
    if not scan_id:
        return jsonify([])
    
    dirsearch_dir = os.path.join(BASE_SCAN_DIR, scan_id, '08_directory_discovery', 'dirsearch')
    urls = []
    
    files_to_read = [
        ('200response.txt', 200),
        ('forbidden_response.txt', 403),
        ('500response.txt', 500)
    ]
    
    for filename, status_code in files_to_read:
        file_path = os.path.join(dirsearch_dir, filename)
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        urls.append({"url": line, "status": status_code})
                        
    return jsonify(urls)


@app.route('/api/modules')
def api_modules_legacy():
    """Legacy module summary endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/modules target=%s", scan_id)
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id) if scan_id else None
    if not scan_dir or not os.path.isdir(scan_dir):
        return jsonify({})

    module_names = {
        '01_asset_discovery': 'Asset Discovery',
        '02_subdomain_enum': 'Subdomain Enumeration',
        '03_dns_resolution': 'DNS Resolution',
        '04_http_discovery': 'HTTP Discovery',
        '05_waf_detection': 'WAF Detection',
        '06_header_analysis': 'Header Analysis',
        '07_service_fingerprint': 'Service Fingerprinting',
        '08_directory_discovery': 'Directory Discovery',
        '09_crawling': 'Web Crawling',
        '10_secret_scanning': 'Secret Scanning',
        '11_param_fuzzing': 'Parameter Fuzzing',
        '12_nuclei_scanning': 'Vulnerability Scanning',
        '13_xss_testing': 'XSS Testing',
        '14_port_scan': 'Port Scanning',
    }

    modules = {}
    for module_dir, module_name in module_names.items():
        module_path = os.path.join(scan_dir, module_dir)
        results_file = None
        if os.path.isdir(module_path):
            matches = sorted(glob.glob(os.path.join(module_path, '*_results.json')), key=os.path.getmtime)
            if matches:
                results_file = matches[-1]

        modules[module_dir] = {
            'name': module_name,
            'completed': bool(results_file),
            'data_count': len([f for f in glob.glob(os.path.join(module_path, '*')) if os.path.isfile(f)]) if os.path.isdir(module_path) else 0,
            'data': load_json_file(results_file) if results_file else {}
        }
    return jsonify(modules)


@app.route('/api/vulnerabilities')
def api_vulnerabilities_legacy():
    """Legacy vulnerability endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/vulnerabilities target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    if not data:
        return jsonify([])
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns = sorted(data.get('vulnerabilities', []), key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
    return jsonify(vulns)


@app.route('/api/risk')
def api_risk_legacy():
    """Legacy risk endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/risk target=%s", scan_id)
    if not scan_id:
        return jsonify({})
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({})
    hosts = data.get('hosts', {})
    org_score, grade = compute_org_risk(hosts)
    bands = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for hd in hosts.values():
        band = hd.get('risk_band', 'low')
        bands[band] = bands.get(band, 0) + 1
    return jsonify({'org_score': org_score, 'grade': grade, 'band_distribution': bands})


@app.route('/api/executive')
def api_executive_legacy():
    """Legacy executive summary endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/executive target=%s", scan_id)
    if not scan_id:
        return jsonify({})
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({})
    # Reuse the structured endpoint
    return api_executive(scan_id)


@app.route('/api/cves')
def api_cves_legacy():
    """Legacy CVE endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/cves target=%s", scan_id)
    if not scan_id:
        return jsonify([])
    return api_cves(scan_id)


@app.route('/api/manifest')
def api_manifest_legacy():
    """Legacy manifest endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/manifest target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    return jsonify(data.get('manifest', {}) if data else {})


@app.route('/api/report')
def api_report_legacy():
    """Legacy report endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/report target=%s", scan_id)
    if not scan_id:
        return jsonify({})
    report_file = os.path.join(BASE_SCAN_DIR, scan_id, 'reports', 'report.json')
    return jsonify(load_json_file(report_file))

# ===========================================================================
# MAIN
# ===========================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("   ARISE Dashboard v3.0 - Summon Every Hidden Exposure.")
    print("=" * 70)
    print()
    
    os.makedirs('templates', exist_ok=True)
    
    if not os.path.exists(BASE_SCAN_DIR):
        os.makedirs(BASE_SCAN_DIR, exist_ok=True)
        print(f"[*] Created scans directory: {BASE_SCAN_DIR}")
    
    scans = get_available_scans()
    print(f"[*] Found {len(scans)} completed scans")
    
    if scans:
        print("\n[+] Available scans:")
        for scan in scans[:5]:
            print(f"    - {scan['name']} ({scan['id']})")
            print(f"      Hosts: {scan['total_hosts']} | HTTP: {scan['http_hosts']} | Ports: {scan['total_ports']}")
    
    _port = int(os.environ.get('ARISE_DASHBOARD_PORT', 5000))

    print()
    print("Dashboard running at:")
    print(f"  http://localhost:{_port}")
    print()
    print("Press Ctrl+C to stop")
    print()

    app.run(host='0.0.0.0', port=_port, debug=True, use_reloader=False)
