# Backend/tools/cve_scanner.py

import requests
import json
import re
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from Backend.db import SessionLocal
from Backend.models import CVE, CVESyncLog, ScanCVE
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComprehensiveCVEScanner:
    """
    Comprehensive CVE scanner that:
    1. Maintains updated local CVE database from NVD
    2. Scans targets for relevant CVEs based on detected technologies
    3. Provides detailed vulnerability analysis
    """

    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_api_base = "https://api.first.org/data/v1/epss"
        self.circl_api_base = "https://cve.circl.lu/api/cve"

        # Initialize session with headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecScan-CVE-Scanner/2.0',
            'Accept': 'application/json'
        })

        # Cache for frequently detected technologies
        self.tech_cache = {}

        # Common technology mappings for better CVE detection
        self.technology_mappings = {
            'apache': ['httpd', 'apache http server', 'apache httpd', 'apache2'],
            'nginx': ['engine x', 'nginx'],
            'wordpress': ['wp', 'wordpress'],
            'drupal': ['drupal cms'],
            'joomla': ['joomla cms'],
            'mysql': ['mariadb', 'mariadb server'],
            'postgresql': ['postgres', 'postgresql'],
            'tomcat': ['apache tomcat'],
            'nodejs': ['node.js', 'node', 'express'],
            'python': ['django', 'flask', 'bottle'],
            'php': ['php-fpm', 'php'],
            'ruby': ['rails', 'ruby on rails'],
            'java': ['spring', 'spring boot', 'java ee'],
            'windows': ['iis', 'internet information services'],
            'linux': ['ubuntu', 'debian', 'centos', 'redhat', 'fedora'],
            'openssl': ['ssl', 'tls'],
            'redis': ['redis server'],
            'mongodb': ['mongo'],
            'elasticsearch': ['elastic search'],
            'docker': ['docker', 'container'],
            'kubernetes': ['k8s', 'kubernetes']
        }

        # Product-specific CVE patterns (common high-profile CVEs)
        self.cve_patterns = {
            'log4j': ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105'],
            'spring': ['CVE-2022-22965', 'CVE-2022-22963', 'CVE-2022-22947'],
            'apache': ['CVE-2021-41773', 'CVE-2021-42013', 'CVE-2021-40438'],
            'wordpress': ['CVE-2021-44227', 'CVE-2020-28032', 'CVE-2019-16217'],
            'drupal': ['CVE-2019-6339', 'CVE-2018-7600', 'CVE-2018-7602'],
            'joomla': ['CVE-2021-23132', 'CVE-2020-35616', 'CVE-2020-10220'],
            'openssl': ['CVE-2021-3449', 'CVE-2020-1967', 'CVE-2019-1547'],
            'struts': ['CVE-2017-5638', 'CVE-2017-9791', 'CVE-2018-11776'],
            'nginx': ['CVE-2021-23017', 'CVE-2019-20372', 'CVE-2018-16845']
        }

    def update_cve_database(self, days_back: int = 7, max_cves: int = 500) -> Dict[str, Any]:
        """
        Update local CVE database with recent vulnerabilities from NVD

        Args:
            days_back: How many days back to fetch CVEs (1-120)
            max_cves: Maximum number of CVEs to fetch

        Returns:
            Dictionary with update statistics
        """
        db = SessionLocal()
        sync_log = None

        try:
            # Create sync log
            sync_log = CVESyncLog(
                sync_type="incremental",
                status="running",
                sync_start=datetime.now(timezone.utc)
            )
            db.add(sync_log)
            db.commit()

            logger.info(f"Updating CVE database for last {days_back} days...")

            # Calculate date range
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=min(days_back, 120))

            # Format dates for NVD API
            start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S')
            end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S')

            all_cves = []
            cves_added = 0
            cves_updated = 0

            # Fetch CVEs from NVD
            start_index = 0
            results_per_page = 2000

            while len(all_cves) < max_cves:
                try:
                    params = {
                        'pubStartDate': f"{start_str} UTC-00:00",
                        'pubEndDate': f"{end_str} UTC-00:00",
                        'resultsPerPage': results_per_page,
                        'startIndex': start_index
                    }

                    logger.debug(f"Fetching CVEs with params: {params}")

                    response = self.session.get(
                        self.nvd_api_base,
                        params=params,
                        timeout=30
                    )
                    response.raise_for_status()
                    data = response.json()

                    vulnerabilities = data.get('vulnerabilities', [])
                    if not vulnerabilities:
                        break

                    for vuln in vulnerabilities:
                        cve_data = self._parse_nvd_vulnerability(vuln)
                        if cve_data:
                            all_cves.append(cve_data)

                            # Save to database
                            existing_cve = db.query(CVE).filter_by(cve_id=cve_data['cve_id']).first()

                            if existing_cve:
                                # Update existing CVE
                                existing_cve.description = cve_data.get('description', existing_cve.description)
                                existing_cve.cvss_score = cve_data.get('cvss_score', existing_cve.cvss_score)
                                existing_cve.severity = cve_data.get('severity', existing_cve.severity)
                                existing_cve.last_modified = cve_data.get('last_modified')
                                existing_cve.affected_products = cve_data.get('affected_products',
                                                                              existing_cve.affected_products)
                                existing_cve.references = cve_data.get('references', existing_cve.references)
                                existing_cve.exploit_available = cve_data.get('exploit_available',
                                                                              existing_cve.exploit_available)
                                existing_cve.weaponized = cve_data.get('weaponized', existing_cve.weaponized)
                                existing_cve.mass_exploited = cve_data.get('mass_exploited',
                                                                           existing_cve.mass_exploited)
                                existing_cve.ransomware_used = cve_data.get('ransomware_used',
                                                                            existing_cve.ransomware_used)
                                existing_cve.epss_score = cve_data.get('epss_score', existing_cve.epss_score)
                                existing_cve.services = cve_data.get('services', existing_cve.services)
                                existing_cve.updated_at = datetime.now(timezone.utc)
                                cves_updated += 1
                            else:
                                # Add new CVE
                                new_cve = CVE(
                                    cve_id=cve_data['cve_id'],
                                    description=cve_data.get('description'),
                                    cvss_score=cve_data.get('cvss_score'),
                                    severity=cve_data.get('severity'),
                                    published_date=cve_data.get('published_date'),
                                    last_modified=cve_data.get('last_modified'),
                                    affected_products=cve_data.get('affected_products', []),
                                    references=cve_data.get('references', []),
                                    exploit_available=cve_data.get('exploit_available', False),
                                    weaponized=cve_data.get('weaponized', False),
                                    mass_exploited=cve_data.get('mass_exploited', False),
                                    ransomware_used=cve_data.get('ransomware_used', False),
                                    epss_score=cve_data.get('epss_score'),
                                    services=cve_data.get('services', [])
                                )
                                db.add(new_cve)
                                cves_added += 1

                    logger.info(f"Processed {len(vulnerabilities)} CVEs, total: {len(all_cves)}")

                    # Check if we have more pages
                    total_results = data.get('totalResults', 0)
                    start_index += results_per_page

                    if start_index >= total_results or start_index >= max_cves:
                        break

                    # Rate limiting (NVD recommends 6 requests per minute)
                    time.sleep(10)  # Wait 10 seconds between requests

                except requests.exceptions.RequestException as e:
                    logger.error(f"Request error fetching CVEs batch: {e}")
                    break
                except Exception as e:
                    logger.error(f"Error processing CVEs batch: {e}")
                    break

            db.commit()

            # Update sync log
            if sync_log:
                sync_log.status = "completed"
                sync_log.cves_added = cves_added
                sync_log.cves_updated = cves_updated
                sync_log.sync_end = datetime.now(timezone.utc)
                db.commit()

            logger.info(f"CVE database updated: {cves_added} added, {cves_updated} updated")

            return {
                "status": "success",
                "cves_added": cves_added,
                "cves_updated": cves_updated,
                "total_processed": len(all_cves),
                "sync_id": sync_log.id if sync_log else None,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to update CVE database: {e}")
            if sync_log:
                sync_log.status = "failed"
                sync_log.error_message = str(e)
                sync_log.sync_end = datetime.now(timezone.utc)
                db.commit()
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        finally:
            db.close()

    def scan_target_for_cves(self, target_url: str, nmap_results: List[Dict], whatweb_results: Dict) -> Dict[str, Any]:
        """
        Scan target for relevant CVEs based on detected technologies

        Args:
            target_url: Target URL
            nmap_results: Results from Nmap scan
            whatweb_results: Results from WhatWeb scan

        Returns:
            Comprehensive CVE scan results
        """
        logger.info(f"Scanning {target_url} for relevant CVEs...")

        try:
            # Extract detected technologies
            detected_tech = self._extract_technologies(whatweb_results, nmap_results)

            if not detected_tech:
                logger.warning(f"No technologies detected for {target_url}")
                return {
                    "status": "success",
                    "target": target_url,
                    "detected_technologies": [],
                    "total_relevant_cves": 0,
                    "cves_found": [],
                    "detailed_cves": {},
                    "scan_summary": {
                        "high_risk": 0,
                        "medium_risk": 0,
                        "low_risk": 0,
                        "exploitable": 0,
                        "weaponized": 0,
                        "mass_exploited": 0,
                        "ransomware_used": 0
                    }
                }

            logger.info(f"Detected {len(detected_tech)} technologies: {detected_tech}")

            # Get relevant CVEs from database
            relevant_cves = self._get_relevant_cves_from_db(detected_tech)

            # Also check for known patterns
            pattern_cves = self._check_cve_patterns(detected_tech)
            relevant_cves.extend(pattern_cves)

            # Remove duplicates
            unique_cves = list(set(relevant_cves))

            # Fetch detailed information for top CVEs
            detailed_results = {}
            top_cves = unique_cves[:50]  # Limit to top 50 most relevant

            for cve_id in top_cves:
                try:
                    cve_data = self.get_cve_details(cve_id)
                    if cve_data and 'error' not in cve_data:
                        detailed_results[cve_id] = cve_data
                except Exception as e:
                    logger.warning(f"Failed to fetch details for {cve_id}: {e}")

            # Calculate statistics
            stats = self._calculate_cve_statistics(detailed_results)

            return {
                "status": "success",
                "target": target_url,
                "detected_technologies": detected_tech,
                "total_relevant_cves": len(unique_cves),
                "cves_found": list(detailed_results.keys()),
                "detailed_cves": detailed_results,
                "scan_summary": stats
            }

        except Exception as e:
            logger.error(f"Error scanning for CVEs: {e}")
            return {
                "status": "error",
                "error": str(e),
                "target": target_url,
                "detected_technologies": [],
                "total_relevant_cves": 0,
                "cves_found": [],
                "detailed_cves": {},
                "scan_summary": {
                    "high_risk": 0,
                    "medium_risk": 0,
                    "low_risk": 0,
                    "exploitable": 0,
                    "weaponized": 0,
                    "mass_exploited": 0,
                    "ransomware_used": 0
                }
            }

    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        Get detailed CVE information from database or API
        """
        db = SessionLocal()

        try:
            # Try database first
            cve = db.query(CVE).filter_by(cve_id=cve_id).first()

            if cve:
                return cve.to_dict()

            # If not in database, fetch from API (use existing cve_data_api_helper)
            from Backend.tools.cve_data_api_helper import fetch_cve_data
            api_data = fetch_cve_data(cve_id)

            if 'error' in api_data:
                return api_data

            # Convert API data to our format
            return self._convert_api_to_cve_model(api_data)

        finally:
            db.close()

    def link_cves_to_scan(self, scan_id: int, cve_results: Dict[str, Any]) -> bool:
        """
        Link found CVEs to a specific scan
        """
        db = SessionLocal()

        try:
            cves_found = cve_results.get('cves_found', [])
            detected_tech = cve_results.get('detected_technologies', [])
            detailed_cves = cve_results.get('detailed_cves', {})

            for cve_id in cves_found:
                # Get CVE from database
                cve = db.query(CVE).filter_by(cve_id=cve_id).first()
                if not cve:
                    # Fetch and save CVE first
                    cve_data = self.get_cve_details(cve_id)
                    if 'error' not in cve_data:
                        cve = CVE(
                            cve_id=cve_data['cve_id'],
                            description=cve_data.get('description'),
                            cvss_score=cve_data.get('cvss_score'),
                            severity=cve_data.get('severity'),
                            published_date=cve_data.get('published_date'),
                            last_modified=cve_data.get('last_modified'),
                            affected_products=cve_data.get('affected_products', []),
                            references=cve_data.get('references', []),
                            exploit_available=cve_data.get('exploit_available', False),
                            weaponized=cve_data.get('weaponized', False),
                            mass_exploited=cve_data.get('mass_exploited', False),
                            ransomware_used=cve_data.get('ransomware_used', False),
                            epss_score=cve_data.get('epss_score'),
                            services=cve_data.get('services', [])
                        )
                        db.add(cve)
                        db.commit()

                if cve:
                    # Check if already linked
                    existing_link = db.query(ScanCVE).filter_by(
                        scan_id=scan_id,
                        cve_id=cve.id
                    ).first()

                    if not existing_link:
                        # Calculate relevance score
                        relevance_score = self._calculate_relevance_score(
                            cve, detected_tech, detailed_cves.get(cve_id, {})
                        )

                        # Create link
                        scan_cve = ScanCVE(
                            scan_id=scan_id,
                            cve_id=cve.id,
                            relevance_score=relevance_score,
                            matched_technologies=[tech[0] for tech in detected_tech],
                            risk_level=detailed_cves.get(cve_id, {}).get('severity', 'UNKNOWN').lower()
                        )
                        db.add(scan_cve)

            db.commit()
            return True

        except Exception as e:
            logger.error(f"Error linking CVEs to scan: {e}")
            db.rollback()
            return False

        finally:
            db.close()

    def _extract_technologies(self, whatweb_results: Dict, nmap_results: List[Dict]) -> List[tuple]:
        """Extract technologies from scan results"""
        detected_tech = set()

        # Extract from WhatWeb
        if isinstance(whatweb_results, dict):
            # Check main result fields
            if whatweb_results.get('status') == 'ok':
                plugins = whatweb_results.get('plugins', [])
                for plugin in plugins:
                    if isinstance(plugin, dict):
                        name = plugin.get('name', '').lower().strip()
                        version = plugin.get('version', '').strip()
                        if name:
                            detected_tech.add((name, version))

            # Also check raw data
            raw_data = whatweb_results.get('raw', {})
            if isinstance(raw_data, dict):
                for key, value in raw_data.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                name = item.get('name', '').lower().strip()
                                version = item.get('version', '').strip()
                                if name:
                                    detected_tech.add((name, version))
                    elif isinstance(value, str):
                        # Check for common tech keywords in string values
                        tech_keywords = ['apache', 'nginx', 'iis', 'tomcat', 'wordpress', 'drupal', 'joomla']
                        for keyword in tech_keywords:
                            if keyword in value.lower():
                                detected_tech.add((keyword, ''))

        # Extract from Nmap
        if isinstance(nmap_results, list):
            for item in nmap_results:
                if isinstance(item, dict):
                    # Service
                    service = item.get('service', '').lower().strip()
                    version = item.get('version', '').strip()
                    if service:
                        detected_tech.add((service, version))

                    # Product
                    product = item.get('product', '').lower().strip()
                    if product and product != service:
                        detected_tech.add((product, version))

                    # Extra info
                    extra_info = item.get('extrainfo', '').lower()
                    if extra_info:
                        # Try to extract technology from extra info
                        for tech in self.technology_mappings.keys():
                            if tech in extra_info:
                                detected_tech.add((tech, ''))

        # Clean up the results
        cleaned_tech = []
        for tech, version in detected_tech:
            if tech and tech not in ['', 'unknown', 'none']:
                cleaned_tech.append((tech, version))

        return cleaned_tech

    def _get_relevant_cves_from_db(self, detected_tech: List[tuple]) -> List[str]:
        """Get relevant CVEs from database based on detected technologies"""
        db = SessionLocal()

        try:
            relevant_cves = []
            search_terms = set()

            # Build search terms from detected technologies
            for tech_name, tech_version in detected_tech:
                if not tech_name:
                    continue

                search_terms.add(tech_name)

                # Add technology mappings
                if tech_name in self.technology_mappings:
                    search_terms.update(self.technology_mappings[tech_name])

            # Search for CVEs
            for term in search_terms:
                # Search in affected products
                cves = db.query(CVE).filter(
                    CVE.affected_products.contains([term]) |
                    CVE.description.ilike(f'%{term}%') |
                    CVE.services.contains([term])
                ).all()

                for cve in cves:
                    relevant_cves.append(cve.cve_id)

            return list(set(relevant_cves))

        finally:
            db.close()

    def _check_cve_patterns(self, detected_tech: List[tuple]) -> List[str]:
        """Check for known CVE patterns based on technologies"""
        cves = []

        for tech_name, _ in detected_tech:
            if tech_name in self.cve_patterns:
                cves.extend(self.cve_patterns[tech_name])

        return list(set(cves))

    def _parse_nvd_vulnerability(self, vuln: Dict) -> Optional[Dict]:
        """Parse NVD vulnerability data"""
        try:
            if 'cve' not in vuln:
                return None

            cve = vuln['cve']
            cve_id = cve.get('id', '')

            if not cve_id:
                return None

            # Extract description
            description = ''
            if cve.get('descriptions'):
                for desc in cve['descriptions']:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

            # Extract CVSS metrics
            cvss_score = None
            severity = "UNKNOWN"
            exploit_available = False
            weaponized = False
            mass_exploited = False
            ransomware_used = False

            if 'metrics' in cve:
                # Try CVSS v3.1
                if 'cvssMetricV31' in cve['metrics']:
                    metric = cve['metrics']['cvssMetricV31'][0]
                    cvss_data = metric['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    exploit_available = metric.get('exploitabilityScore', 0) > 0

                # Try CVSS v3.0
                elif 'cvssMetricV30' in cve['metrics']:
                    metric = cve['metrics']['cvssMetricV30'][0]
                    cvss_data = metric['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    exploit_available = metric.get('exploitabilityScore', 0) > 0

                # Try CVSS v2.0
                elif 'cvssMetricV2' in cve['metrics']:
                    metric = cve['metrics']['cvssMetricV2'][0]
                    cvss_data = metric['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    severity = self._determine_severity_v2(cvss_score)
                    exploit_available = metric.get('exploitabilityScore', 0) > 0

            # Extract affected products
            affected_products = []
            if 'configurations' in cve:
                for config in cve['configurations']:
                    if 'nodes' in config:
                        for node in config['nodes']:
                            if 'cpeMatch' in node:
                                for cpe_match in node['cpeMatch']:
                                    cpe_uri = cpe_match.get('criteria', '')
                                    if cpe_uri:
                                        # Parse CPE to get product name
                                        parts = cpe_uri.split(':')
                                        if len(parts) >= 5:
                                            product = parts[4]
                                            if product and product != '*' and product not in affected_products:
                                                affected_products.append(product)

            # Extract references
            references = []
            if 'references' in cve:
                for ref in cve['references']:
                    url = ref.get('url', '')
                    if url:
                        references.append(url)

            # Parse dates
            published_date = None
            last_modified = None

            if cve.get('published'):
                try:
                    published_str = cve['published'].replace('Z', '+00:00')
                    published_date = datetime.fromisoformat(published_str)
                except:
                    published_date = datetime.now(timezone.utc)

            if cve.get('lastModified'):
                try:
                    modified_str = cve['lastModified'].replace('Z', '+00:00')
                    last_modified = datetime.fromisoformat(modified_str)
                except:
                    last_modified = datetime.now(timezone.utc)

            # Get EPSS score
            epss_score = self._get_epss_score(cve_id)

            # Determine if weaponized/mass exploited
            weaponized = severity in ['CRITICAL', 'HIGH'] and exploit_available
            mass_exploited = 'exploit' in description.lower() or 'mass' in description.lower()
            ransomware_used = 'ransomware' in description.lower() or 'ransom' in description.lower()

            # Extract services from affected products
            services = []
            for product in affected_products:
                if product:
                    services.append(product.lower().split()[0])

            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published_date': published_date,
                'last_modified': last_modified,
                'affected_products': affected_products,
                'references': references[:10],  # Limit to 10 references
                'exploit_available': exploit_available,
                'weaponized': weaponized,
                'mass_exploited': mass_exploited,
                'ransomware_used': ransomware_used,
                'epss_score': epss_score,
                'services': list(set(services))
            }

        except Exception as e:
            logger.error(f"Error parsing vulnerability: {e}")
            return None

    def _convert_api_to_cve_model(self, api_data: Dict) -> Dict[str, Any]:
        """Convert API data from cve_data_api_helper to CVE model format"""
        try:
            # Parse dates
            published_date = None
            last_modified = None

            if api_data.get('published_date'):
                try:
                    if isinstance(api_data['published_date'], str):
                        published_date = datetime.fromisoformat(api_data['published_date'].replace('Z', '+00:00'))
                except:
                    pass

            if api_data.get('last_modified'):
                try:
                    if isinstance(api_data['last_modified'], str):
                        last_modified = datetime.fromisoformat(api_data['last_modified'].replace('Z', '+00:00'))
                except:
                    pass

            return {
                'cve_id': api_data.get('cve_id', ''),
                'description': api_data.get('description', ''),
                'cvss_score': api_data.get('cvss_score'),
                'severity': api_data.get('severity', 'UNKNOWN'),
                'published_date': published_date,
                'last_modified': last_modified,
                'affected_products': [],
                'references': [],
                'exploit_available': False,
                'weaponized': False,
                'mass_exploited': False,
                'ransomware_used': False,
                'epss_score': api_data.get('epss_score'),
                'services': api_data.get('services', [])
            }
        except Exception as e:
            logger.error(f"Error converting API data: {e}")
            return {'error': str(e)}

    def _calculate_relevance_score(self, cve: CVE, detected_tech: List[tuple], cve_details: Dict) -> float:
        """Calculate relevance score for CVE (0-1)"""
        score = 0.0

        # Base score from severity
        severity_scores = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.5,
            'LOW': 0.2,
            'UNKNOWN': 0.1
        }

        score += severity_scores.get(cve.severity.upper(), 0.1) * 0.4

        # Score from exploit availability
        if cve.exploit_available:
            score += 0.3

        # Score from weaponized/mass exploited
        if cve.weaponized or cve.mass_exploited:
            score += 0.2

        # Score from EPSS
        if cve.epss_score:
            score += cve.epss_score * 0.1

        # Cap at 1.0
        return min(score, 1.0)

    def _calculate_cve_statistics(self, cves: Dict[str, Any]) -> Dict[str, int]:
        """Calculate statistics from CVE data"""
        stats = {
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
            "exploitable": 0,
            "weaponized": 0,
            "mass_exploited": 0,
            "ransomware_used": 0
        }

        for cve_id, cve_data in cves.items():
            severity = cve_data.get('severity', '').upper()

            if severity in ['CRITICAL', 'HIGH']:
                stats["high_risk"] += 1
            elif severity == 'MEDIUM':
                stats["medium_risk"] += 1
            elif severity in ['LOW', 'NONE']:
                stats["low_risk"] += 1

            if cve_data.get('exploit_available'):
                stats["exploitable"] += 1

            if cve_data.get('weaponized'):
                stats["weaponized"] += 1

            if cve_data.get('mass_exploited'):
                stats["mass_exploited"] += 1

            if cve_data.get('ransomware_used'):
                stats["ransomware_used"] += 1

        return stats

    def _get_epss_score(self, cve_id: str) -> Optional[float]:
        """Get EPSS score for CVE"""
        try:
            response = self.session.get(
                f"{self.epss_api_base}?cve={cve_id}",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    return float(data['data'][0].get('epss', 0))

            return None

        except Exception as e:
            logger.warning(f"Failed to get EPSS score for {cve_id}: {e}")
            return None

    def _determine_severity_v2(self, cvss_score: float) -> str:
        """Determine severity for CVSS v2"""
        if cvss_score is None:
            return "UNKNOWN"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0:
            return "LOW"
        else:
            return "NONE"

    def _determine_severity(self, cvss_score: float) -> str:
        """Determine severity based on CVSS score"""
        if cvss_score is None:
            return "UNKNOWN"
        elif cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0:
            return "LOW"
        else:
            return "NONE"

    def background_cve_update(self):
        """Run CVE database update in background"""

        def update_task():
            try:
                result = self.update_cve_database(days_back=7, max_cves=200)
                logger.info(f"Background CVE update completed: {result}")
            except Exception as e:
                logger.error(f"Background CVE update failed: {e}")

        thread = threading.Thread(target=update_task, daemon=True)
        thread.start()


# Global instance
cve_scanner = ComprehensiveCVEScanner()