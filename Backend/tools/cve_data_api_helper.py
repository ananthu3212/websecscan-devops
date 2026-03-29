import os
import requests
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()


class CVEService:
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.circl_api_base = "https://cve.circl.lu/api/cve"

    def fetch_cve_data(self, cve_id):
        """Fetch CVE data from NVD API (primary) with fallback to CIRCL"""
        try:
            # Try NVD API first
            nvd_data = self._fetch_from_nvd(cve_id)
            if nvd_data:
                return self._parse_nvd_data(nvd_data)

            # Fallback to CIRCL API
            circl_data = self._fetch_from_circl(cve_id)
            if circl_data:
                return self._parse_circl_data(circl_data)

            return {"error": f"CVE {cve_id} not found"}

        except Exception as e:
            return {"error": f"Failed to fetch CVE data: {str(e)}"}

    def _fetch_from_nvd(self, cve_id):
        """Fetch CVE data from NVD API"""
        try:
            url = f"{self.nvd_api_base}?cveId={cve_id}"
            headers = {
                'User-Agent': 'WebSecScan/1.0',
                'Accept': 'application/json'
            }

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"NVD API error: {e}")
            return None

    def _fetch_from_circl(self, cve_id):
        """Fetch CVE data from CIRCL API (fallback)"""
        try:
            url = f"{self.circl_api_base}/{cve_id}"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"CIRCL API error: {e}")
            return None

    def _parse_nvd_data(self, data):
        """Parse NVD API response"""
        if not data.get('vulnerabilities'):
            return None

        vuln = data['vulnerabilities'][0]['cve']

        # Extract CVSS score if available
        cvss_score = None
        severity = "UNKNOWN"

        if 'metrics' in vuln:
            if 'cvssMetricV31' in vuln['metrics']:
                cvss_metric = vuln['metrics']['cvssMetricV31'][0]
                cvss_score = cvss_metric['cvssData']['baseScore']
                severity = cvss_metric['cvssData']['baseSeverity']
            elif 'cvssMetricV30' in vuln['metrics']:
                cvss_metric = vuln['metrics']['cvssMetricV30'][0]
                cvss_score = cvss_metric['cvssData']['baseScore']
                severity = cvss_metric['cvssData']['baseSeverity']
            elif 'cvssMetricV2' in vuln['metrics']:
                cvss_metric = vuln['metrics']['cvssMetricV2'][0]
                cvss_score = cvss_metric['cvssData']['baseScore']
                severity = self._determine_severity_v2(cvss_score)

        # Parse dates
        published_date = None
        last_modified = None

        if vuln.get('published'):
            try:
                published_date = vuln['published'].replace('Z', '+00:00')
            except:
                published_date = vuln['published']

        if vuln.get('lastModified'):
            try:
                last_modified = vuln['lastModified'].replace('Z', '+00:00')
            except:
                last_modified = vuln['lastModified']

        parsed_data = {
            'cve_id': vuln['id'],
            'title': vuln['id'],
            'description': vuln['descriptions'][0]['value'] if vuln.get('descriptions') else 'No description available',
            'cvss_score': cvss_score,
            'severity': severity,
            'published_date': published_date,
            'last_modified': last_modified
        }
        
        # Add new fields
        parsed_data['epss_score'] = get_epss_score(vuln['id'])
        parsed_data['services'] = get_related_services(vuln['id'])
        
        return parsed_data

    def _parse_circl_data(self, data):
        """Parse CIRCL API response"""
        if not data:
            return None

        # Parse dates from CIRCL format
        published_date = None
        last_modified = None

        if data.get('Published'):
            try:
                published_date = data['Published'].replace('Z', '+00:00')
            except:
                published_date = data['Published']

        if data.get('Modified'):
            try:
                last_modified = data['Modified'].replace('Z', '+00:00')
            except:
                last_modified = data['Modified']

        parsed_data = {
            'cve_id': data.get('id'),
            'title': data.get('id'),
            'description': data.get('summary', 'No description available'),
            'cvss_score': data.get('cvss'),
            'severity': self._determine_severity(data.get('cvss')),
            'published_date': published_date,
            'last_modified': last_modified
        }
        
        # Add new fields
        parsed_data['epss_score'] = get_epss_score(data.get('id'))
        parsed_data['services'] = get_related_services(data.get('id'))
        
        return parsed_data

    def _determine_severity(self, cvss_score):
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

    def _determine_severity_v2(self, cvss_score):
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


def get_epss_score(cve_id):
    """
    جلب EPSS score من API خارجي
    """
    try:
        # استخدام EPSS API الرسمي
        response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('data'):
                return float(data['data'][0].get('epss', 0))
        return None
    except Exception as e:
        print(f"EPSS API error for {cve_id}: {e}")
        return None


def get_related_services(cve_id):
    """
    تحديد الخدمات المتأثرة بـ CVE
    """
    try:
        # قاعدة بيانات محلية للخدمات الشائعة
        services_mapping = {
            "CVE-2021-42013": ["apache", "httpd", "web-server"],
            "CVE-2021-44228": ["log4j", "java", "logging"],
            "CVE-2017-5638": ["struts", "apache", "java"],
        }
        
        return services_mapping.get(cve_id, ["unknown"])
        
    except Exception as e:
        print(f"Services detection error for {cve_id}: {e}")
        return ["unknown"]


# Global instance
cve_service = CVEService()


# Helper function for the routes
def fetch_cve_data(cve_id):
    return cve_service.fetch_cve_data(cve_id)