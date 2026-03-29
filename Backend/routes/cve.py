# routes/cve.py
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from Backend.db import engine
from Backend.models import CVE  # تغيير من CVEData إلى CVE
from tools.cve_data_api_helper import fetch_cve_data


def get_cve_data(cve_id: str):
    with Session(engine) as session:
        try:
            # Check if CVE already exists in database
            existing_cve = session.query(CVE).filter_by(cve_id=cve_id.upper()).first()  # تغيير من CVEData إلى CVE

            if existing_cve:
                return {
                    "status": "success",
                    "source": "database",
                    "data": existing_cve.to_dict(),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }, 200

            # Fetch from external API
            cve_data = fetch_cve_data(cve_id)

            if 'error' in cve_data:
                return {
                    "status": "failed",
                    "message": cve_data['error'],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }, 404

            # Save to database
            new_cve = CVE(  # تغيير من CVEData إلى CVE
                cve_id=cve_data['cve_id'],
                description=cve_data['description'],  # إزالة title لأنه غير موجود في النموذج
                cvss_score=cve_data['cvss_score'],
                severity=cve_data['severity'],
                published_date=datetime.fromisoformat(
                    cve_data['published_date'].replace('Z', '+00:00')) if cve_data.get('published_date') else None,
                last_modified=datetime.fromisoformat(cve_data['last_modified'].replace('Z', '+00:00')) if cve_data.get(
                    'last_modified') else None,
                # إضافة الحقول الجديدة
                epss_score=cve_data.get('epss_score'),
                services=cve_data.get('services')
            )

            session.add(new_cve)
            session.commit()

            return {
                "status": "success",
                "source": "api",
                "data": new_cve.to_dict(),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }, 200

        except Exception as e:
            session.rollback()
            return {
                "status": "failed",
                "message": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }, 500