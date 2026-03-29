# routes/history.py
from datetime import datetime, timezone, timedelta
from flask import request
from Backend.db import SessionLocal
from Backend.models import ScanMain, ScanDelta
from Backend.auth_routes import decode_token_optional


def _parse_time_span(span: str):
    """Convert timeSpan ('alle'|'heute'|'7'|'30') to (start,end) UTC."""
    now = datetime.now(timezone.utc)
    if not span or str(span).lower() == "alle":
        return None, None
    s = str(span).lower()
    if s == "heute":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, now
    if s in ("7", "30"):
        start = now - timedelta(days=int(s))
        return start, now
    return None, None


def _selected_tools_from_body(data: dict):
    """Read tools list from JSON body."""
    allow = {"nmap", "whatweb", "nikto", "zap"}
    raw = data.get("tools")
    if not raw:
        return list(allow)
    if isinstance(raw, list):
        parts = [str(p).strip().lower() for p in raw]
    else:
        parts = [p.strip().lower() for p in str(raw).split(",")]
    return [p for p in parts if p in allow] or list(allow)


def _status_to_result(status: str) -> str:
    """Convert database status to frontend format."""
    if status == "ok":
        return "SUCCESS"
    if status == "error":
        return "FAILED"
    return status.upper() if status else "RUNNING"


def build_history_response(data: dict):
    """Build scan history response with user filtering."""
    target = data.get("targetURL")
    time_span = data.get("timeSpan")
    tools = _selected_tools_from_body(data)

    try:
        limit = int(data.get("limit", 50))
        offset = int(data.get("offset", 0))
    except ValueError:
        return {
            "status": "error",
            "items": [],
            "error": {"code": "BAD_PARAMS", "message": "limit/offset must be integers"}
        }, 400

    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    start_dt, end_dt = _parse_time_span(time_span)

    db = SessionLocal()
    try:
        q = db.query(ScanMain)
        user_id = decode_token_optional(request)

        # Filter by authenticated user
        if user_id:
            q = q.filter(ScanMain.user_id == user_id)
        else:
            # Unauthenticated users see no history
            return {
                "status": "ok",
                "items": [],
                "count": 0,
                "total": 0
            }, 200

        # Apply optional filters
        if target:
            q = q.filter(ScanMain.target == target)
        if start_dt:
            q = q.filter(ScanMain.started_at >= start_dt)
        if end_dt:
            q = q.filter(ScanMain.started_at <= end_dt)

        total = q.count()
        scans = q.order_by(ScanMain.started_at.desc()).offset(offset).limit(limit).all()

        # Build response items
        items = []
        for scan in scans:
            items.append({
                "id": scan.id,
                "target": scan.target,
                "created_at": scan.started_at.isoformat() if scan.started_at else None,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "status": _status_to_result(scan.status),
            })

        return {
            "status": "ok",
            "items": items,
            "count": len(items),
            "total": total
        }, 200

    except Exception as e:
        return {
            "status": "error",
            "items": [],
            "error": {"code": type(e).__name__, "message": str(e)}
        }, 500
    finally:
        db.close()


def save_scan_delta(delta, old_scan_id, new_scan_id):
    """Save delta comparison results to database."""
    db = SessionLocal()
    try:
        for tool, changes in delta.items():
            record = ScanDelta(
                old_scan_id=old_scan_id,
                new_scan_id=new_scan_id,
                tool=tool,
                added=changes.get("added", []),
                removed=changes.get("removed", [])
            )
            db.add(record)
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_delta_history(limit=20):
    """Retrieve recent delta comparisons."""
    db = SessionLocal()
    try:
        deltas = db.query(ScanDelta).order_by(ScanDelta.created_at.desc()).limit(limit).all()
        return [
            {
                "tool": d.tool,
                "old_scan_id": d.old_scan_id,
                "new_scan_id": d.new_scan_id,
                "added": d.added,
                "removed": d.removed,
                "created_at": d.created_at.isoformat()
            }
            for d in deltas
        ]
    finally:
        db.close()