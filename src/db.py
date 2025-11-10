# src/db.py
import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from sqlalchemy import text
from sqlalchemy import inspect, text
import logging

DATABASE_URL = os.getenv("DATABASE_URL") or "sqlite:///data/history.db"

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    url = Column(String(2048), nullable=False)
    domain = Column(String(512), index=True)
    score = Column(Integer)
    verdict = Column(String(64))
    audit = Column(JSON)       # postgresql JSON, sqlite will store text
    meta = Column(JSON)
    note = Column(Text)

class BlacklistEntry(Base):
    __tablename__ = "blacklist"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(512), nullable=False, unique=True, index=True)  # canonical host, lowercase
    source = Column(String(256), nullable=True)   # ex: 'manual', 'github:Phishing.Database'
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    active = Column(Boolean, default=True)

   



logger = logging.getLogger(__name__)

def init_db():
    inspector = inspect(engine)
    try:
        if inspector.has_table("blacklist"):
            try:
                idxs = [i["name"] for i in inspector.get_indexes("blacklist")]
            except Exception:
                idxs = []
            if "ix_blacklist_domain" in idxs:
                with engine.connect() as conn:
                    try:
                        conn.execute(text('DROP INDEX IF EXISTS ix_blacklist_domain'))
                        conn.commit()
                        logger.info("Dropped ix_blacklist_domain")
                    except Exception as e:
                        logger.warning("Não foi possível dropar ix_blacklist_domain: %s", e)
    except Exception as e:
        logger.debug("init_db inspector falhou: %s", e)

    Base.metadata.create_all(bind=engine)

# helpers
def save_scan(session, entry: dict):
    rec = ScanHistory(
        url=entry.get("url"),
        domain=entry.get("domain"),
        score=entry.get("score"),
        verdict=("MALICIOSA" if entry.get("is_suspicious") else "PROVAVELMENTE SEGURO"),
        audit=entry.get("audit"),
        meta={"http_status": entry.get("http_status"), "registered_domain": entry.get("registered_domain")}
    )
    session.add(rec)
    session.commit()
    session.refresh(rec)
    return rec

def add_blacklist_entry(session, domain, source="manual", comment=None):
    domain = domain.strip().lower()
    # remove leading protocol or path
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = (urlparse(domain).hostname or domain).lower()
    # create if not exists
    existing = session.query(BlacklistEntry).filter_by(domain=domain).first()
    if existing:
        existing.active = True
        existing.source = source or existing.source
        if comment:
            existing.comment = comment
        session.commit()
        return existing
    entry = BlacklistEntry(domain=domain, source=source, comment=comment)
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry

def remove_blacklist_entry(session, domain):
    domain = domain.strip().lower()
    existing = session.query(BlacklistEntry).filter_by(domain=domain).first()
    if not existing:
        return None
    # soft delete
    existing.active = False
    session.commit()
    return existing

def list_blacklist(session, active_only=True, limit=1000):
    q = session.query(BlacklistEntry)
    if active_only:
        q = q.filter_by(active=True)
    return q.order_by(BlacklistEntry.created_at.desc()).limit(limit).all()
