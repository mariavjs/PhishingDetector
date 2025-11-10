# src/analyser.py
import re
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
import os

from sync_utils import check_google_safebrowsing

import tldextract
import requests
from bs4 import BeautifulSoup
import dns.resolver


# Optional imports - used if installed; code will fallback se não existir
try:
    import whois as whois_lib
except Exception:
    whois_lib = None

try:
    from rapidfuzz import fuzz
except Exception:
    fuzz = None

# DB access for blacklist snapshot
try:
    from db import SessionLocal, BlacklistEntry
except Exception:
    SessionLocal = None
    BlacklistEntry = None

# ------------------ DDNS suffixes cache/loader (module-level) ------------------
DDNS_SUFFIXES = None

def load_ddns_suffixes(path: str | None = None):
    """
    Carrega (lazy) uma lista de sufixos de serviços de DNS dinâmico (ex: no-ip.org, dyndns.org).
    Retorna list[str]. Usa cache em DDNS_SUFFIXES para não reabrir ficheiro repetidamente.
    """
    global DDNS_SUFFIXES
    if DDNS_SUFFIXES is not None:
        return DDNS_SUFFIXES

    here = os.path.dirname(__file__)
    p = path or os.path.join(here, "data", "ddns_suffixes.txt")
    try:
        with open(p, "r", encoding="utf-8") as f:
            DDNS_SUFFIXES = [ln.strip().lower() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except Exception:
        DDNS_SUFFIXES = []
    return DDNS_SUFFIXES

# ---------------------------------------------------------------------
# Utilities: normalize/parse
# ---------------------------------------------------------------------
def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url

def get_domain_from_url(url):
    """
    Retorna (hostname, registered_domain)
    """
    try:
        nurl = normalize_url(url)
        parsed = urlparse(nurl)
        if not parsed.hostname:
            return None, None
        hostname = parsed.hostname.lower()
        ext = tldextract.extract(hostname)
        if ext.suffix:
            registered = ext.domain + "." + ext.suffix
        else:
            registered = ext.domain
        return hostname, registered
    except Exception:
        return None, None

def host_only(s):
    if not s:
        return s
    try:
        p = urlparse(s if s.startswith("http") else "http://" + s)
        h = (p.hostname or "").lower()
        if h.startswith("www."):
            h = h[4:]
        return h
    except:
        return s.lower()

# ---------------------------------------------------------------------
# Blacklist loading: from DB (preferred) with fallback to file
# ---------------------------------------------------------------------
def load_blacklist_from_db():
    if SessionLocal is None:
        return set()
    s = SessionLocal()
    try:
        rows = s.query(BlacklistEntry).filter_by(active=True).all()
        return set(r.domain for r in rows if r and r.domain)
    except Exception:
        return set()
    finally:
        s.close()

def load_blacklist_file(path=None):
    if path is None:
        here = os.path.dirname(__file__)
        path = os.path.join(here, "data", "blacklist.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#"))
    except FileNotFoundError:
        return set()

def load_blacklist(prefer_db=True, file_path=None):
    if prefer_db:
        dbset = load_blacklist_from_db()
        if dbset:
            return dbset
    return load_blacklist_file(file_path)

# ---------------------------------------------------------------------
# Basic heuristics
# ---------------------------------------------------------------------
def check_basic_indicators(url):
    reasons = []
    suspicious = False

    hostname, registered = get_domain_from_url(url)
    if not hostname:
        return True, ["URL inválida / não foi possível extrair domínio"]

    if registered and re.search(r'\d', registered):
        suspicious = True
        reasons.append("Presença de números no domínio registrado (possível typosquatting)")

    if hostname.count('.') - (registered.count('.') if registered else 0) > 2:
        suspicious = True
        reasons.append("Uso excessivo de subdomínios")

    if re.search(r"[<>\\\^\{\}\|`]", url):
        suspicious = True
        reasons.append("Caracteres especiais não usuais encontradas na URL")

    if len(url) > 200:
        suspicious = True
        reasons.append("URL muito longa")

    return suspicious, reasons

# ---------------------------------------------------------------------
# Blacklist check (works with a set of strings)
# ---------------------------------------------------------------------
def check_blacklist(url, blacklist_set):
    hostname, registered = get_domain_from_url(url)
    if not hostname:
        return False, None
    domain_lower = host_only(hostname)
    reg_lower = (registered or "").lower()
    if domain_lower in blacklist_set or reg_lower in blacklist_set:
        return True, f"Domínio '{hostname}' ou '{registered}' está na blacklist"
    for bad in blacklist_set:
        if domain_lower.endswith("." + bad):
            return True, f"Domínio '{hostname}' corresponde a subdomínio de '{bad}' na blacklist"
    return False, None

# ---------------------------------------------------------------------
# SSL certificate check
# ---------------------------------------------------------------------
def check_ssl_certificate(url, timeout=5):
    hostname, _ = get_domain_from_url(url)
    if not hostname:
        return {"ok": False, "error": "Domínio inválido"}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                not_after = cert.get("notAfter")
                exp = None
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
                    except Exception:
                        exp = not_after

                # domínio no CN
                cn = subject.get("commonName", "")
                domain_mismatch = hostname not in cn

                return {
                    "ok": True,
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "subject": cn,
                    "expires": exp,
                    "domain_mismatch": domain_mismatch,
                }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------
# Fetch page content + detect forms / keywords
# ---------------------------------------------------------------------
def fetch_page_and_check_forms(url, timeout=6):
    try:
        nurl = normalize_url(url)
        r = requests.get(nurl, timeout=timeout, headers={"User-Agent": "phish-detector/1.0"})
        status = r.status_code
        reasons = []
        if r.status_code >= 400:
            return False, ["Página retornou erro HTTP"], status
        text = r.text or ""
        soup = BeautifulSoup(text, "html.parser")
        forms = soup.find_all("form")
        for f in forms:
            if f.find("input", {"type": "password"}):
                reasons.append("Formulário com campo de senha detectado")
            form_text = (f.get_text(" ") or "").lower()
            if any(k in form_text for k in ["senha", "password", "login", "confirme", "verificar", "bank"]):
                reasons.append("Formulário contém texto que pede credenciais")
        page_text = (soup.get_text(" ") or "").lower()
        if any(k in page_text for k in ["senha", "password", "login", "bank", "account", "confirme", "verificar"]):
            reasons.append("Conteúdo da página contém palavras que podem indicar pedido de credenciais")
        reasons = list(dict.fromkeys(reasons))
        return (len(reasons) > 0), reasons or [], status
    except Exception as e:
        return False, [f"Não foi possível buscar/parsear página: {e}"], None

# ---------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------
def check_redirects(url, timeout=6):
    try:
        nurl = normalize_url(url)
        r = requests.get(nurl, timeout=timeout, headers={"User-Agent": "phish-detector/1.0"}, allow_redirects=True)
        history = r.history
        hosts = []
        for h in history:
            try:
                ph = urlparse(h.url).hostname
                if ph:
                    hosts.append(ph.lower())
            except:
                pass
        return hosts, r.url, r.status_code
    except Exception:
        return [], None, None

# ---------------------------------------------------------------------
# WHOIS (best-effort)
# ---------------------------------------------------------------------
def whois_info(registered_domain):
    if whois_lib is None or not registered_domain:
        return None
    try:
        w = whois_lib.whois(registered_domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None
        if isinstance(creation, str):
            try:
                creation = datetime.fromisoformat(creation)
            except Exception:
                pass
        if isinstance(creation, datetime):
            age_days = (datetime.utcnow() - creation).days
            return {"creation_date": creation, "age_days": age_days}
    except Exception:
        return None
    return None

# ---------------------------------------------------------------------
# Typosquatting / similarity (best-effort)
# ---------------------------------------------------------------------
COMMON_BRANDS = [
    "google.com", "facebook.com", "paypal.com", "apple.com", "microsoft.com",
    "amazon.com", "bankofamerica.com"
]

def typosquat_score(registered_domain, brands=COMMON_BRANDS):
    if not registered_domain:
        return None, 0
    best = None
    best_score = 0
    if fuzz:
        for b in brands:
            s = fuzz.ratio(registered_domain, b)
            if s > best_score:
                best_score = int(s)
                best = b
    else:
        for b in brands:
            s = 100 if registered_domain == b else (80 if b.split(".")[0] in registered_domain else 0)
            if s > best_score:
                best_score = s
                best = b
    return best, best_score

# ---------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------
def add_audit(audit_list, rule_name, points, reason):
    audit_list.append({"rule": rule_name, "points": int(points), "reason": reason})



def get_dns_records(hostname):
    """Retorna A, MX e CNAME de um domínio."""
    info = {}
    try:
        a = [r.to_text() for r in dns.resolver.resolve(hostname, "A", lifetime=3)]
        info["A"] = a
    except Exception:
        info["A"] = []
    try:
        mx = [r.exchange.to_text() for r in dns.resolver.resolve(hostname, "MX", lifetime=3)]
        info["MX"] = mx
    except Exception:
        info["MX"] = []
    try:
        cname = [r.to_text() for r in dns.resolver.resolve(hostname, "CNAME", lifetime=3)]
        info["CNAME"] = cname
    except Exception:
        info["CNAME"] = []
    return info

# ---------------------------------------------------------------------
# Main analyze 
# ---------------------------------------------------------------------
def analyze_url_with_b(url, prefer_db=True, blacklist_file=None):
    details = []
    audit = []
    meta = {}
    http_status = None

    # load blacklist (db preferred)
    blacklist = load_blacklist(prefer_db=prefer_db, file_path=blacklist_file)

    hostname, registered = get_domain_from_url(url)

    # basic
    suspicious_basic, reasons_basic = check_basic_indicators(url)
    if reasons_basic:
        details.extend(reasons_basic)
    add_audit(audit, "basic_indicators", 20 if suspicious_basic else 0,
              "; ".join(reasons_basic) if reasons_basic else "none")

    # blacklist
    blacklisted, black_msg = check_blacklist(url, blacklist)
    if blacklisted and black_msg:
        details.append(black_msg)
        add_audit(audit, "blacklist", 70, black_msg)
    else:
        add_audit(audit, "blacklist", 0, "not listed")

    # ssl
    ssl_meta = check_ssl_certificate(url)
    meta["ssl"] = ssl_meta
    if ssl_meta.get("ok"):
        msg = f"Cert SSL por {ssl_meta.get('issuer')} (expira {ssl_meta.get('expires')})"
        if ssl_meta.get("domain_mismatch"):
            msg += " — domínio não corresponde ao certificado"
            add_audit(audit, "ssl", 20, msg)
        else:
            add_audit(audit, "ssl", 0, msg)
    else:
        msg = f"Erro SSL: {ssl_meta.get('error')}"
        add_audit(audit, "ssl", 10, msg)
    details.append(msg)


    # whois
    who = whois_info(registered)
    if who:
        details.append(f"Domínio criado há {who['age_days']} dias (creation: {who['creation_date']})")
        add_audit(audit, "whois_age", 15 if who["age_days"] <= 30 else 0, f"{who['age_days']} dias")
        meta["whois"] = who
    else:
        details.append("WHOIS indisponível ou não suportado")
        add_audit(audit, "whois_age", 0, "WHOIS indisponível")

    # dns info
    if hostname:
        dns_info = get_dns_records(hostname)
        meta["dns"] = dns_info
        if any("no-ip" in r or "dyndns" in r for v in dns_info.values() for r in v):
            details.append("Domínio usa DNS dinâmico (no-ip, dyndns, etc.)")
            add_audit(audit, "dns_dynamic", 20, "serviço DDNS detectado")
        else:
            add_audit(audit, "dns_dynamic", 0, "dns normal")


    # typosquat
    best_brand, ratio = typosquat_score(registered)
    if ratio and ratio >= 80:
        details.append(f"Dominio similar a {best_brand} (similaridade {ratio}%) — possível typosquatting")
        add_audit(audit, "typosquat", 30, f"similaridade {ratio}% com {best_brand}")
    else:
        add_audit(audit, "typosquat", 0, f"max sim {ratio}%")

    # redirects
    redirect_hosts, final_url, final_status = check_redirects(url)
    if redirect_hosts:
        domain_changes = sum(1 for h in redirect_hosts if h and h != hostname)
        if domain_changes > 0:
            details.append(f"Redirecionamento entre domínios detectado: {redirect_hosts} -> {final_url}")
            add_audit(audit, "redirects", 20, f"{domain_changes} troca(s) de domínio")
        else:
            add_audit(audit, "redirects", 0, "redirecionamentos no mesmo domínio")
    else:
        add_audit(audit, "redirects", 0, "sem redirecionamentos detectados")

    meta["redirect_final"] = f"{final_status} → {final_url or '(sem redirecionamento)'}"
    meta.setdefault("whois", who or {})


    # content/forms
    content_susp, content_reasons, http_status = fetch_page_and_check_forms(url)
    if content_reasons:
        details.extend(content_reasons)
    add_audit(audit, "content_forms", 20 if content_susp else 0,
              "; ".join(content_reasons) if content_reasons else "none")

    # DDNS check (uses module-level loader)
    ddns_list = load_ddns_suffixes()
    if registered and ddns_list and any(registered.endswith(suf) for suf in ddns_list):
        details.append("Domínio registrado em serviço de DNS dinâmico (possível abuse)")
        add_audit(audit, "ddns", 20, f"registered endswith ddns suffix")

    # GSB: Google Safe Browsing lookup (opcional)
    gsb_key = os.getenv("GOOGLE_SAFEBROWSING_KEY")
    if gsb_key:
        try:
            gsb_res = check_google_safebrowsing(normalize_url(url), gsb_key)
            meta["gsb"] = gsb_res
            if gsb_res.get("match"):
                details.append("Google Safe Browsing — URL encontrada em lista de ameaças")
                add_audit(audit, "google_safebrowsing", 80, "Google Safe Browsing match")
            else:
                add_audit(audit, "google_safebrowsing", 0, "no match")
        except Exception as e:
            meta["gsb"] = {"match": False, "error": str(e)}
            add_audit(audit, "google_safebrowsing", 0, f"err: {e}")
    else:
        add_audit(audit, "google_safebrowsing", 0, "no api key configured")

    # final scoring
    score = sum(a["points"] for a in audit)
    score = max(0, min(score, 100))
    is_suspicious = score >= 50
    if not details:
        details = ["Nenhuma característica suspeita encontrada"]

    return {
        "url": normalize_url(url),
        "domain": hostname,
        "registered_domain": registered,
        "is_suspicious": is_suspicious,
        "score": score,
        "detalhes": details,
        "http_status": http_status,
        "audit": audit,
        "meta": meta
    }

# Keep backward-compatible name
def analyze_url(url, *args, **kwargs):
    return analyze_url_with_b(url, *args, **kwargs)

if __name__ == "__main__":
    tests = ["example.com", "paypa1.com/login", "very.long.subdomain.login.paypal.example.com", "bit.ly/abcdef"]
    for t in tests:
        r = analyze_url_with_b(t)
        print(t, "->", r["score"], r["detalhes"])
