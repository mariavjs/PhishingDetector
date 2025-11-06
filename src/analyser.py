# analyser.py
import re
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

import tldextract
import requests
from bs4 import BeautifulSoup

# Carrega blacklist simples a partir de arquivo (one domain per line)
import os

def load_blacklist(path=None):
    # Se não passar path, usa data/blacklist.txt relativa a este ficheiro analyser.py
    if path is None:
        here = os.path.dirname(__file__)
        path = os.path.join(here, "data", "blacklist.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#"))
    except FileNotFoundError:
        # opcional: log para facilitar debug
        print(f"[WARN] Blacklist não encontrada em: {path}")
        return set()


def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url

def get_domain_from_url(url):
    """
    Retorna o hostname (ex: a.b.example.com) e o 'registered_domain' (example.com)
    """
    try:
        nurl = normalize_url(url)
        parsed = urlparse(nurl)
        if not parsed.hostname:
            return None, None
        hostname = parsed.hostname.lower()
        ext = tldextract.extract(hostname)
        registered = None
        if ext.suffix:
            registered = ext.domain + "." + ext.suffix
        else:
            registered = ext.domain
        return hostname, registered
    except Exception:
        return None, None

def check_basic_indicators(url):
    """
    Retorna (suspicious: bool, reasons: list[str])
    """
    reasons = []
    suspicious = False

    hostname, registered = get_domain_from_url(url)
    if not hostname:
        return True, ["URL inválida / não foi possível extrair domínio"]

    # 1) números no domínio registrado (ex: paypa1.com)
    if registered and re.search(r'\d', registered):
        suspicious = True
        reasons.append("Presença de números no domínio registrado (possível typosquatting)")

    # 2) subdomínios excessivos (heurística: > 3 níveis além do registered)
    if hostname.count('.') - (registered.count('.') if registered else 0) > 2:
        suspicious = True
        reasons.append("Uso excessivo de subdomínios")

    # 3) caracteres especiais na URL (fora os usuais)
    # Permitimos os caracteres padrão de path/query; aqui procuramos por caracteres óbvios estranhos
    if re.search(r"[<>\\\^\{\}\|`]", url):
        suspicious = True
        reasons.append("Caracteres especiais não usuais encontradas na URL")

    # 4) comprimento excessivo
    if len(url) > 200:
        suspicious = True
        reasons.append("URL muito longa")

    # 5) domínio muito novo/curto (será complementado em B com whois)
    return suspicious, reasons
from urllib.parse import urlparse

def host_only(s):
    # remove protocolo/paths e "www."
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

def check_blacklist(url, blacklist_set):
    hostname, registered = get_domain_from_url(url)
    if not hostname:
        return False, None
    domain_lower = host_only(hostname)
    reg_lower = (registered or "").lower()
    if domain_lower in blacklist_set or reg_lower in blacklist_set:
        return True, f"Domínio '{hostname}' ou '{registered}' está na blacklist local"
    for bad in blacklist_set:
        if domain_lower.endswith("." + bad):
            return True, f"Domínio '{hostname}' corresponde a subdomínio de '{bad}' na blacklist"
    return False, None


def check_ssl_certificate(url, timeout=5):
    """
    Tenta obter informações básicas do certificado.
    Retorna (ok: bool, msg: str).
    Não lança exceções - sempre captura e devolve mensagem.
    """
    hostname, _ = get_domain_from_url(url)
    if not hostname:
        return False, "Domínio inválido para checagem SSL"

    try:
        ctx = ssl.create_default_context()
        # Não usamos verify here because we only want peer cert; socket timeout to avoid hang
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # issuer e subject podem ser listas; extraímos commonName / orgName quando possível
                def extract_name(tuples):
                    # tuples example: (('commonName', 'Let's Encrypt Authority X3'),)
                    if not tuples:
                        return ""
                    # tuples may be nested lists
                    try:
                        for part in tuples:
                            for k, v in part:
                                if k.lower() in ("organizationname", "organization", "org", "o"):
                                    return v
                                if k.lower() in ("commonname", "cn"):
                                    return v
                    except Exception:
                        pass
                    # fallback stringify
                    try:
                        return str(tuples)
                    except Exception:
                        return ""
                issuer = extract_name(cert.get("issuer"))
                subject = extract_name(cert.get("subject"))
                not_after = cert.get('notAfter')
                # tenta parse de data para formato legível
                exp_str = not_after
                try:
                    if not_after:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp_str = exp.strftime("%Y-%m-%d")
                except Exception:
                    pass
                msg = f"Certificado encontrado (issuer='{issuer}', subject='{subject}', expira: {exp_str})"
                return True, msg
    except Exception as e:
        return False, f"Erro ao validar certificado SSL/TLS: {e}"

def fetch_page_and_check_forms(url, timeout=6):
    """
    Tenta buscar a página e detecta formulários que peçam senha/credenciais.
    Retorna (found_suspicious:bool, reasons:list[str], http_status:int|None)
    """
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
            # procura por placeholders/names/labels com palavras-suspeitas
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

def analyze_url(url, blacklist_path="data/blacklist.txt"):
    """
    Retorna dicionário com:
      - url, domain, registered_domain, is_suspicious (bool), score (0-100), detalhes (list)
    """
    details = []
    blacklist = load_blacklist(blacklist_path)
    hostname, registered = get_domain_from_url(url)

    # basic indicators
    suspicious_basic, reasons_basic = check_basic_indicators(url)
    if reasons_basic:
        details.extend(reasons_basic)

    # blacklist
    blacklisted, black_msg = check_blacklist(url, blacklist)
    if blacklisted and black_msg:
        details.append(black_msg)

    # SSL
    ssl_ok, ssl_msg = check_ssl_certificate(url)
    details.append(ssl_msg)

    # fetch page and check forms
    content_susp, content_reasons, http_status = fetch_page_and_check_forms(url)
    if content_reasons:
        details.extend(content_reasons)

    # scoring simples
    score = 0
    if blacklisted:
        score += 70
    if suspicious_basic:
        score += 20
    if not ssl_ok:
        score += 10
    if content_susp:
        score += 20
    # cap
    score = min(score, 100)

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
        "http_status": http_status
    }

if __name__ == "__main__":
    tests = [
        "example.com",
        "paypa1.com/login",
        "very.long.subdomain.login.paypal.example.com",
        "bit.ly/abcdef"
    ]
    for t in tests:
        r = analyze_url(t)
        print(t, "->", r["score"], r["detalhes"])
