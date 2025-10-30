import re
import socket
import ssl
from urllib.parse import urlparse

# Carrega blacklist simples a partir de arquivo (one domain per line)
def load_blacklist(path="data/blacklist.txt"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()

def get_domain_from_url(url):
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        return parsed.hostname.lower()
    except Exception:
        return None

def check_basic_indicators(url):
    """
    Retorna (suspicious: bool, reasons: list[str])
    """
    reasons = []
    suspicious = False

    domain = get_domain_from_url(url)
    if not domain:
        return True, ["URL inválida / não foi possível extrair domínio"]

    # 1) números no domínio (ex: paypa1.com)
    # consider only the registered domain portion (this is a simple heuristic)
    if re.search(r'\d', domain):
        suspicious = True
        reasons.append("Presença de números no domínio")

    # 2) subdomínios excessivos (heurística: > 3 pontos)
    if domain.count('.') > 3:
        suspicious = True
        reasons.append("Uso excessivo de subdomínios")

    # 3) caracteres especiais na URL
    # allow standard domain chars, path may have many, so check domain+path for odd chars
    if re.search(r'[^a-zA-Z0-9\.\-/:?#=@&_%\+\[\]\(\)]', url):
        suspicious = True
        reasons.append("Caracteres especiais suspeitos na URL")

    # 4) comprimento excessivo
    if len(url) > 200:
        suspicious = True
        reasons.append("URL muito longa")

    return suspicious, reasons

def check_blacklist(url, blacklist_set):
    domain = get_domain_from_url(url)
    if not domain:
        return False, None
    # compara domínio exato e também termina com (para subdomínios)
    domain_lower = domain.lower()
    if domain_lower in blacklist_set:
        return True, f"Domínio '{domain}' presente na blacklist local"
    for bad in blacklist_set:
        if domain_lower.endswith("." + bad):
            return True, f"Domínio '{domain}' corresponde a subdomínio de '{bad}' na blacklist"
    return False, None

def check_ssl_certificate(url, timeout=5):
    """
    Tenta obter informações básicas do certificado.
    Retorna (ok: bool, msg: str)
    """
    domain = get_domain_from_url(url)
    if not domain:
        return False, "Domínio inválido para checagem SSL"

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', (("issuer", ""),)))
                not_after = cert.get('notAfter')
                # Simplificado: se obtivemos cert sem exceção, consideramos válido
                return True, f"Certificado OK (emissor: {issuer.get('organizationName', issuer.get('commonName',''))}, expira: {not_after})"
    except Exception as e:
        return False, f"Erro ao validar certificado SSL/TLS: {e}"

def analyze_url(url, blacklist_path="data/blacklist.txt"):
    """
    Retorna dicionário com:
      - url, domain, is_suspicious (bool), score (0-100), detalhes (list)
    Heurísticas simples: cada indicador soma pontos.
    """
    details = []
    blacklist = load_blacklist(blacklist_path)

    suspicious_basic, reasons_basic = check_basic_indicators(url)
    if reasons_basic:
        details.extend(reasons_basic)

    blacklisted, black_msg = check_blacklist(url, blacklist)
    if blacklisted:
        details.append(black_msg)

    ssl_ok, ssl_msg = check_ssl_certificate(url)
    if not ssl_ok:
        details.append(ssl_msg)
    else:
        details.append(ssl_msg)

    # score simples: começar 0; somar por indicador
    score = 0
    if blacklisted:
        score += 70
    if suspicious_basic:
        score += 20
    if not ssl_ok:
        score += 20
    score = min(score, 100)

    is_suspicious = score >= 50

    return {
        "url": url,
        "domain": get_domain_from_url(url),
        "is_suspicious": is_suspicious,
        "score": score,
        "detalhes": details or ["Nenhuma característica suspeita encontrada"]
    }

# se executado diretamente permite testes rápidos
if __name__ == "__main__":
    tests = [
        "http://example.com",
        "http://paypa1.com/login",
        "http://very.long.subdomain.login.paypal.example.com",
        "http://bit.ly/abcdef"
    ]
    for t in tests:
        r = analyze_url(t)
        print(t, "->", r["score"], r["detalhes"])
