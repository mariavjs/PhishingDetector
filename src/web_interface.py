# src/web_interface.py
import streamlit as st
from datetime import datetime
import os
import requests

from analyser import analyze_url_with_b, load_blacklist_file, load_blacklist_from_db
from db import init_db, SessionLocal, save_scan, add_blacklist_entry, remove_blacklist_entry, list_blacklist

# initialize DB/tables
init_db()

st.set_page_config(page_title="Detector de Phishing - Conceito B", layout="centered")
st.title("Detector de Phishing — Conceito B")
st.write("Insira uma URL para análise (heurísticas + blacklist no DB).")

url = st.text_input("URL", value="example.com")

# ----------------- Admin sidebar -----------------
st.sidebar.title("Admin")
with st.sidebar.expander("Gerenciar blacklist"):
    with st.form("add_blacklist"):
        domain = st.text_input("Domínio (ex: bad.com)")
        comment = st.text_input("Comentário (opcional)")
        if st.form_submit_button("Adicionar"):
            if not domain:
                st.warning("Digite um domínio válido.")
            else:
                with SessionLocal() as s:
                    e = add_blacklist_entry(s, domain, source="manual", comment=comment)
                    st.success(f"Adicionado/Atualizado: {e.domain}")

    st.write("---")
    with st.form("remove_blacklist"):
        domain_r = st.text_input("Domínio a remover")
        if st.form_submit_button("Remover"):
            if not domain_r:
                st.warning("Digite um domínio válido.")
            else:
                with SessionLocal() as s:
                    e = remove_blacklist_entry(s, domain_r)
                    if e:
                        st.success(f"Removido (desativado): {e.domain}")
                    else:
                        st.warning("Entrada não encontrada")

    st.write("---")
    if st.button("Sincronizar blacklist do GitHub (Phishing.Database)"):
        with st.spinner("Sincronizando..."):
            try:
                RAW = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
                r = requests.get(RAW, timeout=15)
                if r.status_code == 200:
                    lines = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
                    added = 0
                    with SessionLocal() as s:
                        for ln in lines:
                            # keep only hostname when possible
                            if ln.startswith("http"):
                                from urllib.parse import urlparse
                                ln = (urlparse(ln).hostname or ln)
                            try:
                                add_blacklist_entry(s, ln, source="github", comment="sync from Phishing.Database")
                                added += 1
                            except Exception:
                                continue
                    st.success(f"Sincronizado: {added} entradas (tentadas)")
                else:
                    st.error(f"Falha ao baixar: status {r.status_code}")
            except Exception as ex:
                st.error(f"Erro ao sincronizar: {ex}")

    st.write("Últimas entradas (ativa):")
    with SessionLocal() as s:
        rows = list_blacklist(s, limit=50)
        for r in rows[:50]:
            st.write(f"- {r.domain} (src: {r.source}, {r.created_at.date()})")

# ----------------- Main analysis -----------------
if st.button("Analisar"):
    if not url or url.strip() == "":
        st.warning("Digite uma URL válida.")
    else:
        with st.spinner("Analisando..."):
            try:
                # prefer DB blacklist
                result = analyze_url_with_b(url, prefer_db=True)
            except Exception as e:
                st.error(f"Ocorreu um erro ao analisar a URL: {e}")
                result = None

        if result:
            # save to DB
            try:
                with SessionLocal() as session:
                    rec = save_scan(session, result)
                    st.write("Scan salvo (id):", rec.id)
            except Exception as e:
                st.warning(f"Não foi possível salvar scan no DB: {e}")

            # show result
            score = result.get("score", 0)
            if result.get("is_suspicious"):
                st.error(f"Risco: {score} / 100 — Suspeito")
            else:
                st.success(f"Risco: {score} / 100 — Provavelmente seguro")
            st.subheader("Detalhes da análise")
            for d in result.get("detalhes", []):
                st.write("- " + d)

            st.subheader("Audit trail (regras aplicadas)")
            for a in result.get("audit", []):
                st.write(f"- {a['rule']}: +{a['points']} pontos — {a['reason']}")

            st.write("---")
            st.write("Domínio:", result.get("domain"))
            st.write("Domínio registrado:", result.get("registered_domain"))
            st.write("HTTP status (se obtido):", result.get("http_status"))
            st.write("URL normalizada:", result.get("url"))

# Quick dashboard: counts of last 20 scans
st.write("---")
st.subheader("Últimos scans (resumo)")
try:
    import pandas as pd
    with SessionLocal() as s:
        from sqlalchemy import select
        rows = s.execute(select("url","domain","score","verdict").select_from("scan_history").limit(20)).all()
        # fallback: try to query via ORM if above fails
        if not rows:
            q = s.query("scan_history").limit(20)
            rows = []
    # show simple message (if DB empty)
    st.write("Histórico disponível no banco (use a sidebar Admin para ver blacklist).")
except Exception:
    # não crítico
    pass
