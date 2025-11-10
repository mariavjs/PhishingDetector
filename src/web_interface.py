import streamlit as st
from datetime import datetime
import os, requests, pandas as pd, matplotlib.pyplot as plt
import traceback
import time

from analyser import analyze_url_with_b
from db import (
    init_db, SessionLocal, save_scan, add_blacklist_entry,
    remove_blacklist_entry, list_blacklist, ScanHistory
)

# ----------------- setup -----------------
init_db()
st.set_page_config(page_title="Detector de Phishing - Conceito B", layout="centered")

# ----------------- Função auxiliar -----------------
def render_technical_info(meta):
    st.subheader("🔧 Informações técnicas")

    who = meta.get("whois")
    ssl = meta.get("ssl")
    dns = meta.get("dns")
    redirect_final = meta.get("redirect_final")

    st.write("**WHOIS / Idade do domínio**")
    if who:
        st.write(f"- Criação: {who.get('creation_date')} — idade (dias): {who.get('age_days')}")
        st.caption("Domínios muito novos são comuns em ataques de phishing.")
    else:
        st.write("- WHOIS: indisponível")

    st.write("**SSL / Certificado**")
    if ssl:
        if isinstance(ssl, dict):
            st.write(f"- Issuer: {ssl.get('issuer')}")
            st.write(f"- Subject: {ssl.get('subject')}")
            st.write(f"- Expira: {ssl.get('expires')}")
            st.write(f"- Domain mismatch: {ssl.get('domain_mismatch')}")
        else:
            st.write(f"- {ssl}")
    else:
        st.write("- SSL: indisponível")

    st.write("**DNS (A / MX / CNAME)**")
    if dns:
        for k,v in dns.items():
            st.write(f"- {k}: {v if v else 'nenhum'}")
    else:
        st.write("- DNS: indisponível")

    if redirect_final:
        st.write(f"**Redirecionamento final / HTTP status:** {redirect_final}")
    st.write("")

# ----------------- abas -----------------
aba_analise, aba_dashboard, aba_blacklist = st.tabs(["🔍 Analisar URL", "📊 Dashboard", "🗂 Blacklist Admin"])

# ===========================================================
# ABA 1 - ANALISAR
# ===========================================================
with aba_analise:
    st.title("🔍 Detector de Phishing — Análise de URL")
    url = st.text_input("URL para analisar", value="example.com")

    if st.button("Analisar"):
        if not url or url.strip() == "":
            st.warning("Digite uma URL válida.")
        else:
            with st.spinner("Analisando..."):
                start = time.time()
                try:
                    # prefer DB blacklist
                    result = analyze_url_with_b(url, prefer_db=True)
                except Exception as e:
                    # mostra erro no app e imprime traceback no terminal
                    st.error(f"Ocorreu um erro ao analisar a URL: {e}")
                    tb = traceback.format_exc()
                    print("=== EXCEPTION during analyze_url_with_b ===")
                    print(tb)
                    # mostrar traceback na UI (opcional, útil em dev)
                    with st.expander("Ver traceback completo (dev)"):
                        st.text(tb)
                    result = None
                finally:
                    dur = time.time() - start
                    print(f"[debug] analyze_url_with_b duration: {dur:.2f}s")

            if result:
                with SessionLocal() as session:
                    rec = save_scan(session, result)
                    st.write("Scan salvo (id):", rec.id)

                            # --- Exibição com borda verde/vermelha ---
                score = result.get("score", 0)
                is_suspicious = result.get("is_suspicious")
                verdict = "Suspeito" if is_suspicious else "Provavelmente seguro"

                border_color = "#ff4b4b" if is_suspicious else "#00cc66"  # vermelho ou verde
                bg_color = "#ffe6e6" if is_suspicious else "#e6ffe6"
                box_html = f"""
                <div style="border:3px solid {border_color}; border-radius:10px; padding:15px; background-color:{bg_color};">
                <h3 style="margin:0;">Resultado: {verdict}</h3>
                <p style="margin:5px 0 0 0;"><strong>Score:</strong> {score}/100</p>
                </div>
                """
                st.markdown(box_html, unsafe_allow_html=True)

                # --- sugestão de adicionar à blacklist se for suspeito ---
                if is_suspicious:
                    registered = result.get("registered_domain") or result.get("domain")
                    st.warning(
                        f"O domínio **{registered}** parece suspeito. "
                        "Considere adicioná-lo à blacklist para futuras verificações."
                    )
                   
                st.subheader("📋 Detalhes da análise")
                for d in result.get("detalhes", []):
                    st.write("- " + d)

                st.subheader("🧩 Audit trail (regras aplicadas)")
                for a in result.get("audit", []):
                    st.write(f"- {a['rule']}: +{a['points']} pts — {a['reason']}")
                st.caption("Cada regra contribui pontos ao score. ≥50 indica suspeito.")

                meta = result.get("meta", {}) or {}
                gsb = meta.get("gsb")

                st.subheader("🔧 Informações técnicas")
                st.write("**Google Safe Browsing**")
                if gsb:
                    if gsb.get("match"):
                        st.error("Google Safe Browsing: URL encontrada em lista de ameaças")
                        st.json(gsb.get("detail") or gsb)
                    else:
                        st.success("Google Safe Browsing: sem correspondência")
                        # opcional: mostrar detalhe
                        if "detail" in gsb and gsb.get("detail"):
                            st.json(gsb.get("detail"))
                else:
                    st.write("- Google Safe Browsing: não configurado (defina GOOGLE_SAFEBROWSING_KEY)")


                render_technical_info(result.get("meta", {}))

# ===========================================================
# ABA 2 - DASHBOARD
# ===========================================================
with aba_dashboard:
    st.title("📊 Dashboard de Análises Recentes")

    with SessionLocal() as s:
        scans = s.query(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(50).all()

    if scans:
        df = pd.DataFrame([{
            "Data": r.timestamp.strftime("%Y-%m-%d %H:%M"),
            "URL": r.url,
            "Score": r.score,
            "Veredito": r.verdict
        } for r in scans])

        st.dataframe(df, width="stretch")
        st.bar_chart(df["Score"])

        counts = df["Veredito"].value_counts()
        st.subheader("Distribuição de Vereditos")
        fig1 = plt.figure()
        counts.plot.pie(autopct="%1.1f%%", ylabel="")
        st.pyplot(fig1)

        st.download_button(
            "📥 Exportar CSV",
            df.to_csv(index=False).encode("utf-8"),
            "historico_scans.csv",
            "text/csv"
        )
    else:
        st.info("Nenhum scan registrado ainda.")

# ===========================================================
# ABA 3 - BLACKLIST ADMIN
# ===========================================================
with aba_blacklist:
    st.title("🗂 Gerenciar Blacklist")
    with st.form("add_blacklist"):
        domain = st.text_input("Domínio (ex: bad.com)")
        comment = st.text_input("Comentário (opcional)")
        submit = st.form_submit_button("Adicionar")
        if submit:
            with SessionLocal() as s:
                e = add_blacklist_entry(s, domain, source="manual", comment=comment)
                st.success(f"Adicionado/Atualizado: {e.domain}")

    with st.form("remove_blacklist"):
        domain_r = st.text_input("Domínio a remover")
        rm = st.form_submit_button("Remover")
        if rm:
            with SessionLocal() as s:
                e = remove_blacklist_entry(s, domain_r)
                if e:
                    st.success(f"Removido: {e.domain}")
                else:
                    st.warning("Entrada não encontrada.")

    if st.button("Sincronizar do GitHub (Phishing.Database)"):
        with st.spinner("Sincronizando..."):
            try:
                RAW = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
                r = requests.get(RAW, timeout=15)
                if r.status_code == 200:
                    lines = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
                    added = 0
                    with SessionLocal() as s:
                        for ln in lines:
                            if ln.startswith("http"):
                                from urllib.parse import urlparse
                                ln = (urlparse(ln).hostname or ln)
                            add_blacklist_entry(s, ln, source="github", comment="sync")
                            added += 1
                    st.success(f"{added} domínios sincronizados.")
                else:
                    st.error(f"Falha HTTP {r.status_code}")
            except Exception as ex:
                st.error(f"Erro: {ex}")

    st.write("Últimas entradas:")
    with SessionLocal() as s:
        rows = list_blacklist(s, limit=30)
        for r in rows:
            st.write(f"- {r.domain} ({r.source}, {r.created_at.date()})")
