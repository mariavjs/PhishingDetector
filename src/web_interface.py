# src/web_interface.py
import streamlit as st
from analyser import analyze_url

st.set_page_config(page_title="Detector de Phishing - Conceito C", layout="centered")

st.title("Detector de Phishing — Conceito C")
st.write("Insira uma URL para análise básica (heurísticas + blacklist local).")

url = st.text_input("URL", value="example.com")

if st.button("Analisar"):
    if not url or url.strip() == "":
        st.warning("Digite uma URL válida.")
    else:
        try:
            result = analyze_url(url)
        except Exception as e:
            st.error(f"Ocorreu um erro ao analisar a URL: {e}")
        else:
            score = result.get("score", 0)
            if result.get("is_suspicious"):
                st.error(f"Risco: {score} / 100 — Suspeito")
            else:
                st.success(f"Risco: {score} / 100 — Provavelmente seguro")
            st.subheader("Detalhes da análise")
            for d in result.get("detalhes", []):
                st.write("- " + d)

            st.write("---")
            st.write("Domínio:", result.get("domain"))
            st.write("Domínio registrado:", result.get("registered_domain"))
            st.write("HTTP status (se obtido):", result.get("http_status"))
            st.write("URL normalizada:", result.get("url"))
