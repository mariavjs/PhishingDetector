# src/web_interface.py
import streamlit as st
from analyser import analyze_url


st.set_page_config(page_title="Detector de Phishing - Conceito C", layout="centered")

st.title("Detector de Phishing — Conceito C")
st.write("Insira uma URL para análise básica (heurísticas + blacklist local).")

url = st.text_input("URL", value="https://example.com")

if st.button("Analisar"):
    if not url:
        st.warning("Digite uma URL válida.")
    else:
        result = analyze_url(url)
        score = result["score"]
        if result["is_suspicious"]:
            st.error(f"Risco: {score} / 100 — Suspeito")
        else:
            st.success(f"Risco: {score} / 100 — Provavelmente seguro")
        st.subheader("Detalhes da análise")
        for d in result["detalhes"]:
            st.write("- " + d)

        st.write("---")
        st.write("Domínio:", result["domain"])
