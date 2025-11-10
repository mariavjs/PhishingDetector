# PhishingDetector

O projeto feito para a matéria Tecnologias Hacker é um protótipo de ferramenta para **detecção de sites de phishing**.  

O projeto tem:
- **Uma API local em Python (Flask)**, responsável por analisar URLs e detectar características suspeitas;
- **Uma extensão para Firefox**, que realiza verificações em tempo real enquanto o usuário navega;
- **Um dashboard em Streamlit**, usado para visualizar histórico, métricas e resultados das análises.

---

## 🎯 Objetivo
O objetivo é demonstrar um sistema completo capaz de:
1. Analisar URLs automaticamente (ou manualmente);
2. Detectar sinais de phishing usando heurísticas e bases conhecidas;
3. Alertar o usuário em tempo real;
4. Armazenar histórico de análises para consulta posterior.

---

## 🧠 Funcionalidades

### 🔹 API Flask (`src/api.py`)
- Endpoint `/health`: checa se o servidor está ativo;
- Endpoint `/analyze`: recebe uma URL, executa `analyze_url_with_b()` e devolve um JSON com:
  - **score** (0 a 100)
  - **is_suspicious** (true/false)
  - **motivos da detecção**
  - **metadados técnicos** (SSL, WHOIS, DNS etc.)
- Pode salvar as análises no banco `data/history.db` para uso no dashboard Streamlit.

---

### 🔹 Extensão Firefox (`phishguard_extension/`)
- Verifica **todas as páginas visitadas** e **links ao passar o mouse**;
- Faz chamadas para o servidor local (`http://127.0.0.1:5000/analyze`);
- Mostra **banners de alerta** no topo da página e **notificações do navegador**;
- Configurações:
  - **Sensibilidade (threshold)** ajustável;
  - **Auto-block** (bloqueio automático de sites suspeitos);
  - **Whitelist** de domínios confiáveis.

#### 🧩 Estrutura da extensão:
