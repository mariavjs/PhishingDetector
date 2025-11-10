from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
# ajuste PYTHONPATH se necessário:
sys.path.insert(0, os.path.abspath("src"))

from analyser import analyze_url_with_b

app = Flask(__name__)
CORS(app)  # permite chamadas do extension dev; em produção restrinja

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json() or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "missing url"}), 400
    try:
        res = analyze_url_with_b(url, prefer_db=True)
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    print(">> Entrando em api.py principal")
    app.run(host="127.0.0.1", port=5000, debug=True)
