# Dockerfile
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# system deps for e.g. tldextract (no network needed), psycopg2-binary, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# copy requirements and install
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel
RUN pip install -r requirements.txt

# copy app
COPY . .

# streamlit runs on 8501 by default; expose
EXPOSE 8501

# default command
CMD ["streamlit", "run", "src/web_interface.py", "--server.port=8501", "--server.address=0.0.0.0"]
