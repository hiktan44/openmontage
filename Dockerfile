FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg git curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p projects

EXPOSE 4750

CMD ["python", "-m", "uvicorn", "backlot.server:app", "--host", "0.0.0.0", "--port", "4750"]

# --- Agentic Security Firewall: Katman 2 (non-root hardening) ---
RUN (id -u appuser >/dev/null 2>&1 || useradd -m -u 10001 appuser) && { [ ! -d /app ] || chown -R appuser:appuser /app; }
USER appuser
