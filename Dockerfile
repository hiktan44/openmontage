FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p projects

ENV PYTHONUNBUFFERED=1

EXPOSE 4750

CMD ["python", "-m", "uvicorn", "backlot.server:app", "--host", "0.0.0.0", "--port", "4750"]
