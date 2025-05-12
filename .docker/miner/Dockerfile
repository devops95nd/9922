FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential git curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.version.txt .
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && pip install setuptools --upgrade
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# 6. Chạy server
CMD ["python", "model_servers/miner.py"]