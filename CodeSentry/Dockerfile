FROM node:18-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

ENV PIP_DEFAULT_TIMEOUT=300
RUN pip3 install --break-system-packages --no-cache-dir ruff bandit
RUN pip3 install --break-system-packages --no-cache-dir --retries 5 semgrep

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev
RUN npm install -g eslint

COPY . .

RUN npm link

ENTRYPOINT ["codesentry"]
