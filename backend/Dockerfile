# Pinned to bookworm (Debian 12): playwright 1.49's `install --with-deps`
# references font/lib package names that were renamed in trixie (Debian 13),
# so the default `slim` (now trixie) fails on `ttf-ubuntu-font-family`.
FROM python:3.12-slim-bookworm

# Security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    whatweb \
    dnsutils \
    whois \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Go-based tools (nuclei, subfinder, gitleaks)
RUN curl -sL https://go.dev/dl/go1.22.4.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:$PATH"
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/zricethezav/gitleaks/v8@latest \
    && mv ~/go/bin/* /usr/local/bin/

WORKDIR /app

# semgrep is installed isolated (pipx) — pulling it into the app env upgrades
# starlette and breaks fastapi. ~/.local/bin is where pipx exposes the binary.
ENV PATH="/root/.local/bin:$PATH"
RUN pip install --no-cache-dir pipx && pipx install semgrep

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium --with-deps

COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
