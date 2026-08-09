#!/usr/bin/env bash
#
# install.sh — Automatic installer/uninstaller for SOC YARA Scanner Docker setup
# Usage: chmod +x install.sh && ./install.sh [install|uninstall]
#
set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="soc-yara-scanner:latest"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.yml"
CONTAINER_NAME="soc-yara-scanner"

# Helpers
echo_stderr() { printf '%s\n' "$*" >&2; }
prompt_yesno() {
  local prompt="$1" default="$2" answer
  if [ "$default" = "Y" ]; then
    printf "%s [Y/n]: " "$prompt"
  else
    printf "%s [y/N]: " "$prompt"
  fi
  read -r answer
  answer="${answer:-$default}"
  case "$answer" in
    [Yy]* ) return 0 ;;
    * ) return 1 ;;
  esac
}

check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

ensure_docker() {
  if check_cmd docker; then
    echo "Docker is installed."
    return 0
  fi

  echo "Docker is not installed."
  if ! prompt_yesno "Install Docker now (Debian/Ubuntu only)?" "N"; then
    echo "Please install Docker manually and re-run this script."
    return 1
  fi

  # Detect Debian/Ubuntu
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    if printf '%s' "$ID" | grep -E -i -q "ubuntu|debian"; then
      echo "Installing Docker using get.docker.com (requires sudo)..."
      curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
      sudo sh /tmp/get-docker.sh
      rm -f /tmp/get-docker.sh
      sudo usermod -aG docker "$USER" || true
      echo "Docker installed. You may need to log out/in for group changes to take effect."
      return 0
    fi
  fi

  echo "Automatic Docker install is only implemented for Debian/Ubuntu."
  echo "Please install Docker following your OS docs: https://docs.docker.com/get-docker/"
  return 1
}

ensure_docker_compose() {
  # Prefer builtin "docker compose"
  if docker compose version >/dev/null 2>&1; then
    echo "Docker Compose plugin available (docker compose)."
    return 0
  fi
  if check_cmd docker-compose; then
    echo "docker-compose binary found."
    return 0
  fi

  echo "Docker Compose not found."
  if ! prompt_yesno "Install docker-compose (python-based) now?" "N"; then
    echo "Skipping docker-compose install. You can use 'docker compose' or install compose later."
    return 1
  fi

  # Try pip install (will use user's pip)
  if check_cmd pip3; then
    echo "Installing docker-compose via pip3 (requires sudo if global)."
    pip3 install --user docker-compose
    echo "docker-compose installed (in user local bin). Ensure \$HOME/.local/bin is on your PATH."
    return 0
  fi

  echo "pip3 not found — please install docker-compose manually."
  return 1
}

create_files() {
  # Create requirements.txt if missing
  if [ ! -f "${REPO_ROOT}/requirements.txt" ]; then
    cat > "${REPO_ROOT}/requirements.txt" <<'REQ'
yara-python
watchdog
REQ
    echo "Created requirements.txt"
  else
    echo "requirements.txt exists — skipping"
  fi

  # Create Dockerfile if missing
  if [ ! -f "${REPO_ROOT}/Dockerfile" ]; then
    cat > "${REPO_ROOT}/Dockerfile" <<'DOCK'
FROM python:3.11-slim

# Install system dependencies needed to build/install yara-python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    pkg-config \
    libyara-dev \
    python3-dev \
    ca-certificates \
    curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scanner and rules
COPY YARA_scanning.py .
COPY rules/ rules/

# Create default uploads dir and findings file
RUN mkdir -p /app/uploads
VOLUME ["/app/uploads", "/app/findings.ndjson"]

ENV WATCH_DIRECTORY=/app/uploads
ENV YARA_RULES_FILE=/app/rules/test_rule.yar
ENV AUTH_LOG_PATH=/var/log/auth.log
ENV FINDINGS_FILE=/app/findings.ndjson

CMD ["python", "YARA_scanning.py"]
DOCK
    echo "Created Dockerfile"
  else
    echo "Dockerfile exists — skipping"
  fi

  # Create docker-compose.yml if missing
  if [ ! -f "${COMPOSE_FILE}" ]; then
    cat > "${COMPOSE_FILE}" <<'DC'
version: "3.8"
services:
  scanner:
    build: .
    image: soc-yara-scanner:latest
    container_name: soc-yara-scanner
    restart: unless-stopped
    environment:
      - WATCH_DIRECTORY=/app/uploads
      - YARA_RULES_FILE=/app/rules/test_rule.yar
      - AUTH_LOG_PATH=/var/log/auth.log
      - FINDINGS_FILE=/app/findings.ndjson
    volumes:
      - ./uploads:/app/uploads:rw
      - ./findings.ndjson:/app/findings.ndjson:rw
      - /var/log/auth.log:/var/log/auth.log:ro
DC
    echo "Created docker-compose.yml"
  else
    echo "docker-compose.yml exists — skipping"
  fi

  # Create rules directory and a test rule if missing
  if [ ! -d "${REPO_ROOT}/rules" ]; then
    mkdir -p "${REPO_ROOT}/rules"
  fi
  if [ ! -f "${REPO_ROOT}/rules/test_rule.yar" ]; then
    cat > "${REPO_ROOT}/rules/test_rule.yar" <<'YAR'
rule TestRule {
    meta:
        author = "installer"
        description = "Simple test rule that matches the text 'malware'"
    strings:
        $mal = "malware"
    condition:
        $mal
}
YAR
    echo "Created rules/test_rule.yar"
  else
    echo "rules/test_rule.yar exists — skipping"
  fi

  # Create a simple YARA_scanning.py if missing
  if [ ! -f "${REPO_ROOT}/YARA_scanning.py" ]; then
    cat > "${REPO_ROOT}/YARA_scanning.py" <<'PY'
#!/usr/bin/env python3
"""
Minimal YARA scanning watcher.
- Watches WATCH_DIRECTORY (env) and scans newly created files with yara-python.
- On hit, correlates with /var/log/auth.log for failed SSH attempts in last 5 minutes.
- Appends NDJSON records to FINDINGS_FILE.
"""
import os
import time
import json
import yara
import datetime
import hashlib
import sys

WATCH_DIRECTORY = os.getenv("WATCH_DIRECTORY", "./uploads")
YARA_RULES_FILE = os.getenv("YARA_RULES_FILE", "rules/test_rule.yar")
AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
FINDINGS_FILE = os.getenv("FINDINGS_FILE", "findings.ndjson")
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.5"))

# Simple in-memory seen set
_seen = set()

def load_rules():
    if os.path.exists(YARA_RULES_FILE):
        try:
            rules = yara.compile(filepath=YARA_RULES_FILE)
            print("Loaded YARA rules from", YARA_RULES_FILE)
            return rules
        except Exception as e:
            print("Error compiling YARA rules:", e)
    # fallback test rule
    print("Using embedded TestRule fallback")
    src = 'rule TestRule { strings: $a = "malware" condition: $a }'
    return yara.compile(source=src)

def recent_failed_auths(minutes=5):
    results = []
    if not os.path.exists(AUTH_LOG_PATH):
        return results
    cutoff = datetime.datetime.now() - datetime.timedelta(minutes=minutes)
    try:
        with open(AUTH_LOG_PATH, "r", errors="ignore") as fh:
            for line in fh:
                if "Failed password" in line or "authentication failure" in line:
                    # Syslog timestamp format: "Aug  9 12:34:56"
                    try:
                        parts = line.split()
                        # parts[0]=Month, parts[1]=day, parts[2]=time
                        ts_str = " ".join(parts[0:3])
                        ts = datetime.datetime.strptime(ts_str, "%b %d %H:%M:%S")
                        ts = ts.replace(year=datetime.datetime.now().year)
                        if ts >= cutoff:
                            results.append(line.strip())
                    except Exception:
                        # If parse fails, include line just in case
                        results.append(line.strip())
    except Exception:
        pass
    return results

def scan_file(path, rules):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except Exception as e:
        print("Failed to read", path, e)
        return None

    try:
        matches = rules.match(data=data)
    except Exception as e:
        print("Error scanning", path, e)
        return None

    if matches:
        matched_rules = [m.rule for m in matches]
        auths = recent_failed_auths(5)
        rec = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "file": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "matched_rules": matched_rules,
            "auth_matches": auths,
        }
        try:
            with open(FINDINGS_FILE, "a") as out:
                out.write(json.dumps(rec) + "\n")
            print("Wrote finding for", path)
        except Exception as e:
            print("Failed to write finding:", e)
        return rec
    return None

def main():
    os.makedirs(WATCH_DIRECTORY, exist_ok=True)
    print("Watching", WATCH_DIRECTORY)
    rules = load_rules()
    while True:
        try:
            for fname in os.listdir(WATCH_DIRECTORY):
                path = os.path.join(WATCH_DIRECTORY, fname)
                if path in _seen:
                    continue
                if os.path.isfile(path):
                    _seen.add(path)
                    print("Detected new file:", path)
                    scan_file(path, rules)
        except KeyboardInterrupt:
            print("Exiting on user interrupt")
            sys.exit(0)
        except Exception as e:
            print("Watcher error:", e)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
PY
    chmod +x "${REPO_ROOT}/YARA_scanning.py"
    echo "Created YARA_scanning.py (minimal)."
  else
    echo "YARA_scanning.py exists — skipping"
  fi

  # Ensure uploads dir and findings file exist
  mkdir -p "${REPO_ROOT}/uploads"
  touch "${REPO_ROOT}/findings.ndjson"
  echo "Prepared uploads/ and findings.ndjson"
}

build_image() {
  if ! check_cmd docker; then
    echo "Docker is not available; cannot build image."
    return 1
  fi
  echo "Building Docker image ${IMAGE_NAME}..."
  docker build -t "${IMAGE_NAME}" "${REPO_ROOT}"
  echo "Docker image built: ${IMAGE_NAME}"
}

maybe_docker_login_and_push() {
  if ! check_cmd docker; then
    echo "Docker not available; skipping push."
    return 0
  fi

  if ! prompt_yesno "Do you want to push the image to Docker Hub (requires login)?" "N"; then
    return 0
  fi

  read -r -p "Docker Hub username: " hub_user
  echo -n "Docker Hub password for ${hub_user}: "
  # shellcheck disable=SC2034
  read -r -s hub_pass
  echo
  if [ -z "$hub_user" ] || [ -z "$hub_pass" ]; then
    echo "Username or password empty — aborting push."
    return 1
  fi

  # Tag as <username>/soc-yara-scanner:latest and push
  hub_image="${hub_user}/soc-yara-scanner:latest"
  echo "$hub_pass" | docker login --username "$hub_user" --password-stdin
  docker tag "${IMAGE_NAME}" "${hub_image}"
  docker push "${hub_image}"
  echo "Pushed image to ${hub_image}"
}

maybe_run_container() {
  if ! check_cmd docker; then
    echo "Docker not available; cannot run container."
    return 1
  fi

  if prompt_yesno "Start the scanner now using docker-compose (if available)?" "Y"; then
    if [ -f "${COMPOSE_FILE}" ] && docker compose version >/dev/null 2>&1; then
      docker compose up -d
      echo "Started via 'docker compose up -d'"
    elif [ -f "${COMPOSE_FILE}" ] && check_cmd docker-compose; then
      docker-compose up -d
      echo "Started via 'docker-compose up -d'"
    else
      echo "docker-compose not available. Starting single container via docker run..."
      docker run -d --name "${CONTAINER_NAME}" \
        -v "${REPO_ROOT}/uploads":/app/uploads:rw \
        -v "${REPO_ROOT}/findings.ndjson":/app/findings.ndjson:rw \
        -v /var/log/auth.log:/var/log/auth.log:ro \
        --restart unless-stopped "${IMAGE_NAME}"
      echo "Container started."
    fi
  else
    echo "Skipping starting container."
  fi
}

# Uninstall functions
stop_container() {
  if ! check_cmd docker; then
    echo "Docker not available; skipping container stop."
    return 0
  fi

  echo "Stopping and removing containers..."
  
  # Try docker-compose first
  if [ -f "${COMPOSE_FILE}" ] && docker compose version >/dev/null 2>&1; then
    echo "Stopping via 'docker compose down'..."
    docker compose down 2>/dev/null || true
  elif [ -f "${COMPOSE_FILE}" ] && check_cmd docker-compose; then
    echo "Stopping via 'docker-compose down'..."
    docker-compose down 2>/dev/null || true
  else
    # Stop and remove manually
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
      echo "Stopping container ${CONTAINER_NAME}..."
      docker stop "${CONTAINER_NAME}" 2>/dev/null || true
      echo "Removing container ${CONTAINER_NAME}..."
      docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    else
      echo "Container ${CONTAINER_NAME} not found."
    fi
  fi
}

remove_image() {
  if ! check_cmd docker; then
    echo "Docker not available; skipping image removal."
    return 0
  fi

  if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${IMAGE_NAME}$"; then
    if prompt_yesno "Remove Docker image ${IMAGE_NAME}?" "Y"; then
      echo "Removing Docker image..."
      docker rmi "${IMAGE_NAME}" 2>/dev/null || echo "Note: Image may be in use; remove manually with: docker rmi ${IMAGE_NAME}"
    fi
  else
    echo "Docker image ${IMAGE_NAME} not found."
  fi
}

remove_generated_files() {
  if prompt_yesno "Remove generated files (Dockerfile, docker-compose.yml, etc.)?" "N"; then
    echo "Removing generated files..."
    rm -f "${REPO_ROOT}/Dockerfile" && echo "Removed Dockerfile"
    rm -f "${REPO_ROOT}/docker-compose.yml" && echo "Removed docker-compose.yml"
    rm -f "${REPO_ROOT}/requirements.txt" && echo "Removed requirements.txt"
    rm -f "${REPO_ROOT}/YARA_scanning.py" && echo "Removed YARA_scanning.py"
    
    if [ -d "${REPO_ROOT}/rules" ]; then
      rm -rf "${REPO_ROOT}/rules" && echo "Removed rules directory"
    fi
    
    if [ -d "${REPO_ROOT}/uploads" ]; then
      rm -rf "${REPO_ROOT}/uploads" && echo "Removed uploads directory"
    fi
  else
    echo "Keeping generated files."
  fi
}

remove_findings() {
  if prompt_yesno "Remove findings.ndjson file?" "N"; then
    rm -f "${REPO_ROOT}/findings.ndjson" && echo "Removed findings.ndjson"
  else
    echo "Keeping findings.ndjson."
  fi
}

uninstall() {
  echo "=== SOC YARA Scanner Uninstaller ==="
  echo "This will remove the Docker container, image, and optionally generated files."
  echo

  stop_container
  echo
  remove_image
  echo
  remove_findings
  echo
  remove_generated_files

  echo
  echo "Uninstall complete."
  echo "To reinstall, run: ./install.sh"
}

# Main flow
main() {
  local action="${1:-}"

  case "$action" in
    uninstall|remove)
      uninstall
      ;;
    install|"")
      echo "Starting installer..."
      create_files

      if ! ensure_docker; then
        echo "Docker not present. Exiting installer after file creation."
        exit 0
      fi

      ensure_docker_compose || true

      if prompt_yesno "Build the Docker image now?" "Y"; then
        build_image
      fi

      maybe_docker_login_and_push || true
      maybe_run_container

      echo
      echo "Installer finished. Next steps:"
      echo " - To check logs: docker logs -f ${CONTAINER_NAME}"
      echo " - To stop: docker stop ${CONTAINER_NAME} && docker rm ${CONTAINER_NAME}"
      echo " - To rebuild after edits: ./install.sh"
      echo " - To uninstall: ./install.sh uninstall"
      ;;
    *)
      echo "Usage: $0 [install|uninstall]"
      echo "  install    - Install and set up the SOC YARA Scanner (default)"
      echo "  uninstall  - Remove containers, images, and optionally generated files"
      exit 1
      ;;
  esac
}

main "$@"
