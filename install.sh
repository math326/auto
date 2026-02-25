#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute como root/sudo: sudo bash install.sh"
  exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install_debian_like() {
  apt update
  apt install -y \
    python3 \
    python3-pip \
    nmap \
    kleopatra \
    gnupg \
    paperkey \
    openssh-client \
    openssh-server \
    docker.io
}

install_arch() {
  pacman -Sy --noconfirm \
    python \
    python-pip \
    nmap \
    kleopatra \
    gnupg \
    paperkey \
    openssh \
    docker
}

enable_service_if_exists() {
  local service="$1"
  if systemctl list-unit-files | grep -q "^${service}"; then
    systemctl enable --now "${service}"
    return 0
  fi
  return 1
}

if command -v apt >/dev/null 2>&1; then
  echo "[*] Detectado Debian/Ubuntu (apt)"
  install_debian_like
elif command -v pacman >/dev/null 2>&1; then
  echo "[*] Detectado Arch Linux (pacman)"
  install_arch
else
  echo "[!] Distribuicao nao suportada automaticamente."
  exit 1
fi

echo "[*] Ativando SSH..."
enable_service_if_exists "ssh.service" || enable_service_if_exists "sshd.service" || true

echo "[*] Ativando Docker..."
enable_service_if_exists "docker.service" || true

if [[ -n "${SUDO_USER:-}" ]] && id -u "${SUDO_USER}" >/dev/null 2>&1; then
  usermod -aG docker "${SUDO_USER}" || true
  echo "[*] Usuario ${SUDO_USER} adicionado ao grupo docker (se existir)."
fi

chmod +x "${REPO_DIR}/auto"
chmod +x "${REPO_DIR}/install.sh"

echo
echo "[+] Instalacao concluida."
echo "[+] Rode a ferramenta com: ${REPO_DIR}/auto --help"
echo "[+] Se quiser usar Docker sem sudo, faça logout/login apos a instalacao."
