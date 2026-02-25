#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_USER="${SUDO_USER:-$USER}"
ORIGINAL_HOME="$(eval echo "~${ORIGINAL_USER}")"

if [[ "${EUID}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "[*] Elevando privilegios com sudo..."
    exec sudo -E bash "$0" "$@"
  fi
  echo "[!] Este script precisa de root/sudo."
  exit 1
fi

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

ensure_user_local_bin_on_path() {
  local bashrc="${ORIGINAL_HOME}/.bashrc"
  local export_line='export PATH="$HOME/.local/bin:$PATH"'
  mkdir -p "${ORIGINAL_HOME}/.local/bin"
  if [[ -f "${bashrc}" ]]; then
    if ! grep -Fq "${export_line}" "${bashrc}"; then
      echo "${export_line}" >> "${bashrc}"
    fi
  else
    echo "${export_line}" > "${bashrc}"
  fi
  chown -R "${ORIGINAL_USER}:${ORIGINAL_USER}" "${ORIGINAL_HOME}/.local"
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

if id -u "${ORIGINAL_USER}" >/dev/null 2>&1; then
  usermod -aG docker "${ORIGINAL_USER}" || true
  echo "[*] Usuario ${ORIGINAL_USER} adicionado ao grupo docker (se existir)."
fi

chmod +x "${REPO_DIR}/auto"
chmod +x "${REPO_DIR}/install.sh"
if ln -sf "${REPO_DIR}/auto" /usr/local/bin/auto 2>/dev/null; then
  echo "[*] Comando global criado em /usr/local/bin/auto"
else
  echo "[*] Nao foi possivel criar /usr/local/bin/auto; usando ~/.local/bin/auto"
fi

ensure_user_local_bin_on_path
ln -sf "${REPO_DIR}/auto" "${ORIGINAL_HOME}/.local/bin/auto"
chown -h "${ORIGINAL_USER}:${ORIGINAL_USER}" "${ORIGINAL_HOME}/.local/bin/auto"

echo
echo "[+] Instalacao concluida."
echo "[+] Rode a ferramenta com: auto --help"
echo "[+] Ou usando caminho completo: ${REPO_DIR}/auto --help"
echo "[+] Se o comando auto nao abrir agora, rode: source ~/.bashrc"
echo "[+] Se quiser usar Docker sem sudo, faca logout/login apos a instalacao."
