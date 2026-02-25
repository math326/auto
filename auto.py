import argparse
import getpass
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from menus import show_docker_menu, show_kleopatra_menu, show_main_menu, show_nmap_menu, show_zip_menu
from menus import show_ssh_menu
from utils import clear_screen, input_with_prompt, print_header, wait_for_enter

DOCKER_USE_SUDO = False
APT_UPDATED = False

NMAP_COMMAND_TEMPLATES = {
    "1": ["nmap", "-sn", "{target_net}"],
    "2": ["nmap", "-sn", "{target_net}"],
    "3": ["nmap", "-sV", "{target_host}"],
    "4": ["nmap", "-sS", "{target_host}"],
    "5": ["nmap", "-sU", "{target_host}"],
    "6": ["nmap", "-sT", "{target_host}"],
    "7": ["nmap", "-sL", "{target_net}"],
    "8": ["nmap", "-p", "22,80,443", "{target_host}"],
    "9": ["nmap", "-p-", "{target_host}"],
    "10": ["nmap", "-A", "{target_host}"],
    "11": ["nmap", "-O", "{target_host}"],
    "12": ["nmap", "-v", "{target_host}"],
    "13": ["nmap", "-iL", "{input_file}"],
    "14": ["nmap", "-iL", "{input_file}", "-p", "22,80,443"],
    "15": ["nmap", "-iL", "{input_file}", "-sV"],
    "16": ["nmap", "-iL", "{input_file}", "-sS", "-p", "22,80,443"],
    "17": ["nmap", "-iL", "{input_file}", "-sU", "-p", "53"],
    "18": ["nmap", "-iL", "{input_file}", "-sT", "-p", "22,80,443"],
    "19": ["nmap", "-iL", "{input_file}", "-sL"],
    "20": ["nmap", "-iL", "{input_file}", "-sn"],
    "21": ["nmap", "-iL", "{input_file}", "-sS", "-p-"],
    "22": ["nmap", "-iL", "{input_file}", "-sU", "-p-"],
    "23": ["nmap", "-iL", "{input_file}", "-sV", "-p", "22,80,443"],
    "24": ["nmap", "-iL", "{input_file}", "-A"],
    "25": ["nmap", "-iL", "{input_file}", "-O"],
    "26": ["nmap", "-iL", "{input_file}", "-p", "22,80,443", "-v"],
    "27": ["nmap", "-iL", "{input_file}", "-sU", "-p", "53", "-v"],
    "28": ["nmap", "-iL", "{input_file}", "-sT", "-p", "22,80,443", "-v"],
    "29": ["nmap", "-iL", "{input_file}", "-sS", "-p-", "-v"],
    "30": ["nmap", "-iL", "{input_file}", "-sU", "-p-", "-v"],
    "31": ["nmap", "-iL", "{input_file}", "-sV", "-p-", "-v"],
    "32": ["nmap", "-iL", "{input_file}", "-A", "-v"],
    "33": ["nmap", "-iL", "{input_file}", "-O", "-v"],
    "34": ["nmap", "-p", "22,80,443", "-sV", "{target_host}"],
    "35": ["nmap", "-sU", "-p", "53", "-sV", "{target_host}"],
    "36": ["nmap", "-sT", "-p", "22,80,443", "-sV", "{target_host}"],
    "37": ["nmap", "-sS", "-p-", "-sV", "{target_host}"],
    "38": ["nmap", "-sU", "-p-", "-sV", "{target_host}"],
    "39": ["nmap", "-p", "22,80,443", "-O", "{target_host}"],
    "40": ["nmap", "-sU", "-p", "53", "-O", "{target_host}"],
    "41": ["nmap", "-sT", "-p", "22,80,443", "-O", "{target_host}"],
    "42": ["nmap", "-sS", "-p-", "-O", "{target_host}"],
    "43": ["nmap", "-sU", "-p-", "-O", "{target_host}"],
    "44": ["nmap", "-p", "22,80,443", "-sV", "-O", "{target_host}"],
    "45": ["nmap", "-sU", "-p", "53", "-sV", "-O", "{target_host}"],
    "46": ["nmap", "-sT", "-p", "22,80,443", "-sV", "-O", "{target_host}"],
    "47": ["nmap", "-sS", "-p-", "-sV", "-O", "{target_host}"],
    "48": ["nmap", "-sU", "-p-", "-sV", "-O", "{target_host}"],
}


def run_command(command, capture_output=False, text_input=None, display_command=None, workdir=None):
    shown_command = display_command if display_command is not None else command
    print(f"\nExecutando: {' '.join(shown_command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=capture_output,
            text=True,
            input=text_input,
            cwd=workdir,
        )
        return result
    except FileNotFoundError:
        print(f"Comando nao encontrado: {command[0]}")
    except subprocess.CalledProcessError as exc:
        print(f"Comando falhou com codigo {exc.returncode}.")
        if exc.stderr:
            print(exc.stderr)
    return None


def ensure_sudo_for_nmap(command):
    if command and command[0] == "nmap":
        return ["sudo"] + command
    return command


def docker_command(args):
    if DOCKER_USE_SUDO:
        return ["sudo", "docker"] + args
    return ["docker"] + args


def ensure_tool_exists(tool):
    if shutil.which(tool) is None:
        print(f"Dependencia ausente: {tool}")
        return False
    return True


def detect_package_manager():
    if shutil.which("pacman"):
        return "pacman"
    if shutil.which("apt"):
        return "apt"
    return None


def install_package(package_name):
    global APT_UPDATED
    package_manager = detect_package_manager()
    if package_manager == "pacman":
        return run_command(["sudo", "pacman", "-S", "--noconfirm", package_name])
    if package_manager == "apt":
        if not APT_UPDATED:
            if run_command(["sudo", "apt", "update"]) is None:
                return None
            APT_UPDATED = True
        return run_command(["sudo", "apt", "install", package_name, "-y"])
    print("Gerenciador de pacotes nao suportado automaticamente.")
    return None


def ensure_or_install_tool(tool_name, package_name=None):
    if ensure_tool_exists(tool_name):
        print(f"Ferramenta encontrada: {tool_name}")
        return True

    pkg = package_name or tool_name
    print(f"Ferramenta ausente: {tool_name}")
    print(f"Tentando instalar {pkg}...")
    result = install_package(pkg)
    if result is None:
        return False

    if not ensure_tool_exists(tool_name):
        print(f"Nao foi possivel instalar/verificar: {tool_name}")
        return False
    return True


def ensure_or_install_command(command_name):
    package_manager = detect_package_manager()
    package_overrides = {
        "7z": {"apt": "p7zip-full", "pacman": "p7zip"},
        "unrar": {"apt": "unrar", "pacman": "unrar"},
        "rar": {"apt": "rar", "pacman": "rar"},
        "ssh": {"apt": "openssh-client", "pacman": "openssh"},
        "ssh-keygen": {"apt": "openssh-client", "pacman": "openssh"},
        "sshpass": {"apt": "sshpass", "pacman": "sshpass"},
    }
    package_name = command_name
    if command_name in package_overrides and package_manager in package_overrides[command_name]:
        package_name = package_overrides[command_name][package_manager]
    return ensure_or_install_tool(command_name, package_name)


def install_crypto_dependencies():
    if ensure_tool_exists("gpg") and ensure_tool_exists("paperkey"):
        return True

    package_manager = detect_package_manager()
    if package_manager == "pacman":
        print("Instalando dependencias com pacman...")
        result = run_command(["sudo", "pacman", "-S", "--noconfirm", "gnupg", "paperkey"])
    elif package_manager == "apt":
        print("Instalando dependencias com apt...")
        result = run_command(["sudo", "apt", "install", "gnupg", "paperkey", "-y"])
    else:
        print("Gerenciador nao suportado automaticamente. Instale gnupg e paperkey manualmente.")
        return False

    if result is None:
        return False

    if not ensure_tool_exists("gpg") or not ensure_tool_exists("paperkey"):
        print("Dependencias ainda ausentes apos tentativa de instalacao.")
        return False
    return True


def _resolve_nmap_template_tokens(template):
    resolved = []
    values = {}
    needs_file = "{input_file}" in template
    needs_host = "{target_host}" in template
    needs_net = "{target_net}" in template

    if needs_file:
        input_file = os.path.expanduser(
            input_with_prompt("Nome/caminho do arquivo de IPs (ex: ips.txt): ").strip()
        )
        if not input_file or not os.path.exists(input_file):
            print("Arquivo de IPs invalido.")
            return None
        values["{input_file}"] = input_file

    if needs_host:
        target_host = input_with_prompt("Digite o IP/host alvo: ").strip()
        if not target_host:
            print("IP/host invalido.")
            return None
        values["{target_host}"] = target_host

    if needs_net:
        target_net = input_with_prompt("Digite a rede/CIDR alvo (ex: 192.168.1.0/24): ").strip()
        if not target_net:
            print("Rede/CIDR invalida.")
            return None
        if "/" not in target_net:
            target_net = f"{target_net}/24"
            print(f"CIDR nao informado. Usando automaticamente: {target_net}")
        values["{target_net}"] = target_net

    for token in template:
        resolved.append(values.get(token, token))
    return resolved


def nmap_scan_flow():
    print_header("Scanner Nmap")
    print("Use apenas em hosts/redes com autorizacao.")
    if not ensure_or_install_tool("nmap", "nmap"):
        return

    scan_choice = show_nmap_menu()
    template = NMAP_COMMAND_TEMPLATES.get(scan_choice)
    if not template:
        print("Opcao de scan invalida.")
        return

    command = _resolve_nmap_template_tokens(template)
    if not command:
        return
    run_command(ensure_sudo_for_nmap(command))


def prompt_existing_path(label):
    value = os.path.expanduser(input_with_prompt(label).strip())
    if not value or not os.path.exists(value):
        print("Arquivo/pasta invalido(a).")
        return None
    return value


def prompt_output_path(label):
    value = os.path.expanduser(input_with_prompt(label).strip())
    if not value:
        print("Nome/caminho invalido.")
        return None
    return value


def execute_zip_option(choice):
    command_map = {
        "1": ["gunzip"],
        "2": ["gzip"],
        "3": ["unzip"],
        "4": ["zip"],
        "5": ["zip"],
        "6": ["zip"],
        "7": ["unzip"],
        "8": ["unzip"],
        "9": ["tar"],
        "10": ["tar"],
        "11": ["tar"],
        "12": ["tar"],
        "13": ["tar"],
        "14": ["tar"],
        "15": ["7z"],
        "16": ["7z"],
        "17": ["rar"],
        "18": ["unrar"],
        "19": ["ar"],
        "20": ["ar"],
        "21": ["bzip2"],
        "22": ["bunzip2"],
        "23": ["xz"],
        "24": ["unxz"],
        "25": ["cpio"],
        "26": ["cpio"],
        "27": ["zcat"],
        "28": ["bzcat"],
        "29": ["xzcat"],
        "30": ["7z"],
    }

    required = command_map.get(choice, [])
    for cmd in required:
        if not ensure_or_install_command(cmd):
            return

    if choice == "1":
        file_path = prompt_existing_path("Arquivo .gz: ")
        if file_path:
            run_command(["gunzip", file_path])
    elif choice == "2":
        file_path = prompt_existing_path("Arquivo para compactar em .gz: ")
        if file_path:
            run_command(["gzip", file_path])
    elif choice == "3":
        zip_file = prompt_existing_path("Arquivo .zip para extrair: ")
        if not zip_file:
            return
        password = getpass.getpass("Senha (deixe vazio se nao tiver): ").strip()
        command = ["unzip"]
        display = ["unzip"]
        if password:
            command += ["-P", password]
            display += ["-P", "******"]
        command.append(zip_file)
        display.append(zip_file)
        run_command(command, display_command=display)
    elif choice == "4":
        zip_out = prompt_output_path("Nome do .zip de saida (ex: arquivo.zip): ")
        file_path = prompt_existing_path("Arquivo para adicionar no .zip: ")
        if zip_out and file_path:
            run_command(["zip", zip_out, file_path])
    elif choice == "5":
        zip_out = prompt_output_path("Nome do .zip de saida (ex: pasta.zip): ")
        folder = prompt_existing_path("Diretorio para zipar recursivamente: ")
        if zip_out and folder:
            run_command(["zip", "-r", zip_out, folder])
    elif choice == "6":
        zip_out = prompt_output_path("Nome do .zip de saida (ex: protegido.zip): ")
        file_path = prompt_existing_path("Arquivo para zipar com senha: ")
        if not zip_out or not file_path:
            return
        password = getpass.getpass("Digite a senha do .zip: ").strip()
        if not password:
            print("Senha invalida.")
            return
        run_command(
            ["zip", "-P", password, zip_out, file_path],
            display_command=["zip", "-P", "******", zip_out, file_path],
        )
    elif choice == "7":
        zip_file = prompt_existing_path("Arquivo .zip para extrair: ")
        destination = prompt_output_path("Diretorio de destino (ex: /tmp/destino): ")
        if not zip_file or not destination:
            return
        os.makedirs(destination, exist_ok=True)
        password = getpass.getpass("Senha (deixe vazio se nao tiver): ").strip()
        command = ["unzip"]
        display = ["unzip"]
        if password:
            command += ["-P", password]
            display += ["-P", "******"]
        command += [zip_file, "-d", destination]
        display += [zip_file, "-d", destination]
        run_command(command, display_command=display)
    elif choice == "8":
        zip_file = prompt_existing_path("Arquivo .zip para testar integridade: ")
        if zip_file:
            run_command(["unzip", "-t", zip_file])
    elif choice == "9":
        tar_file = prompt_output_path("Nome do arquivo .tar.gz (ex: arquivo.tar.gz): ")
        folder = prompt_existing_path("Diretorio/pasta para compactar: ")
        if tar_file and folder:
            run_command(["tar", "-czvf", tar_file, folder])
    elif choice == "10":
        tar_file = prompt_existing_path("Arquivo .tar.gz para extrair: ")
        if tar_file:
            run_command(["tar", "-xzvf", tar_file])
    elif choice == "11":
        tar_file = prompt_output_path("Nome do arquivo .tar.bz2 (ex: arquivo.tar.bz2): ")
        folder = prompt_existing_path("Diretorio/pasta para compactar: ")
        if tar_file and folder:
            run_command(["tar", "-cjvf", tar_file, folder])
    elif choice == "12":
        tar_file = prompt_existing_path("Arquivo .tar.bz2 para extrair: ")
        if tar_file:
            run_command(["tar", "-xjvf", tar_file])
    elif choice == "13":
        tar_file = prompt_output_path("Nome do arquivo .tar.xz (ex: arquivo.tar.xz): ")
        folder = prompt_existing_path("Diretorio/pasta para compactar: ")
        if tar_file and folder:
            run_command(["tar", "-cJvf", tar_file, folder])
    elif choice == "14":
        tar_file = prompt_existing_path("Arquivo .tar.xz para extrair: ")
        if tar_file:
            run_command(["tar", "-xJvf", tar_file])
    elif choice == "15":
        out_file = prompt_output_path("Nome do arquivo .7z (ex: arquivo.7z): ")
        input_file = prompt_existing_path("Arquivo para compactar em .7z: ")
        if out_file and input_file:
            run_command(["7z", "a", out_file, input_file])
    elif choice == "16":
        file_7z = prompt_existing_path("Arquivo .7z para extrair: ")
        if not file_7z:
            return
        password = getpass.getpass("Senha (deixe vazio se nao tiver): ").strip()
        command = ["7z", "x"]
        display = ["7z", "x"]
        if password:
            command.append(f"-p{password}")
            display.append("-p******")
        command.append(file_7z)
        display.append(file_7z)
        run_command(command, display_command=display)
    elif choice == "17":
        out_file = prompt_output_path("Nome do arquivo .rar (ex: arquivo.rar): ")
        input_file = prompt_existing_path("Arquivo para compactar em .rar: ")
        if out_file and input_file:
            run_command(["rar", "a", out_file, input_file])
    elif choice == "18":
        rar_file = prompt_existing_path("Arquivo .rar para extrair: ")
        if not rar_file:
            return
        password = getpass.getpass("Senha (deixe vazio se nao tiver): ").strip()
        command = ["unrar", "x"]
        display = ["unrar", "x"]
        if password:
            command.append(f"-p{password}")
            display.append("-p******")
        command.append(rar_file)
        display.append(rar_file)
        run_command(command, display_command=display)
    elif choice == "19":
        out_file = prompt_output_path("Nome da biblioteca .a (ex: arquivo.a): ")
        input_file = prompt_existing_path("Arquivo para adicionar na .a: ")
        if out_file and input_file:
            run_command(["ar", "-r", out_file, input_file])
    elif choice == "20":
        archive_file = prompt_existing_path("Arquivo .a para extrair: ")
        if archive_file:
            run_command(["ar", "-x", archive_file])
    elif choice == "21":
        input_file = prompt_existing_path("Arquivo para compactar em .bz2: ")
        if input_file:
            run_command(["bzip2", input_file])
    elif choice == "22":
        input_file = prompt_existing_path("Arquivo .bz2 para extrair: ")
        if input_file:
            run_command(["bunzip2", input_file])
    elif choice == "23":
        input_file = prompt_existing_path("Arquivo para compactar em .xz: ")
        if input_file:
            run_command(["xz", input_file])
    elif choice == "24":
        input_file = prompt_existing_path("Arquivo .xz para extrair: ")
        if input_file:
            run_command(["unxz", input_file])
    elif choice == "25":
        list_file = prompt_existing_path("Arquivo de lista (ex: lista.txt): ")
        out_file = prompt_output_path("Arquivo .cpio de saida (ex: arquivo.cpio): ")
        if not list_file or not out_file:
            return
        with open(list_file, "r", encoding="utf-8") as handle:
            print(f"\nExecutando: cpio -ov -O {out_file} < {list_file}")
            try:
                subprocess.run(["cpio", "-ov", "-O", out_file], check=True, stdin=handle)
            except subprocess.CalledProcessError as exc:
                print(f"Comando falhou com codigo {exc.returncode}.")
    elif choice == "26":
        cpio_file = prompt_existing_path("Arquivo .cpio para extrair: ")
        if cpio_file:
            run_command(["cpio", "-idv", "-I", cpio_file])
    elif choice == "27":
        input_file = prompt_existing_path("Arquivo .gz para ler sem extrair: ")
        if input_file:
            run_command(["zcat", input_file])
    elif choice == "28":
        input_file = prompt_existing_path("Arquivo .bz2 para ler sem extrair: ")
        if input_file:
            run_command(["bzcat", input_file])
    elif choice == "29":
        input_file = prompt_existing_path("Arquivo .xz para ler sem extrair: ")
        if input_file:
            run_command(["xzcat", input_file])
    elif choice == "30":
        input_file = prompt_existing_path("Arquivo .7z para listar conteudo: ")
        if input_file:
            run_command(["7z", "l", input_file])


def zip_menu_flow():
    while True:
        clear_screen()
        print_header("Auto - Zip")
        choice = show_zip_menu()
        if choice == "0":
            return
        execute_zip_option(choice)
        wait_for_enter()


def ensure_ssh_service_running():
    if not ensure_or_install_command("ssh") or not ensure_or_install_command("ssh-keygen"):
        return False

    active_ssh = subprocess.run(
        ["systemctl", "is-active", "ssh"],
        check=False,
        capture_output=True,
        text=True,
    ).returncode == 0
    active_sshd = subprocess.run(
        ["systemctl", "is-active", "sshd.service"],
        check=False,
        capture_output=True,
        text=True,
    ).returncode == 0
    if active_ssh or active_sshd:
        print("Servico SSH ja esta ativo.")
        return True

    print("Ativando servico SSH...")
    result = run_command(["sudo", "systemctl", "enable", "--now", "ssh"])
    if result is None:
        result = run_command(["sudo", "systemctl", "enable", "--now", "sshd.service"])
    return result is not None


def append_ssh_config_block(alias, hostname, user, identity_file):
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    os.chmod(ssh_dir, 0o700)
    config_path = os.path.join(ssh_dir, "config")

    block = (
        f"\nHost {alias}\n"
        f"  HostName {hostname}\n"
        f"  User {user}\n"
        f"  IdentityFile {identity_file}\n"
        f"  IdentitiesOnly yes\n"
    )
    with open(config_path, "a", encoding="utf-8") as config_file:
        config_file.write(block)
    os.chmod(config_path, 0o600)
    return config_path


def ssh_github_flow():
    print_header("SSH - GitHub")
    email = input_with_prompt("Digite seu email do GitHub: ").strip()
    if not email:
        print("Email invalido.")
        return

    alias = input_with_prompt("Nome do alias SSH para GitHub (padrao: github): ").strip() or "github"
    print("\nGerando chave (responda as perguntas do ssh-keygen no terminal):")
    run_command(["ssh-keygen", "-t", "ed25519", "-C", email])

    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    os.chmod(ssh_dir, 0o700)

    append_ssh_config_block(alias, "github.com", "git", "~/.ssh/id_ed25519")
    run_command(["chmod", "700", os.path.expanduser("~/.ssh")])
    run_command(["chmod", "600", os.path.expanduser("~/.ssh/config")])

    pub_key_path = os.path.expanduser("~/.ssh/id_ed25519.pub")
    if os.path.exists(pub_key_path):
        result = run_command(["cat", pub_key_path], capture_output=True)
        if result and result.stdout:
            print("\nConteudo da chave publica:")
            print(result.stdout.strip())

    print("\nAgora copie esse texto e adicione nas chaves SSH da sua conta GitHub.")
    print("Teste a conexao com: ssh -T git@github.com")
    print(f"Se quiser testar pelo alias, rode: ssh -T {alias}")


def ssh_other_machine_flow():
    print_header("SSH - Outra Maquina")
    local_ip = input_with_prompt("Digite o IP da sua maquina local: ").strip()
    remote_ip = input_with_prompt("Digite o IP da maquina remota: ").strip()
    remote_user = input_with_prompt("Digite o usuario da maquina remota: ").strip()
    alias = input_with_prompt("Nome da maquina/alias SSH (ex: kali): ").strip()
    if not local_ip or not remote_ip or not remote_user or not alias:
        print("Dados invalidos.")
        return

    password = getpass.getpass("Digite a senha SSH da maquina remota: ").strip()
    if not password:
        print("Senha invalida.")
        return

    if not ensure_or_install_command("sshpass"):
        print("Nao foi possivel instalar/verificar sshpass.")
        return

    key_path = os.path.expanduser(f"~/.ssh/id_rsa_{alias}")
    print("\nGerando chave RSA (responda as perguntas do ssh-keygen no terminal):")
    run_command(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", key_path])

    pub_key_path = f"{key_path}.pub"
    if not os.path.exists(pub_key_path):
        print("Chave publica nao encontrada.")
        return

    with open(pub_key_path, "r", encoding="utf-8") as pub_file:
        public_key_content = pub_file.read().strip()
    if not public_key_content:
        print("Conteudo da chave publica vazio.")
        return

    remote_script = (
        "mkdir -p ~/.ssh && "
        "chmod 700 ~/.ssh && "
        "touch ~/.ssh/authorized_keys && "
        "grep -qxF '{key}' ~/.ssh/authorized_keys || echo '{key}' >> ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys && "
        "chown $USER:$USER ~/.ssh -R"
    ).format(key=public_key_content.replace("'", "'\"'\"'"))

    run_command(
        ["sshpass", "-p", password, "ssh", f"{remote_user}@{remote_ip}", remote_script],
        display_command=[
            "sshpass",
            "-p",
            "******",
            "ssh",
            f"{remote_user}@{remote_ip}",
            remote_script,
        ],
    )

    append_ssh_config_block(alias, remote_ip, remote_user, f"~/.ssh/id_rsa_{alias}")
    run_command(["chmod", "600", os.path.expanduser("~/.ssh/config")])
    run_command(["ssh", alias])


def ssh_menu_flow():
    if not ensure_ssh_service_running():
        print("Nao foi possivel validar/ativar SSH.")
        wait_for_enter()
        return

    while True:
        clear_screen()
        print_header("Auto - SSH")
        choice = show_ssh_menu()
        if choice == "0":
            return
        if choice == "1":
            ssh_github_flow()
        elif choice == "2":
            ssh_other_machine_flow()
        wait_for_enter()


CONTAINER_APT_PACKAGES = (
    "nano vim less man-db "
    "net-tools iproute2 iputils-ping dnsutils curl wget ca-certificates "
    "build-essential git python3 python3-pip openjdk-21-jdk "
    "sudo procps util-linux lsb-release "
    "rsync unzip tree htop "
    "parted fdisk exfatprogs dosfstools "
    "openssh-server"
)


def has_docker_compose():
    if shutil.which("docker-compose"):
        return True
    check = subprocess.run(
        ["docker", "compose", "version"],
        check=False,
        capture_output=True,
        text=True,
    )
    return check.returncode == 0


def ensure_docker_ready():
    global DOCKER_USE_SUDO
    package_manager = detect_package_manager()
    docker_installed = ensure_tool_exists("docker")
    compose_installed = has_docker_compose()

    if not docker_installed or not compose_installed:
        print("Instalando Docker e Docker Compose...")
        if package_manager == "pacman":
            result = run_command(["sudo", "pacman", "-S", "--noconfirm", "docker", "docker-compose"])
        elif package_manager == "apt":
            result = run_command(["sudo", "apt", "install", "-y", "docker.io", "docker-compose"])
        else:
            print("Gerenciador de pacotes nao suportado automaticamente.")
            return False
        if result is None:
            return False

    if not ensure_tool_exists("docker"):
        return False

    is_active = subprocess.run(
        ["systemctl", "is-active", "docker"],
        check=False,
        capture_output=True,
        text=True,
    ).returncode == 0

    if not is_active:
        print("Servico Docker nao esta ativo. Ativando...")
        if run_command(["sudo", "systemctl", "enable", "--now", "docker"]) is None:
            return False
    else:
        print("Servico Docker ja esta ativo.")

    docker_info = subprocess.run(
        ["docker", "info"],
        check=False,
        capture_output=True,
        text=True,
    )
    if docker_info.returncode != 0:
        stderr = (docker_info.stderr or "").lower()
        if "permission denied" in stderr or "docker.sock" in stderr:
            DOCKER_USE_SUDO = True
            print("Sem permissao no docker.sock. Usando sudo nos comandos Docker.")
        else:
            print("Docker instalado, mas nao foi possivel acessar o daemon.")
            if docker_info.stderr:
                print(docker_info.stderr.strip())
            return False
    return True


def run_container_setup_commands(container_id):
    if run_command(docker_command(["start", container_id])) is None:
        return False
    if run_command(docker_command(["exec", container_id, "bash", "-lc", "apt update"])) is None:
        return False
    if run_command(
        docker_command(
            [
                "exec",
                container_id,
                "bash",
                "-lc",
                f"apt install -y {CONTAINER_APT_PACKAGES}",
            ]
        )
    ) is None:
        return False
    return True


def create_basic_container(image_name):
    if run_command(docker_command(["pull", image_name])) is None:
        return

    created = run_command(docker_command(["run", "-dit", image_name, "bash"]), capture_output=True)
    if not created or not created.stdout.strip():
        print("Nao foi possivel criar o container.")
        return
    container_id = created.stdout.strip()
    run_command(docker_command(["ps", "-a"]))
    if not run_container_setup_commands(container_id):
        print("Falha ao configurar dependencias dentro do container.")
        return
    print(f"\nContainer pronto. ID: {container_id}")
    print(f"Para entrar agora: docker start -ai {container_id}")


def create_password_container(base_image):
    password = getpass.getpass("Qual sera a senha SSH do container? ").strip()
    if not password:
        print("Senha invalida.")
        return

    project_dir = Path.cwd() / "container_ssh"
    project_dir.mkdir(exist_ok=True)
    dockerfile_path = project_dir / "Dockerfile"
    safe_password = password.replace("\\", "\\\\").replace('"', '\\"')

    dockerfile_content = (
        f"FROM {base_image}\n\n"
        "ENV DEBIAN_FRONTEND=noninteractive\n\n"
        "RUN apt-get update && apt-get install -y openssh-server sudo\n"
        "RUN mkdir -p /var/run/sshd\n"
        f'RUN useradd -m aluno && echo "aluno:{safe_password}" | chpasswd\n'
        "RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config\n"
        "RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config\n"
        "EXPOSE 22\n"
        'CMD ["/usr/sbin/sshd","-D"]\n'
    )
    dockerfile_path.write_text(dockerfile_content, encoding="utf-8")
    print(f"Dockerfile gerado em: {dockerfile_path}")

    image_tag_default = "meu_ssh_debian" if "debian" in base_image else "meu_ssh_ubuntu"
    image_tag = input_with_prompt(f"Nome da imagem Docker (padrao: {image_tag_default}): ").strip() or image_tag_default
    container_name_default = "lab1" if "debian" in base_image else "lab2"
    container_name = input_with_prompt(
        f"Nome do container (padrao: {container_name_default}): "
    ).strip() or container_name_default
    port = input_with_prompt("Porta local para SSH (padrao: 2222): ").strip() or "2222"

    if run_command(docker_command(["build", "-t", image_tag, "."]), workdir=str(project_dir)) is None:
        print("Falha no build da imagem Docker. Corrija o erro e tente novamente.")
        return
    if run_command(docker_command(["run", "-d", "-p", f"{port}:22", "--name", container_name, image_tag])) is None:
        print("Falha ao criar/executar o container com SSH.")
        return
    if not run_container_setup_commands(container_name):
        print("Falha ao instalar dependencias dentro do container.")
        return
    print(f"\nContainer com SSH pronto. Use: ssh aluno@127.0.0.1 -p {port}")


def list_containers():
    result = run_command(
        docker_command(["ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}"]),
        capture_output=True,
    )
    if not result or not result.stdout.strip():
        return []

    containers = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        containers.append(
            {
                "id": parts[0],
                "image": parts[1],
                "name": parts[2],
                "status": parts[3],
            }
        )
    return containers


def select_container_from_list():
    containers = list_containers()
    if not containers:
        print("Nenhum container encontrado.")
        return None

    print("\nCONTAINERS:")
    for idx, item in enumerate(containers, start=1):
        print(f"{idx}) {item['id']} | {item['name']} | {item['image']} | {item['status']}")

    choice = input_with_prompt("Escolha o numero do container: ").strip()
    if not choice.isdigit():
        print("Opcao invalida.")
        return None
    index = int(choice)
    if index < 1 or index > len(containers):
        print("Opcao invalida.")
        return None
    return containers[index - 1]


def docker_menu_flow():
    if not ensure_docker_ready():
        print("Nao foi possivel validar/instalar Docker.")
        wait_for_enter()
        return

    while True:
        clear_screen()
        print_header("Auto - Docker")
        choice = show_docker_menu()
        if choice == "0":
            return
        if choice == "1":
            create_basic_container("debian")
        elif choice == "2":
            create_basic_container("ubuntu")
        elif choice == "3":
            create_password_container("debian:stable")
        elif choice == "4":
            create_password_container("ubuntu:22.04")
        elif choice == "5":
            selected = select_container_from_list()
            if selected:
                status = selected.get("status", "").lower()
                if status.startswith("up"):
                    run_command(docker_command(["exec", "-it", selected["name"], "bash"]))
                else:
                    if run_command(docker_command(["start", selected["id"]])) is not None:
                        run_command(docker_command(["exec", "-it", selected["name"], "bash"]))
        elif choice == "6":
            selected = select_container_from_list()
            if selected:
                status = selected.get("status", "").lower()
                if status.startswith("up"):
                    run_command(docker_command(["rm", "-f", selected["id"]]))
                else:
                    run_command(docker_command(["rm", selected["id"]]))
        wait_for_enter()


def create_paperkey_template(template_path):
    if os.path.exists(template_path):
        return
    lines = [
        "1: 00 XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XXXXXX",
        "2: 00 XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XXXXXX",
        "3: ...",
        "4: ...",
        "5: ...",
        "6: ...",
        "7: ...",
    ]
    with open(template_path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")


def recover_key_flow():
    print_header("Recuperar Chave Privada (GPG + paperkey)")
    if not ensure_tool_exists("gpg") or not ensure_tool_exists("paperkey"):
        return

    recover_dir = os.path.expanduser("~/recover")
    os.makedirs(recover_dir, exist_ok=True)
    os.chmod(recover_dir, 0o700)
    print(f"Pasta preparada: {recover_dir}")

    public_key_path = input_with_prompt("Caminho do arquivo key_public.asc: ").strip()
    public_key_path = os.path.expanduser(public_key_path)
    if not os.path.exists(public_key_path):
        print("Arquivo de chave publica nao encontrado.")
        return

    run_command(["gpg", "--homedir", recover_dir, "--import", public_key_path])
    run_command(["gpg", "--homedir", recover_dir, "--list-keys", "--fingerprint"])

    template_path = os.path.expanduser("~/paperkey.txt")
    create_paperkey_template(template_path)
    print(f"\nTemplate pronto em: {template_path}")
    print("Preencha o arquivo com as 7 linhas do PDF e salve.")
    input_with_prompt("Pressione Enter quando terminar de editar o paperkey.txt...")

    fingerprint = input_with_prompt("Fingerprint para exportar public.gpg: ").strip()
    if not fingerprint:
        print("Fingerprint invalido.")
        return

    public_gpg_path = os.path.join(recover_dir, "public.gpg")
    secret_gpg_path = os.path.join(recover_dir, "secret.gpg")

    with open(public_gpg_path, "wb") as public_out:
        export_result = subprocess.run(
            ["gpg", "--homedir", recover_dir, "--export", fingerprint],
            check=False,
            stdout=public_out,
        )
    if export_result.returncode != 0:
        print("Falha ao exportar public.gpg.")
        return

    with open(secret_gpg_path, "wb") as secret_out:
        reconstruct_result = subprocess.run(
            [
                "paperkey",
                "--pubring",
                public_gpg_path,
                "--secrets",
                template_path,
            ],
            check=False,
            stdout=secret_out,
        )
    if reconstruct_result.returncode != 0:
        print("Falha ao reconstruir secret.gpg com paperkey.")
        return

    run_command(["gpg", "--homedir", recover_dir, "--import", secret_gpg_path])
    run_command(["gpg", "--homedir", recover_dir, "--list-secret-keys", "--fingerprint"])

    output_path = input_with_prompt(
        "Arquivo de saida da chave privada (ex: ~/yourname-private.asc): "
    ).strip()
    output_path = os.path.expanduser(output_path)
    if not output_path:
        print("Caminho de saida invalido.")
        return

    with open(output_path, "w", encoding="utf-8") as private_out:
        export_secret_result = subprocess.run(
            [
                "gpg",
                "--homedir",
                recover_dir,
                "--export-secret-keys",
                "-a",
                fingerprint,
            ],
            check=False,
            stdout=private_out,
        )
    if export_secret_result.returncode != 0:
        print("Falha ao exportar chave privada em ASCII.")
        return

    run_command(["gpg", "--homedir", recover_dir, "--list-secret-keys"])
    print(f"\nConcluido. Chave privada exportada para: {output_path}")
    print("Na outra maquina, importe com: gpg --import <arquivo.asc>")


def collect_paperkey_lines():
    print(
        "\nDigite as 7 linhas do paperkey (uma por vez), no formato:\n"
        "1: 00 ...\n2: 00 ...\n3: ...\n4: ...\n5: ...\n6: ...\n7: ..."
    )
    lines = []
    for index in range(1, 8):
        line = input_with_prompt(f"Linha {index}: ").rstrip()
        lines.append(line)
    return lines


def list_public_key_emails():
    result = run_command(["gpg", "--list-keys", "--with-colons"], capture_output=True)
    if not result or not result.stdout:
        return []

    emails = []
    seen = set()
    for line in result.stdout.splitlines():
        if not line.startswith("uid:"):
            continue
        parts = line.split(":")
        if len(parts) < 10:
            continue
        uid_text = parts[9]
        match = re.search(r"<([^>]+)>", uid_text)
        if match:
            email = match.group(1).strip()
        else:
            email = uid_text.strip()
        if "@" not in email:
            continue
        if email not in seen:
            seen.add(email)
            emails.append(email)
    return emails


def choose_recipient_email():
    emails = list_public_key_emails()
    if not emails:
        print("Nenhuma chave publica com email foi encontrada no GPG/Kleopatra.")
        return None

    print("\nCHAVES PUBLICAS (emails):")
    for index, email in enumerate(emails, start=1):
        print(f"{index}) {email}")

    while True:
        selected = input_with_prompt("Escolha o numero do email destinatario: ").strip()
        if not selected.isdigit():
            print("Digite apenas numero.")
            continue
        selected_index = int(selected)
        if 1 <= selected_index <= len(emails):
            return emails[selected_index - 1]
        print("Opcao invalida.")


def collect_multiline_ciphertext():
    print("\nCole o texto criptografado.")
    print("Se for bloco PGP, termina automaticamente em -----END PGP MESSAGE-----.")
    print("Se nao for bloco PGP, finalize com uma linha contendo apenas FIM.")

    lines = []
    saw_begin = False
    begin_marker = "-----BEGIN PGP MESSAGE-----"
    end_marker = "-----END PGP MESSAGE-----"

    while True:
        line = input()
        stripped = line.strip()

        if stripped == begin_marker:
            saw_begin = True

        lines.append(line)

        if saw_begin and stripped == end_marker:
            break
        if not saw_begin and stripped == "FIM":
            lines.pop()
            break

    return "\n".join(lines).strip()


def reconstruct_private_key_kleopatra_flow():
    print_header("Kleopatra - Reconstruir Chave Privada")
    if not install_crypto_dependencies():
        print("Instale as dependencias manualmente e tente novamente.")
        return

    recover_dir = os.path.expanduser("~/recover")
    os.makedirs(recover_dir, exist_ok=True)
    os.chmod(recover_dir, 0o700)
    print(f"Pasta preparada: {recover_dir}")

    key_name = input_with_prompt("Nome/caminho da chave publica (ex: math.asc): ").strip()
    key_path = os.path.expanduser(key_name)
    if not os.path.exists(key_path):
        print("Arquivo de chave publica nao encontrado.")
        return

    run_command(["gpg", "--homedir", recover_dir, "--import", key_path])
    run_command(["gpg", "--homedir", recover_dir, "--list-keys", "--fingerprint"])

    paperkey_lines = collect_paperkey_lines()
    paperkey_path = os.path.expanduser("~/paperkey.txt")
    with open(paperkey_path, "w", encoding="utf-8") as file:
        file.write("\n".join(paperkey_lines) + "\n")
    print(f"Arquivo criado: {paperkey_path}")

    fingerprint = input_with_prompt("Digite o ID/fingerprint da chave: ").strip()
    if not fingerprint:
        print("Fingerprint invalido.")
        return

    public_gpg_path = os.path.join(recover_dir, "public.gpg")
    secret_gpg_path = os.path.join(recover_dir, "secret.gpg")

    with open(public_gpg_path, "wb") as public_out:
        export_public = subprocess.run(
            ["gpg", "--homedir", recover_dir, "--export", fingerprint],
            check=False,
            stdout=public_out,
        )
    if export_public.returncode != 0:
        print("Falha ao gerar ~/recover/public.gpg")
        return

    with open(secret_gpg_path, "wb") as secret_out:
        rebuild = subprocess.run(
            ["paperkey", "--pubring", public_gpg_path, "--secrets", paperkey_path],
            check=False,
            stdout=secret_out,
        )
    if rebuild.returncode != 0:
        print("Falha ao gerar ~/recover/secret.gpg")
        return

    run_command(["gpg", "--homedir", recover_dir, "--import", secret_gpg_path])
    run_command(["gpg", "--homedir", recover_dir, "--list-secret-keys", "--fingerprint"])

    output_name = input_with_prompt(
        "Nome do arquivo de saida (ex: ~/yourname-private.asc): "
    ).strip()
    output_path = os.path.expanduser(output_name) if output_name else os.path.expanduser(
        "~/yourname-private.asc"
    )
    with open(output_path, "w", encoding="utf-8") as private_out:
        export_secret = subprocess.run(
            [
                "gpg",
                "--homedir",
                recover_dir,
                "--export-secret-keys",
                "-a",
                fingerprint,
            ],
            check=False,
            stdout=private_out,
        )
    if export_secret.returncode != 0:
        print("Falha ao exportar chave privada ASCII.")
        return

    run_command(["gpg", "--homedir", recover_dir, "--list-secret-keys"])
    print("\nChave privada reconstruida com sucesso.")
    print(f"Arquivo exportado: {output_path}")


def kleopatra_menu_flow():
    if not ensure_or_install_tool("kleopatra", "kleopatra"):
        print("Nao foi possivel validar/instalar Kleopatra.")
        wait_for_enter()
        return
    if not ensure_or_install_tool("gpg", "gnupg"):
        print("Nao foi possivel validar/instalar GnuPG.")
        wait_for_enter()
        return

    while True:
        clear_screen()
        print_header("Auto - Kleopatra")
        choice = show_kleopatra_menu()

        if choice == "0":
            return
        if choice == "1":
            encrypt_text_flow()
        elif choice == "2":
            decrypt_text_flow()
        elif choice == "3":
            encrypt_file_flow()
        elif choice == "4":
            decrypt_file_flow()
        elif choice == "5":
            reconstruct_private_key_kleopatra_flow()
        wait_for_enter()


def encrypt_file_flow():
    print_header("Criptografar Arquivo com GPG")
    if not ensure_tool_exists("gpg"):
        return

    recipient = choose_recipient_email()
    if not recipient:
        return

    file_path = os.path.expanduser(input_with_prompt("Nome/caminho do arquivo (ex: mensagem.txt): ").strip())
    if not os.path.exists(file_path):
        print("Arquivo invalido.")
        return
    run_command(["gpg", "--encrypt", "--recipient", recipient, file_path])


def decrypt_file_flow():
    print_header("Descriptografar Arquivo com GPG")
    if not ensure_tool_exists("gpg"):
        return

    file_path = os.path.expanduser(
        input_with_prompt(
            "Nome/caminho do arquivo criptografado (ex: arquivo.txt.gpg): "
        ).strip()
    )
    if not os.path.exists(file_path):
        print("Arquivo invalido.")
        return

    run_command(["gpg", "--decrypt", file_path])


def encrypt_text_flow():
    print_header("Criptografar Texto com GPG (armor)")
    if not ensure_tool_exists("gpg"):
        return

    recipient = choose_recipient_email()
    if not recipient:
        return

    text = input_with_prompt("Texto para criptografar: ")
    if not text:
        print("Texto invalido.")
        return

    result = run_command(
        ["gpg", "--encrypt", "--armor", "-r", recipient],
        capture_output=True,
        text_input=text,
    )
    if result and result.stdout:
        print("\nTexto criptografado (copie o bloco abaixo):")
        print("----- INICIO BLOCO -----")
        print(result.stdout.rstrip())
        print("----- FIM BLOCO -----")
    else:
        print("Nao foi possivel gerar saida criptografada.")


def decrypt_text_flow():
    print_header("Descriptografar Texto com GPG")
    if not ensure_tool_exists("gpg"):
        return

    ciphertext = collect_multiline_ciphertext()
    if not ciphertext:
        print("Texto criptografado invalido.")
        return

    result = run_command(
        ["gpg", "--decrypt"],
        capture_output=True,
        text_input=ciphertext,
    )
    if result and result.stdout:
        print("\nTexto descriptografado:")
        print("----- INICIO TEXTO -----")
        print(result.stdout.rstrip())
        print("----- FIM TEXTO -----")
    else:
        print("Nao foi possivel descriptografar o texto.")


def interactive_menu():
    while True:
        clear_screen()
        print_header("Auto - Automacao de Scripts")
        choice = show_main_menu()
        if choice == "0":
            print("\nSaindo...")
            return
        if choice == "1":
            nmap_scan_flow()
        elif choice == "2":
            recover_key_flow()
        elif choice == "3":
            encrypt_file_flow()
        elif choice == "4":
            encrypt_text_flow()
        wait_for_enter()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="auto",
        description="Automacao de comandos com Nmap e GPG/paperkey.",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("nmap", help="Abre o menu interativo de scans Nmap.")

    subparsers.add_parser("recover-key", help="Fluxo guiado de recuperacao de chave.")
    subparsers.add_parser("encrypt-file", help="Fluxo guiado para criptografar arquivo.")
    subparsers.add_parser("encrypt-text", help="Fluxo guiado para criptografar texto.")
    subparsers.add_parser("kleopatra", help="Menu de automacao da Kleopatra.")
    subparsers.add_parser("zip", help="Menu de automacao de compactacao/extracao.")
    subparsers.add_parser("ssh", help="Menu de automacao para chaves SSH.")
    subparsers.add_parser("docker", help="Menu de automacao para containers Docker.")

    return parser


def run_cli(args):
    if args.command == "nmap":
        nmap_scan_flow()
        return 0
    if args.command == "recover-key":
        recover_key_flow()
        return 0
    if args.command == "encrypt-file":
        encrypt_file_flow()
        return 0
    if args.command == "encrypt-text":
        encrypt_text_flow()
        return 0
    if args.command == "kleopatra":
        kleopatra_menu_flow()
        return 0
    if args.command == "zip":
        zip_menu_flow()
        return 0
    if args.command == "ssh":
        ssh_menu_flow()
        return 0
    if args.command == "docker":
        docker_menu_flow()
        return 0

    interactive_menu()
    return 0


def main():
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run_cli(args))


if __name__ == "__main__":
    main()
