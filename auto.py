import argparse
import os
import re
import shutil
import subprocess
import sys

from menus import show_kleopatra_menu, show_main_menu, show_nmap_menu
from utils import clear_screen, input_with_prompt, print_header, wait_for_enter


def run_command(command, capture_output=False, text_input=None):
    print(f"\nExecutando: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=capture_output,
            text=True,
            input=text_input,
        )
        return result
    except FileNotFoundError:
        print(f"Comando nao encontrado: {command[0]}")
    except subprocess.CalledProcessError as exc:
        print(f"Comando falhou com codigo {exc.returncode}.")
        if exc.stderr:
            print(exc.stderr)
    return None


def ensure_tool_exists(tool):
    if shutil.which(tool) is None:
        print(f"Dependencia ausente: {tool}")
        return False
    return True


def install_crypto_dependencies():
    if ensure_tool_exists("gpg") and ensure_tool_exists("paperkey"):
        return True

    if shutil.which("pacman"):
        print("Instalando dependencias com pacman...")
        result = run_command(["sudo", "pacman", "-S", "--noconfirm", "gnupg", "paperkey"])
    elif shutil.which("apt"):
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


def nmap_scan_flow():
    print_header("Scanner Nmap")
    print("Use apenas em hosts/redes com autorizacao.")
    if not ensure_tool_exists("nmap"):
        return

    target = input_with_prompt("Alvo (IP, host ou rede): ").strip()
    if not target:
        print("Alvo invalido.")
        return

    scan_choice = show_nmap_menu()
    scan_map = {
        "1": ["nmap", "-sn", target],
        "2": ["nmap", "-F", target],
        "3": ["nmap", "-p-", target],
        "4": ["nmap", "-sV", "-sC", target],
    }
    run_command(scan_map[scan_choice])


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

    nmap_parser = subparsers.add_parser("nmap", help="Executa um scan Nmap.")
    nmap_parser.add_argument("target", help="Alvo (IP, host ou rede).")
    nmap_parser.add_argument(
        "--mode",
        choices=["ping", "fast", "full", "detect"],
        default="fast",
        help="Tipo de scan.",
    )

    subparsers.add_parser("recover-key", help="Fluxo guiado de recuperacao de chave.")
    subparsers.add_parser("encrypt-file", help="Fluxo guiado para criptografar arquivo.")
    subparsers.add_parser("encrypt-text", help="Fluxo guiado para criptografar texto.")
    subparsers.add_parser("kleopatra", help="Menu de automacao da Kleopatra.")

    return parser


def run_cli(args):
    if args.command == "nmap":
        if not ensure_tool_exists("nmap"):
            return 1
        mode_map = {
            "ping": ["nmap", "-sn", args.target],
            "fast": ["nmap", "-F", args.target],
            "full": ["nmap", "-p-", args.target],
            "detect": ["nmap", "-sV", "-sC", args.target],
        }
        result = run_command(mode_map[args.mode])
        return 0 if result else 1
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

    interactive_menu()
    return 0


def main():
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run_cli(args))


if __name__ == "__main__":
    main()
