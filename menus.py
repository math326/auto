def _read_choice(valid_options):
    while True:
        choice = input("\nEscolha uma opcao: ").strip()
        if choice in valid_options:
            return choice
        print("Opcao invalida. Tente novamente.")


def show_main_menu():
    print("\nMENU PRINCIPAL:")
    print("1) Scanner Nmap")
    print("2) Recuperar chave privada (GPG + paperkey)")
    print("3) Criptografar arquivo com GPG")
    print("4) Criptografar texto com GPG (armor)")
    print("0) Sair")
    return _read_choice({"0", "1", "2", "3", "4"})


def show_nmap_menu():
    print("\nTIPO DE SCAN NMAP:")
    print("1) Ping scan (-sn)")
    print("2) Portas comuns (-F)")
    print("3) Scan completo de portas (-p-)")
    print("4) Deteccao de versao + scripts default (-sV -sC)")
    return _read_choice({"1", "2", "3", "4"})


def show_kleopatra_menu():
    print("\nKLEOPATRA:")
    print("1) Criptografar texto")
    print("2) Descriptografar texto")
    print("3) Criptografar arquivo")
    print("4) Descriptografar arquivo")
    print("5) Reconstruir chave privada")
    print("0) Voltar")
    return _read_choice({"0", "1", "2", "3", "4", "5"})
