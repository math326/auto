COMO FUNCIONA O AUTO:

auto é uma ferramenta CLI de automação para tarefas de infraestrutura, segurança defensiva, criptografia e bootstrap de ambientes de desenvolvimento.

Ela inclui:

auto nmap
Menu extenso de scans Nmap com execução guiada, leitura de alvos por IP/rede/arquivo, ajuste automático de CIDR quando necessário e execução com privilégios apropriados.

auto kleopatra
Fluxos para criptografar/descriptografar texto e arquivos com GPG, importar chaves públicas/privadas por arquivo ou bloco de texto, geração de chaves e reconstrução assistida de chave privada com paperkey.

auto zip
Menu completo para compactação e extração em múltiplos formatos (zip, gz, bz2, xz, tar.*, 7z, rar, cpio, ar), incluindo operações com senha, leitura sem extração e validações de dependência por opção.

auto ssh
Automação de geração e configuração de chaves SSH para GitHub e para acesso a máquinas remotas, com atualização de ~/.ssh/config, deploy de chave pública em authorized_keys e validação de serviço SSH.

auto docker
Criação e gerenciamento de containers Debian/Ubuntu, incluindo variantes com SSH/senha, instalação de pacotes base no container, entrada interativa em containers e remoção segura (com rm -f quando necessário).

auto website
Bootstrap completo de projeto web com Node.js + Express + PM2 + PostgreSQL + Nginx (ou Tor Onion Service), criação de estrutura inicial (server.js, index.html, style.css, .env), configuração de proxy em porta 80, perfis de sites para alternância rápida no Nginx e suporte a publicação Onion.

Em resumo: a ferramenta centraliza fluxos repetitivos em um menu único, reduz comandos manuais e padroniza setup/execução para quem trabalha com ambientes Linux.





COMO INSTALAR:

git clone https://github.com/math326/auto.git
cd auto
sudo bash install.sh
source ~/.bashrc
auto --help
