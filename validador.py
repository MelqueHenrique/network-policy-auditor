import yaml
import socket
import datetime
import os
import json

# ==============================================================================
# VALIDADOR DE POLÍTICAS DE SEGURANÇA DE REDE - v6
# Universidade Federal de Catalão — PFC II
# Autor: Melque Henrique Lemes de Castro
#
# Este script lê um arquivo YAML contendo a política de segurança desejada
# e verifica se a rede real está em conformidade, gerando dois relatórios:
#   - Um arquivo .txt para conferencia manual do usuario (leitura direta)
#   - Um arquivo .json estruturado (para comparação automática entre execuções)
# ==============================================================================

# --- Configuração ---
DIRETORIO_SCRIPT = os.path.dirname(os.path.abspath(__file__))
ARQUIVO_POLITICA = os.path.join(DIRETORIO_SCRIPT, "politica-isolamento-apartamentos.yaml")
TIMEOUT_SOCKET   = 3.0

# Gera o timestamp único para nomear os arquivos desta execução
timestamp_arquivo = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_TXT  = os.path.join(DIRETORIO_SCRIPT, f"relatorio_detalhado_{timestamp_arquivo}.txt")
LOG_JSON = os.path.join(DIRETORIO_SCRIPT, f"relatorio_detalhado_{timestamp_arquivo}.json")

# Lista de portas críticas verificadas em TODOS os ativos,
# independentemente do que está declarado no YAML.
SCAN_LIST_PADRAO = [
    21,   # FTP   — Transferência de arquivos (inseguro, texto claro)
    22,   # SSH   — Acesso remoto Linux/Switch (crítico)
    23,   # Telnet — Acesso remoto legado (inseguro, texto claro)
    80,   # HTTP  — Web padrão
    443,  # HTTPS — Web seguro
    139,  # NetBIOS — Compartilhamento Windows antigo
    445,  # SMB   — Compartilhamento Windows (principal vetor de ransomware)
    3389, # RDP   — Acesso Remoto Windows (crítico)
    8080, # HTTP Alternativo — Proxy/Tomcat/Aplicações Web
    8051, # Porta de aplicação do ERP do hospital e sistema de prontuário eletrônico (PEP)
    5060  # SIP   — Telefonia IP/VoIP
]

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================

def log(mensagem):
    """Registra uma mensagem no terminal e no arquivo .txt."""
    if "---" in mensagem or "===" in mensagem:
        texto_final = mensagem
    else:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        texto_final = f"[{timestamp}] {mensagem}"

    print(texto_final)
    try:
        with open(LOG_TXT, "a", encoding="utf-8") as f:
            f.write(texto_final + "\n")
    except Exception as e:
        print(f"Erro ao salvar log TXT: {e}")


def testar_porta_tcp(ip, porta):
    """
    Tenta estabelecer uma conexão TCP com o IP e porta informados.
    Retorna "open" se o handshake foi bem-sucedido, "closed" caso contrário.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_SOCKET)
    try:
        resultado = s.connect_ex((ip, int(porta)))
        return "open" if resultado == 0 else "closed"
    except Exception:
        return "erro"
    finally:
        s.close()


def realizar_scan(ip, portas):
    """
    Varre um conjunto de portas em um IP e retorna o conjunto
    das portas que responderam (estado 'open').
    """
    abertas = set()
    for porta in portas:
        if testar_porta_tcp(ip, porta) == "open":
            abertas.add(porta)
    return abertas


# ==============================================================================
# FUNÇÕES DE AUDITORIA
# ==============================================================================

def auditar_host_permitido(host, scan_list_padrao):
    """
    Audita um ativo de Acessibilidade em Rede ou Dependência.
    Retorna um dicionário com o resultado estruturado para o JSON.
    """
    ip         = host['ip']
    nome       = host['nome']
    permitidas = set(host.get('portas_tcp_permitidas', []))

    log(f"Verificando: {nome} [{ip}]...")

    # Escopo de teste: portas da política + lista de risco padrão
    portas_para_testar = permitidas | set(scan_list_padrao)
    portas_abertas     = realizar_scan(ip, portas_para_testar)

    # Classificação por Teoria dos Conjuntos
    sucessos    = portas_abertas & permitidas   # O ∩ P
    violacoes   = portas_abertas - permitidas   # O - P
    falhas_disp = permitidas - portas_abertas   # P - O

    # Exibe resultados no terminal e no .txt
    for p in sorted(sucessos):
        log(f"   [v] OK: Porta {p} TCP respondeu corretamente (Autorizada).")
    for p in sorted(falhas_disp):
        log(f"   [!] FALHA: Porta {p} TCP deveria estar aberta, mas não respondeu.")
    for p in sorted(violacoes):
        log(f"   [X] VIOLAÇÃO: Porta {p} TCP está ABERTA indevidamente!")

    status = "APROVADO" if not violacoes and not falhas_disp else "REPROVADO"
    log(f"   >>> STATUS FINAL: {status}")
    log("-" * 50)

    # Retorna o resultado estruturado para o JSON
    return {
        "tipo"        : "acessibilidade",
        "nome"        : nome,
        "ip"          : ip,
        "status"      : status,
        "portas_ok"   : sorted(sucessos),
        "violacoes"   : sorted(violacoes),
        "falhas_disp" : sorted(falhas_disp),
    }


def auditar_isolamento(host):
    """
    Audita um ativo de Isolamento e Restrição.
    Aqui a lógica é invertida: qualquer porta que responda é uma falha crítica.
    Retorna um dicionário com o resultado estruturado para o JSON.
    """
    ip        = host['ip']
    nome      = host['nome']
    proibidas = set(host.get('portas_proibidas', []))

    log(f"Testando Isolamento (ACL): {nome} [{ip}]...")

    portas_abertas = realizar_scan(ip, proibidas)

    if not portas_abertas:
        log("   [v] SUCESSO: Nenhuma porta proibida foi acessada.")
        log("   >>> STATUS FINAL: SEGMENTADO CORRETAMENTE")
        status = "SEGMENTADO CORRETAMENTE"
    else:
        for p in sorted(portas_abertas):
            log(f"   [CRÍTICO] FALHA DE ISOLAMENTO: Porta {p} TCP está acessível!")
        log("   >>> STATUS FINAL: VULNERÁVEL (Sem segmentação efetiva)")
        status = "VULNERÁVEL"

    log("-" * 50)

    return {
        "tipo"              : "isolamento",
        "nome"              : nome,
        "ip"                : ip,
        "status"            : status,
        "portas_proibidas"  : sorted(proibidas),
        "portas_acessiveis" : sorted(portas_abertas),
    }


# ==============================================================================
# FUNÇÃO PRINCIPAL
# ==============================================================================

def executar_auditoria():
    log("\n" + "=" * 60)
    log("--- AUDITORIA DE REDE DETALHADA: PYTHON SOCKETS V6 ---")
    log(f"Política      : {ARQUIVO_POLITICA}")
    log(f"Relatório TXT : {LOG_TXT}")
    log(f"Relatório JSON: {LOG_JSON}")
    log("=" * 60 + "\n")

    # Lê o arquivo de política YAML
    try:
        with open(ARQUIVO_POLITICA, 'r', encoding='utf-8') as f:
            dados = yaml.safe_load(f)
    except Exception as e:
        log(f"ERRO CRÍTICO: Não foi possível ler o arquivo YAML: {e}")
        return

    # Estrutura que será salva no JSON ao final
    resultado_json = {
        "auditoria": {
            "data_hora"        : timestamp_arquivo,
            "arquivo_politica" : ARQUIVO_POLITICA,
        },
        "resultados": []
    }

    # 1. Audita regras internas (Acessibilidade em Rede)
    log(">>> INICIANDO TESTES DE ACESSIBILIDADE EM REDE <<<\n")
    for host in dados.get('regras_internas', []):
        resultado = auditar_host_permitido(host, SCAN_LIST_PADRAO)
        resultado_json["resultados"].append(resultado)

    # 2. Audita regras externas (Dependências)
    log(">>> INICIANDO TESTES DE DEPENDÊNCIAS <<<\n")
    for host in dados.get('regras_externas', []):
        resultado = auditar_host_permitido(host, SCAN_LIST_PADRAO)
        resultado_json["resultados"].append(resultado)

    # 3. Audita regras de isolamento
    log(">>> INICIANDO TESTES DE SEGMENTAÇÃO DE REDE <<<\n")
    for host in dados.get('regras_isolamento', []):
        resultado = auditar_isolamento(host)
        resultado_json["resultados"].append(resultado)

    # Salva o arquivo JSON
    try:
        with open(LOG_JSON, 'w', encoding='utf-8') as f:
            json.dump(resultado_json, f, ensure_ascii=False, indent=4)
        log(f"\nRelatório JSON salvo em: {LOG_JSON}")
    except Exception as e:
        log(f"Erro ao salvar JSON: {e}")

    log("\n" + "=" * 60)
    log("--- AUDITORIA CONCLUÍDA ---")
    log("=" * 60)


if __name__ == "__main__":
    executar_auditoria()
