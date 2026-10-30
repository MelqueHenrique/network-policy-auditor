import json
import sys
import os
import datetime

# ==============================================================================
# COMPARADOR DE RELATÓRIOS DE AUDITORIA - v2
# Universidade Federal de Catalão — PFC II
# Autor: Melque Henrique Lemes de Castro
#
# Este script compara dois relatórios JSON gerados pelo validador.py e mostra
# de forma clara o que mudou entre duas execuções de auditoria.
#
# USO:
#   python comparador.py <relatorio_antigo.json> <relatorio_novo.json>
#
# EXEMPLO:
#   python comparador.py relatorio_2025-12-10.json relatorio_2026-04-17.json
#
# O QUE ELE FAZ:
#   Para cada ativo presente nos dois relatórios, o script verifica:
#   - Se o STATUS mudou (ex: REPROVADO -> APROVADO)
#   - Quais violações foram CORRIGIDAS (existiam antes, sumiram agora)
#   - Quais violações são NOVAS (não existiam antes, apareceram agora)
#   - Quais violações PERSISTEM (existiam antes e continuam agora)
#   - O mesmo para falhas de disponibilidade e falhas de isolamento
#
# SAÍDA:
#   Além de exibir o resultado no terminal, o script gera automaticamente
#   um arquivo .txt com o relatório comparativo completo, no mesmo diretório
#   do script, com nome do tipo: comparativo_AAAA-MM-DD_HH-MM-SS.txt
# ==============================================================================


# --- Configuração de Log ---
DIRETORIO_SCRIPT = os.path.dirname(os.path.abspath(__file__))
timestamp_arquivo = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
nome_arquivo_log = f"comparativo_{timestamp_arquivo}.txt"
LOG_FILE = os.path.join(DIRETORIO_SCRIPT, nome_arquivo_log)


def log(mensagem=""):
    """
    Escreve a mensagem no terminal E no arquivo de log .txt.
    Substitui o uso direto de print() em todo o script para garantir
    que toda saída seja preservada no relatório em arquivo.
    """
    print(mensagem)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(mensagem + "\n")
    except Exception as e:
        # Se falhar ao escrever no arquivo, ainda mostra no terminal
        print(f"[Aviso] Erro ao salvar log: {e}")


def carregar_json(caminho):
    """
    Carrega um arquivo JSON de relatório.
    Encerra o programa com mensagem de erro se o arquivo não existir.
    """
    if not os.path.exists(caminho):
        log(f"ERRO: Arquivo não encontrado: {caminho}")
        sys.exit(1)

    with open(caminho, 'r', encoding='utf-8') as f:
        return json.load(f)


def indexar_resultados(relatorio):
    """
    Transforma a lista de resultados do JSON em um dicionário indexado por IP.

    Por quê? Porque precisamos comparar o mesmo ativo entre dois relatórios.
    Usar o IP como chave garante que estamos comparando o mesmo host,
    mesmo que o nome tenha mudado entre as execuções.

    Entrada:
        relatorio: dicionário carregado do JSON
    Saída:
        dicionário no formato { "192.168.x.x": { dados do ativo } }
    """
    index = {}
    for item in relatorio.get("resultados", []):
        ip = item["ip"]
        index[ip] = item
    return index


def comparar_listas(lista_antiga, lista_nova, label_corrigido, label_novo, label_persiste):
    """
    Compara duas listas de portas e classifica cada item em:
    - CORRIGIDO: estava na lista antiga, não está na nova (problema resolvido)
    - NOVO: não estava na lista antiga, está na nova (problema novo)
    - PERSISTE: estava em ambas (problema não resolvido)

    Esta função é usada tanto para violações quanto para falhas.
    """
    conjunto_antigo = set(lista_antiga)
    conjunto_novo   = set(lista_nova)

    corrigidos = conjunto_antigo - conjunto_novo   # Saíram da lista
    novos      = conjunto_novo - conjunto_antigo   # Entraram na lista
    persistem  = conjunto_antigo & conjunto_novo   # Continuam na lista

    if corrigidos:
        for item in sorted(corrigidos):
            log(f"      [OK] {label_corrigido}: Porta {item}")

    if novos:
        for item in sorted(novos):
            log(f"      [!!] {label_novo}: Porta {item}")

    if persistem:
        for item in sorted(persistem):
            log(f"      [--] {label_persiste}: Porta {item}")

    return len(corrigidos), len(novos), len(persistem)


def comparar_ativo_acessibilidade(ip, dados_antigo, dados_novo):
    """
    Compara os dados de um ativo do tipo 'acessibilidade' entre dois relatórios.
    Analisa violações (portas abertas indevidas) e falhas de disponibilidade.
    """
    nome          = dados_novo.get("nome", dados_antigo.get("nome", ip))
    status_antigo = dados_antigo.get("status", "?")
    status_novo   = dados_novo.get("status", "?")

    # Indicador visual de melhora ou piora
    if status_antigo != status_novo:
        if status_novo == "APROVADO":
            mudanca_status = f"[MELHOROU] {status_antigo} -> {status_novo}"
        else:
            mudanca_status = f"[PIOROU]   {status_antigo} -> {status_novo}"
    else:
        mudanca_status = f"[IGUAL]    {status_antigo} -> {status_novo}"

    log(f"\n   [{ip}] {nome}")
    log(f"   Status: {mudanca_status}")

    # Compara violações (portas abertas indevidas)
    violacoes_antigas = dados_antigo.get("violacoes", [])
    violacoes_novas   = dados_novo.get("violacoes", [])

    if violacoes_antigas or violacoes_novas:
        log("   Violacoes de Seguranca:")
        comparar_listas(
            violacoes_antigas,
            violacoes_novas,
            label_corrigido = "CORRIGIDA",
            label_novo      = "NOVA VIOLACAO",
            label_persiste  = "PERSISTE"
        )

    # Compara falhas de disponibilidade
    falhas_antigas = dados_antigo.get("falhas_disp", [])
    falhas_novas   = dados_novo.get("falhas_disp", [])

    if falhas_antigas or falhas_novas:
        log("   Falhas de Disponibilidade:")
        comparar_listas(
            falhas_antigas,
            falhas_novas,
            label_corrigido = "RESOLVIDA",
            label_novo      = "NOVA FALHA",
            label_persiste  = "PERSISTE"
        )


def comparar_ativo_isolamento(ip, dados_antigo, dados_novo):
    """
    Compara os dados de um ativo do tipo 'isolamento' entre dois relatórios.
    Analisa portas que deveriam estar bloqueadas mas estão acessíveis.
    """
    nome          = dados_novo.get("nome", dados_antigo.get("nome", ip))
    status_antigo = dados_antigo.get("status", "?")
    status_novo   = dados_novo.get("status", "?")

    if status_antigo != status_novo:
        if status_novo == "SEGMENTADO CORRETAMENTE":
            mudanca_status = f"[ACL EFETIVA] {status_antigo} -> {status_novo}"
        else:
            mudanca_status = f"[NOVA FALHA]  {status_antigo} -> {status_novo}"
    else:
        mudanca_status = f"[IGUAL]       {status_antigo} -> {status_novo}"

    log(f"\n   [{ip}] {nome}")
    log(f"   Status: {mudanca_status}")

    acessiveis_antigas = dados_antigo.get("portas_acessiveis", [])
    acessiveis_novas   = dados_novo.get("portas_acessiveis", [])

    if acessiveis_antigas or acessiveis_novas:
        log("   Portas de Isolamento:")
        comparar_listas(
            acessiveis_antigas,
            acessiveis_novas,
            label_corrigido = "BLOQUEADA (ACL funcionando)",
            label_novo      = "EXPOSTA (nova falha)",
            label_persiste  = "AINDA ACESSIVEL"
        )


def gerar_relatorio_comparativo(caminho_antigo, caminho_novo):
    """
    Função principal do comparador.
    Carrega os dois JSONs, identifica os ativos em comum e compara cada um.
    """
    relatorio_antigo = carregar_json(caminho_antigo)
    relatorio_novo   = carregar_json(caminho_novo)

    meta_antigo = relatorio_antigo.get("auditoria", {})
    meta_novo   = relatorio_novo.get("auditoria", {})

    log("\n" + "=" * 65)
    log("  RELATORIO COMPARATIVO DE AUDITORIAS DE SEGURANCA")
    log("=" * 65)
    log(f"  Relatorio ANTERIOR : {meta_antigo.get('data_hora', caminho_antigo)}")
    log(f"  Relatorio ATUAL    : {meta_novo.get('data_hora', caminho_novo)}")
    log(f"  Arquivo gerado     : {nome_arquivo_log}")
    log("=" * 65)

    index_antigo      = indexar_resultados(relatorio_antigo)
    index_novo        = indexar_resultados(relatorio_novo)

    ips_comuns        = set(index_antigo.keys()) & set(index_novo.keys())
    ips_apenas_antigo = set(index_antigo.keys()) - set(index_novo.keys())
    ips_apenas_novo   = set(index_novo.keys()) - set(index_antigo.keys())

    # --- Ativos presentes nos dois relatórios ---
    if ips_comuns:
        log("\nATIVOS COMPARADOS (presentes nos dois relatorios):")
        log("-" * 65)
        for ip in sorted(ips_comuns):
            dado_antigo = index_antigo[ip]
            dado_novo   = index_novo[ip]
            tipo        = dado_novo.get("tipo", dado_antigo.get("tipo", "acessibilidade"))

            if tipo == "isolamento":
                comparar_ativo_isolamento(ip, dado_antigo, dado_novo)
            else:
                comparar_ativo_acessibilidade(ip, dado_antigo, dado_novo)

    # --- Ativos removidos ---
    if ips_apenas_antigo:
        log("\n\nATIVOS REMOVIDOS (presentes antes, ausentes agora):")
        log("-" * 65)
        for ip in sorted(ips_apenas_antigo):
            nome = index_antigo[ip].get("nome", ip)
            log(f"   [{ip}] {nome}")

    # --- Novos ativos ---
    if ips_apenas_novo:
        log("\n\nNOVOS ATIVOS (ausentes antes, presentes agora):")
        log("-" * 65)
        for ip in sorted(ips_apenas_novo):
            nome = index_novo[ip].get("nome", ip)
            log(f"   [{ip}] {nome}")

    # --- Resumo final ---
    melhorias = 0
    pioras    = 0
    for ip in ips_comuns:
        s_antigo = index_antigo[ip].get("status", "")
        s_novo   = index_novo[ip].get("status", "")
        if s_antigo != s_novo:
            if s_novo in ("APROVADO", "SEGMENTADO CORRETAMENTE"):
                melhorias += 1
            else:
                pioras += 1

    log("\n\n" + "=" * 65)
    log("  RESUMO FINAL")
    log("=" * 65)
    log(f"  Total de ativos comparados : {len(ips_comuns)}")
    log(f"  Ativos removidos           : {len(ips_apenas_antigo)}")
    log(f"  Novos ativos adicionados   : {len(ips_apenas_novo)}")
    log(f"  Ativos que melhoraram      : {melhorias}")
    log(f"  Ativos que pioraram        : {pioras}")
    log("=" * 65 + "\n")

    print(f"\n>>> Relatorio salvo em: {LOG_FILE}\n")


# ==============================================================================
# PONTO DE ENTRADA
# ==============================================================================

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("\nUSO CORRETO:")
        print("  python comparador.py <relatorio_antigo.json> <relatorio_novo.json>")
        print("\nEXEMPLO:")
        print("  python comparador.py relatorio_2025-12-10.json relatorio_2026-04-17.json\n")
        sys.exit(1)

    gerar_relatorio_comparativo(sys.argv[1], sys.argv[2])