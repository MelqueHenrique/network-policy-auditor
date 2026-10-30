# Network Policy Auditor (NPA)

Ferramenta local de auditoria de políticas de rede: testa a conectividade TCP observada a partir do ponto onde é executada, compara os resultados com as políticas declaradas e gera relatórios para acompanhar divergências e mudanças.

Esta é uma continuação independente do projeto desenvolvido para o PFC II em Ciência da Computação pela Universidade Federal de Catalão (UFCAT), sob orientação do Prof. Dr. Ricardo Couto Antunes da Rocha. O repositório do trabalho acadêmico original permanece disponível em [validador-politicas-rede](https://github.com/MelqueHenrique/validador-politicas-rede).

A proposta aplica o paradigma de **Política como Código** (*Policy as Code*) à verificação de conformidade de redes: o estado desejado da rede é declarado em arquivos YAML, e os programas em Python confrontam essa declaração com o estado real observado, apontando divergências e acompanhando sua evolução ao longo do tempo.

## Por que existe

Redes segmentadas por VLANs acumulam dezenas ou centenas de regras de controle de
acesso. Conferir manualmente se cada regra continua em vigor é lento, esporádico e
sujeito a erro, e a documentação tende a divergir da configuração real com o tempo.
Estas ferramentas transformam a documentação em algo executável: o mesmo arquivo que
descreve o que deveria valer é a entrada que verifica se de fato vale.

## Os dois artefatos

| Arquivo | Papel |
|---|---|
| `validador.py` | Lê a política YAML, testa a rede via *sockets* TCP e gera dois relatórios: um `.txt` para conferência manual e um `.json` estruturado |
| `comparador.py` | Recebe dois relatórios `.json` de execuções distintas e classifica o que foi corrigido, o que surgiu de novo e o que persiste |

Nenhuma dependência além do `PyYAML`. Não é necessário instalar Nmap nem qualquer
binário externo, e não são exigidos privilégios de administrador: o teste usa a
biblioteca nativa `socket` do Python.

## Instalação

```bash
git clone https://github.com/MelqueHenrique/network-policy-auditor.git
cd network-policy-auditor
pip install pyyaml
```

Requer Python 3.8 ou superior.

## Uso

### 1. Declare a política

Copie `exemplos/politica-exemplo.yaml` e ajuste os valores para a sua rede. Ele é um
modelo genérico, sem relação com nenhuma rede real, e existe apenas para mostrar a
estrutura esperada. A política aceita três blocos, que podem ser combinados ou usados
isoladamente:

```yaml
# Portas que DEVEM estar acessíveis em ativos internos
regras_internas:
  - ip: "192.0.2.10"
    nome: "Servidor de Arquivos"
    portas_tcp_permitidas: [139, 445]

# Serviços externos que DEVEM permanecer alcançáveis (aceita nome de domínio)
regras_externas:
  - ip: "aplicacao.example.com"
    nome: "Sistema corporativo em nuvem"
    portas_tcp_permitidas: [443]

# Portas que JAMAIS devem responder a partir do ponto de origem do teste
regras_isolamento:
  - ip: "192.0.2.100"
    nome: "Estação de outro segmento de rede"
    portas_proibidas: [135, 139, 445, 3389]
```

A semântica de cada bloco é distinta:

- **`regras_internas`** e **`regras_externas`** usam lista de permissões. Uma porta
  aberta fora da lista é **violação**; uma porta declarada que não responde é **falha
  de disponibilidade**.
- **`regras_isolamento`** usa lista de proibições e inverte a lógica: aqui, qualquer
  conexão bem-sucedida é o resultado indesejado, pois indica que a fronteira entre
  segmentos não está sendo aplicada.

### 2. Execute o validador

Aponte a constante `ARQUIVO_POLITICA`, no início do `validador.py`, para o seu
arquivo de política e execute:

```bash
python validador.py
```

Além das portas declaradas, o validador sempre testa uma lista fixa de portas
historicamente associadas a serviços de risco (`SCAN_LIST_PADRAO`: 21, 22, 23, 80,
443, 139, 445, 3389, 8080, 8051 e 5060). É esse mecanismo que revela serviços ativos
sem previsão na política, e a lista pode ser ajustada à realidade de cada rede.

Cada execução gera dois arquivos com data e hora no nome:

```
relatorio_detalhado_2026-05-04_15-42-41.txt    <- leitura do analista
relatorio_detalhado_2026-05-04_15-42-41.json   <- entrada do comparador
```

### 3. Compare duas execuções

```bash
python comparador.py relatorio_ANTES.json relatorio_DEPOIS.json
```

A saída classifica cada ativo em corrigido, novo, persistente ou inalterado, e grava
um `comparativo_AAAA-MM-DD_HH-MM-SS.txt`. É esse passo que transforma verificações
isoladas em auditoria continuada: em vez de reler dois relatórios inteiros, o
administrador examina apenas o que mudou entre eles.

## Como o teste funciona

O validador tenta estabelecer uma conexão TCP com cada par de endereço e porta. Se o
*handshake* de três vias se completa, a porta está aberta e há serviço em escuta; se
a conexão é recusada ou expira o tempo limite, a porta é classificada como fechada.
A classificação dos resultados usa operações de conjuntos entre as portas observadas
(`O`) e as portas declaradas na política (`P`):

- `O ∩ P` → conformidades
- `O − P` → violações
- `P − O` → falhas de disponibilidade

## Limitações conhecidas

Declaradas abertamente, porque delimitam o alcance da ferramenta:

- **Somente TCP.** Serviços sobre UDP (DNS, SNMP, NTP, VoIP) não são auditados.
- **Porta filtrada e ativo desligado produzem o mesmo resultado.** Ambos resultam em
  tempo limite esgotado, e a ferramenta os classifica como fechados. Um ativo
  desligado pode, portanto, gerar um falso "conforme".
- **Verificação estática.** A ferramenta compara o estado configurado com o estado
  declarado. Não observa tráfego ao longo do tempo, e portanto não detecta anomalias
  de comportamento, exfiltração de dados ou ataques em curso.
- **Pareamento por endereço IP.** Em redes com endereçamento dinâmico, o mesmo IP
  pode corresponder a ativos distintos entre duas execuções.

## Sobre o arquivo de exemplo

`exemplos/politica-exemplo.yaml` é **puramente ilustrativo**: serve para mostrar a
estrutura aceita pelo validador e não corresponde a nenhuma rede real. Os endereços
usados pertencem à faixa `192.0.2.0/24`, reservada pela RFC 5737 exclusivamente para
documentação, e os domínios usam `example.com`, reservado pela RFC 2606.

Nenhum dado da rede estudada na monografia é distribuído neste repositório. O estudo
de caso foi conduzido em uma instituição hospitalar mediante compromisso de
anonimização, e as políticas e os relatórios daquele ambiente permanecem fora daqui.

## Projeto acadêmico original

A versão correspondente ao PFC II, incluindo sua documentação e os arquivos usados no trabalho, está preservada no repositório [validador-politicas-rede](https://github.com/MelqueHenrique/validador-politicas-rede).

## Licença

Distribuído sob a licença MIT. Consulte o arquivo `LICENSE`.

## Como citar

CASTRO, Melque Henrique Lemes de. **Verificação Automatizada de Políticas de
Segurança Baseada em Política como Código: Um Estudo de Caso em Redes Hospitalares**.
2026. Monografia (Bacharelado em Ciência da Computação) — Universidade Federal de
Catalão, Catalão, 2026.


