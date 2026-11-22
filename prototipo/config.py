"""Parâmetros centrais do protótipo (Corvina Crédito Digital S.A., dados fictícios)."""
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
PASTA_DADOS = RAIZ / "dados"
PASTA_SAIDA = RAIZ / "saida"
CAMINHO_LOGS = PASTA_DADOS / "logs_api.csv"

SEMENTE = 42
DATA_INICIO = "2026-09-01"
FUSO = "America/Sao_Paulo"
TOTAL_DIAS = 30

# Divisão temporal (índice do dia, 0 = 2026-09-01). Nunca embaralhar.
DIAS_AQUECIMENTO = (0, 6)    # só alimentam o histórico das entidades
DIAS_TREINO = (7, 20)        # treino sem rótulos
DIAS_TESTE = (21, 29)        # avaliação
DIAS_SEMANA_1 = (21, 24)     # analista rotula os alertas
DIAS_SEMANA_2 = (25, 29)     # compara antes x depois do retreino

JANELA_MINUTOS = 5
HISTORICO_DIAS = 14          # memória das features "nunca visto"
ORCAMENTO_ALERTAS_DIA = 5    # capacidade do analista de plantão
INTERVALO_DEDUP_MIN = 15     # janelas acima do limiar a até 15 min viram um alerta
TTL_ALLOWLIST_DIAS = 7

HORARIO_COMERCIAL = (7, 19)  # 7h às 18h59 em dias úteis

ENDPOINTS = {
    "login": "/auth/login",
    "token": "/auth/token",
    "saldo": "/contas/{id}/saldo",
    "extrato": "/contas/{id}/extrato",
    "pix": "/pix/transferencias",
    "cartao": "/cartoes/{id}",
    "parceiro": "/parceiros/v1/clientes",
}

# Cores (paleta categórica validada; texto em tons neutros).
COR_IF = "#2a78d6"
COR_AE = "#eb6834"
COR_ALERTA = "#e34948"
COR_TEXTO = "#0b0b0b"
COR_TEXTO_2 = "#52514e"
COR_GRADE = "#e4e3df"


def dia_no_intervalo(dia, intervalo):
    """Retorna True se o índice do dia estiver no intervalo fechado."""
    return intervalo[0] <= dia <= intervalo[1]


def fora_do_horario(timestamp):
    """Indica se o horário está fora do expediente (noite, madrugada ou fim de semana)."""
    if timestamp.weekday() >= 5:
        return True
    return not (HORARIO_COMERCIAL[0] <= timestamp.hour < HORARIO_COMERCIAL[1])
