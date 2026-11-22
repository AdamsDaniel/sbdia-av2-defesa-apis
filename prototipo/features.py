"""Pseudonimização e janelas de 5 minutos com features relativas ao histórico.

Duas visões:
- ``principal``: usuário autenticado ou ``api_key`` de parceiro (logins
  recusados ficam fora, pois ainda não há sessão autenticada);
- ``ip``: IP de origem, apenas nos endpoints ``/auth/*`` (pega ataques
  distribuídos em muitos usuários, como credential stuffing).

As features "novidade" olham só para o passado da própria entidade
(últimos 14 dias), percorrendo as janelas em ordem cronológica.
"""
import hashlib
import hmac
import math
import os
import warnings
from collections import defaultdict, deque
from datetime import timedelta

import numpy as np
import pandas as pd

from config import (CAMINHO_LOGS, DATA_INICIO, HISTORICO_DIAS, JANELA_MINUTOS,
                    fora_do_horario)

FEATURES = [
    "log_requisicoes", "razao_volume", "endpoints_distintos", "recursos_novos",
    "taxa_falha", "usuarios_distintos", "raridade_horario", "pais_novo",
    "asn_novo", "ip_novo", "log_razao_bytes", "pix_acima_historico",
    "historico_curto",
    "novidades",
]
MIN_JANELAS_HISTORICO = 5
_CHAVE_DEMO = "chave-demonstracao-nao-usar-em-producao"


def chave_hmac():
    """Lê a chave HMAC do ambiente; sem ela usa uma chave de demonstração."""
    chave = os.environ.get("SBDIA_HMAC_KEY")
    if not chave:
        warnings.warn("SBDIA_HMAC_KEY não definida: usando chave de demonstração.")
        chave = _CHAVE_DEMO
    return chave.encode()


def pseudonimizar(valor, prefixo, chave):
    """HMAC-SHA256 truncado; o mesmo valor sempre gera o mesmo pseudônimo."""
    if not valor:
        return ""
    resumo = hmac.new(chave, str(valor).encode(), hashlib.sha256).hexdigest()
    return f"{prefixo}_{resumo[:12]}"


def carregar_logs(caminho=CAMINHO_LOGS):
    """Lê o CSV, converte o horário e calcula o índice do dia."""
    logs = pd.read_csv(caminho, keep_default_na=False, dtype={"recurso_id": str})
    logs["timestamp"] = pd.to_datetime(logs["timestamp"], format="ISO8601")
    inicio = pd.Timestamp(DATA_INICIO, tz=logs["timestamp"].dt.tz)
    logs["dia"] = (logs["timestamp"] - inicio).dt.days
    return logs


def _agregar_visao(logs, visao, coluna_entidade):
    """Agrega as requisições de uma visão em janelas entidade x 5 min."""
    dados = logs[logs[coluna_entidade] != ""].copy()
    dados["visao"] = visao
    dados["entidade_tipo"] = np.where(
        dados["api_key_hash"] != "", "api_key", "usuario") if visao == "principal" else "ip"
    dados["entidade_hash"] = dados[coluna_entidade]
    dados["janela_inicio"] = dados["timestamp"].dt.floor(f"{JANELA_MINUTOS}min")
    dados["falha"] = dados["status"].isin([401, 403, 404, 429])
    dados["pix"] = dados["endpoint"] == "/pix/transferencias"
    grupos = dados.groupby(["visao", "entidade_tipo", "entidade_hash", "janela_inicio"],
                           sort=False)
    janelas = grupos.agg(
        requisicoes=("request_id", "size"),
        endpoints_distintos=("endpoint", "nunique"),
        usuarios_distintos=("usuario_hash", "nunique"),
        falhas=("falha", "sum"),
        qtd_pix=("pix", "sum"),
        bytes_total=("bytes_resposta", "sum"),
        recursos=("recurso_id", lambda s: set(v for v in s if v)),
        paises=("pais", set),
        asns=("asn", set),
        ips_hash=("ip_hash", set),
        ip=("ip", lambda s: s.mode().iloc[0]),
        ip_hash=("ip_hash", lambda s: s.mode().iloc[0]),
        pais=("pais", lambda s: s.mode().iloc[0]),
        endpoint_principal=("endpoint", lambda s: s.mode().iloc[0]),
        ataque_id=("ataque_id", lambda s: next((v for v in s if v), "")),
        cenario=("cenario", lambda s: next((v for v in s if v), "")),
        dia=("dia", "first"),
    ).reset_index()
    if visao == "ip":
        janelas["usuarios_distintos"] = janelas["usuarios_distintos"].astype(int)
    else:
        janelas["usuarios_distintos"] = 0
    return janelas


def _raridade(contagem_horas, hora):
    """-log10 da frequência suavizada de janelas anteriores na faixa hora ±1."""
    n_anteriores = sum(contagem_horas)
    n_faixa = sum(contagem_horas[(hora + d) % 24] for d in (-1, 0, 1))
    return -math.log10((n_faixa + 1) / (n_anteriores + 2))


class HistoricoEntidade:
    """Estado incremental de uma entidade (últimos 14 dias)."""

    def __init__(self):
        self.janelas = deque()           # (inicio, hora, requisicoes, bytes, pix)
        self.vistos = defaultdict(dict)  # tipo -> {valor: último instante}
        self.contagem_horas = [0] * 24

    def podar(self, agora):
        """Descarta janelas mais antigas que o horizonte do histórico."""
        limite = agora - timedelta(days=HISTORICO_DIAS)
        while self.janelas and self.janelas[0][0] < limite:
            antiga = self.janelas.popleft()
            self.contagem_horas[antiga[1]] -= 1
        return limite

    def medianas_no_horario(self, hora):
        """Medianas de requisições e bytes nas janelas da faixa hora ±1.

        Compara a entidade com ela mesma naquele horário (um lote que roda
        todo dia às 2h não é anômalo às 2h). Com menos de 3 janelas na faixa,
        usa todas as janelas do histórico.
        """
        faixa = [j for j in self.janelas
                 if min((j[1] - hora) % 24, (hora - j[1]) % 24) <= 1]
        base = faixa if len(faixa) >= 3 else self.janelas
        return (float(np.median([j[2] for j in base])),
                float(np.median([j[3] for j in base])))

    def novos(self, tipo, valores, limite):
        """Quantos valores não foram vistos dentro do horizonte."""
        vistos = self.vistos[tipo]
        return sum(1 for v in valores if vistos.get(v, limite - timedelta(1)) < limite)

    def atualizar(self, inicio, linha):
        """Registra a janela atual no histórico (depois de calcular as features)."""
        self.janelas.append((inicio, inicio.hour, linha.requisicoes, linha.bytes_total,
                             linha.qtd_pix))
        self.contagem_horas[inicio.hour] += 1
        for tipo, valores in (("pais", linha.paises), ("asn", linha.asns),
                              ("ip", linha.ips_hash), ("recurso", linha.recursos)):
            for valor in valores:
                self.vistos[tipo][valor] = inicio


def calcular_features(janelas):
    """Percorre as janelas em ordem cronológica e calcula as features.

    ``endpoints_distintos``, ``usuarios_distintos`` e ``qtd_pix`` já vêm da agregação.
    """
    janelas = janelas.sort_values("janela_inicio", kind="stable").reset_index(drop=True)
    historicos = defaultdict(HistoricoEntidade)
    registros = []
    for linha in janelas.itertuples(index=False):
        historico = historicos[(linha.visao, linha.entidade_hash)]
        limite = historico.podar(linha.janela_inicio)
        anteriores = len(historico.janelas)
        curto = anteriores < MIN_JANELAS_HISTORICO
        if curto:
            razao_volume, razao_bytes = 0.0, 0.0
            pais_novo = asn_novo = ip_novo = 0
            recursos_novos = 0
            pix_acima = 0
        else:
            mediana_req, mediana_bytes = historico.medianas_no_horario(
                linha.janela_inicio.hour)
            razao_volume = math.log1p(linha.requisicoes / max(mediana_req, 1))
            razao_bytes = math.log1p(linha.bytes_total / max(mediana_bytes, 1))
            pais_novo = int(historico.novos("pais", linha.paises, limite) > 0)
            asn_novo = int(historico.novos("asn", linha.asns, limite) > 0)
            ip_novo = int(historico.novos("ip", linha.ips_hash, limite) > 0)
            recursos_novos = historico.novos("recurso", linha.recursos, limite)
            maximo_pix = max(j[4] for j in historico.janelas)
            pix_acima = max(0, int(linha.qtd_pix) - int(maximo_pix))
        raridade = _raridade(historico.contagem_horas, linha.janela_inicio.hour)
        novidades = (pais_novo + asn_novo + ip_novo + int(raridade >= 1.3)
                     + int(recursos_novos >= 5) + int(razao_bytes > 3)
                     + int(pix_acima >= 3))
        registros.append({
            "log_requisicoes": math.log1p(linha.requisicoes),
            "razao_volume": razao_volume,
            "recursos_novos": math.log1p(recursos_novos),
            "taxa_falha": linha.falhas / linha.requisicoes,
            "raridade_horario": raridade,
            "pais_novo": pais_novo,
            "asn_novo": asn_novo,
            "ip_novo": ip_novo,
            "log_razao_bytes": razao_bytes,
            "pix_acima_historico": pix_acima,
            "historico_curto": int(curto),
            "novidades": novidades,
        })
        historico.atualizar(linha.janela_inicio, linha)
    features = pd.DataFrame(registros)
    resultado = pd.concat([janelas.drop(columns=["recursos", "paises", "asns",
                                                  "ips_hash"]), features], axis=1)
    resultado["janela_fim"] = resultado["janela_inicio"] + pd.Timedelta(
        minutes=JANELA_MINUTOS)
    resultado["fora_horario"] = resultado["janela_inicio"].map(fora_do_horario)
    return resultado


def criar_janelas(caminho=CAMINHO_LOGS):
    """Pipeline completo: logs -> pseudônimos -> janelas -> features."""
    logs = carregar_logs(caminho)
    chave = chave_hmac()
    cache = {}

    def pseudo(valor, prefixo):
        if (valor, prefixo) not in cache:
            cache[(valor, prefixo)] = pseudonimizar(valor, prefixo, chave)
        return cache[(valor, prefixo)]

    logs["usuario_hash"] = [pseudo(v, "u") for v in logs["usuario_id"]]
    logs["api_key_hash"] = [pseudo(v, "k") for v in logs["api_key_id"]]
    logs["ip_hash"] = [pseudo(v, "ip") for v in logs["ip"]]
    logs["principal"] = np.where(logs["usuario_hash"] != "", logs["usuario_hash"],
                                 logs["api_key_hash"])
    # Login recusado não é atividade de quem está autenticado: fica só na visão por IP.
    login_recusado = (logs["endpoint"] == "/auth/login") & (logs["status"] == 401)
    logs.loc[login_recusado, "principal"] = ""
    logs["ip_auth"] = np.where(logs["endpoint"].str.startswith("/auth/"),
                               logs["ip_hash"], "")
    janelas = pd.concat([
        _agregar_visao(logs, "principal", "principal"),
        _agregar_visao(logs, "ip", "ip_auth"),
    ], ignore_index=True)
    tabela = (logs[logs["principal"] != ""]
              .drop_duplicates("principal")
              .set_index("principal")[["usuario_id", "api_key_id"]])
    return calcular_features(janelas), tabela
