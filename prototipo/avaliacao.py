"""Métricas por ocorrência de ataque, por caso do analista e MTTD.

Os rótulos (``ataque_id``/``cenario``) só são usados aqui, nunca no treino.
SQLi/XSS fica fora da avaliação da IA: é tratado por regra do WAF/Wazuh.
"""
import numpy as np
import pandas as pd

from modelos import agrupar_casos, deduplicar

CENARIOS_REGRA = {"injecao_sql_xss"}


def ocorrencias(janelas):
    """Conjunto de ataques avaliáveis pela IA presentes nas janelas."""
    mascara = (janelas["ataque_id"] != "") & ~janelas["cenario"].isin(CENARIOS_REGRA)
    return set(janelas.loc[mascara, "ataque_id"])


def inicio_dos_ataques(logs):
    """Instante da primeira requisição de cada ataque."""
    ataques = logs[logs["ataque_id"] != ""]
    return ataques.groupby("ataque_id")["timestamp"].min()


def fora_da_allowlist(janelas, allowlist):
    """Máscara das janelas que não estão cobertas por uma entrada válida da allowlist.

    ``allowlist`` mapeia ``entidade_hash`` -> instante de expiração (TTL).
    """
    if not allowlist:
        return pd.Series(True, index=janelas.index)
    expira = janelas["entidade_hash"].map(allowlist)
    return expira.isna() | (janelas["janela_inicio"] >= expira)


def avaliar(janelas, coluna_score, limiar, inicios, allowlist=None):
    """Calcula as métricas de um período.

    - revocação por ocorrência (geral e por cenário);
    - casos/dia, falsos positivos/dia e precisão dos casos;
    - MTTD: do início do ataque ao fim da primeira janela que gerou alerta.
    """
    dias = janelas["dia"].nunique()
    alertas = deduplicar(janelas, coluna_score, limiar)
    alertas = alertas[fora_da_allowlist(alertas, allowlist)]
    alvo = ocorrencias(janelas)
    detectados = set().union(*alertas["ataques"]) & alvo if len(alertas) else set()

    if len(alertas):
        casos = agrupar_casos(alertas).groupby("caso")["ataques"].agg(
            lambda s: frozenset().union(*s))
        verdadeiros = int((casos.map(len) > 0).sum())
        total_casos = len(casos)
    else:
        verdadeiros = total_casos = 0

    cenario_de = (janelas[janelas["ataque_id"].isin(alvo)]
                  .drop_duplicates("ataque_id").set_index("ataque_id")["cenario"])
    por_cenario = {}
    for cenario, ids in cenario_de.groupby(cenario_de):
        por_cenario[cenario] = round(len(set(ids.index) & detectados) / len(ids), 3)

    mttd = []
    acima = janelas[(janelas[coluna_score] >= limiar)
                    & fora_da_allowlist(janelas, allowlist)]
    for ataque in detectados:
        primeira = acima.loc[acima["ataque_id"] == ataque, "janela_fim"].min()
        mttd.append(max(0.0, (primeira - inicios[ataque]).total_seconds() / 60))

    return {
        "ocorrencias": len(alvo),
        "detectadas": len(detectados),
        "revocacao_ocorrencia": round(len(detectados) / max(len(alvo), 1), 3),
        "revocacao_por_cenario": por_cenario,
        "nao_detectadas": sorted(alvo - detectados),
        "casos_por_dia": round(total_casos / dias, 2),
        "falsos_positivos_por_dia": round((total_casos - verdadeiros) / dias, 2),
        "precisao_casos": round(verdadeiros / total_casos, 3) if total_casos else None,
        "mttd_min_medio": round(float(np.mean(mttd)), 1) if mttd else None,
        "mttd_min_maximo": round(float(np.max(mttd)), 1) if mttd else None,
    }


def rotulos_do_analista(alertas):
    """Simula a triagem: o analista confirma ataque ou marca falso positivo."""
    return pd.DataFrame({
        "alerta_id": alertas["alerta_id"],
        "entidade_hash": alertas["entidade_hash"],
        "rotulo_analista": np.where(alertas["ataques"].map(len) > 0,
                                    "verdadeiro", "falso_positivo"),
        "comentario": np.where(alertas["ataques"].map(len) > 0,
                               "ataque confirmado na investigação",
                               "atividade legítima revisada"),
    })
