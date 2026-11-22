"""Predição do volume por endpoint e hora, com alerta para desvio acima de 3σ.

Para cada hora, o volume esperado é a mediana da mesma hora nos 14 dias
anteriores do mesmo tipo (dia útil ou fim de semana). A dispersão σ é estimada
de forma robusta (1,4826 × MAD, com piso de √esperado, como numa contagem de
Poisson), para que um ataque passado não infle a linha de base. Alerta: observado
acima de ``esperado + 3σ`` e pelo menos 20 requisições acima do esperado.
"""
import pandas as pd

from config import HISTORICO_DIAS

DESVIO_MINIMO = 20


def volume_horario(logs):
    """Tabela de requisições por endpoint e hora (horas sem tráfego = 0)."""
    hora = logs["timestamp"].dt.floor("h")
    tabela = logs.groupby([logs["endpoint"], hora]).size().unstack(0, fill_value=0)
    indice = pd.date_range(tabela.index.min(), tabela.index.max(), freq="h")
    return tabela.reindex(indice, fill_value=0)


def prever(tabela):
    """Esperado, desvio-padrão e alerta para cada endpoint e hora."""
    resultados = []
    fim_de_semana = tabela.index.dayofweek >= 5
    for endpoint in tabela.columns:
        serie = tabela[endpoint]
        for posicao, instante in enumerate(tabela.index):
            mesmo_tipo = fim_de_semana == fim_de_semana[posicao]
            passado = ((tabela.index < instante)
                       & (tabela.index >= instante - pd.Timedelta(days=HISTORICO_DIAS))
                       & (tabela.index.hour == instante.hour) & mesmo_tipo)
            historico = serie[passado]
            if len(historico) < 3:
                continue
            esperado = float(historico.median())
            mad = float((historico - esperado).abs().median())
            desvio = max(1.4826 * mad, esperado ** 0.5, 1.0)
            observado = int(serie.iloc[posicao])
            resultados.append({
                "endpoint": endpoint, "hora": instante, "observado": observado,
                "esperado": round(esperado, 1), "desvio": round(desvio, 1),
                "alerta": bool(observado > esperado + 3 * desvio
                               and observado - esperado >= DESVIO_MINIMO),
            })
    return pd.DataFrame(resultados)


def ataques_com_pico(previsao, logs):
    """Ataques cujo endpoint teve alerta de volume na hora em que ocorreram."""
    ataques = logs[logs["ataque_id"] != ""]
    alertas = previsao[previsao["alerta"]]
    chaves = set(zip(alertas["endpoint"], alertas["hora"]))
    detectados = set()
    for ataque_id, grupo in ataques.groupby("ataque_id"):
        horas = set(zip(grupo["endpoint"], grupo["timestamp"].dt.floor("h")))
        if horas & chaves:
            detectados.add(ataque_id)
    return detectados
