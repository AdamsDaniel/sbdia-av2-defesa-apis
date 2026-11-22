"""Treina Isolation Forest e autoencoder, avalia no teste e exporta os alertas.

Saídas em ``saida/``: ``janelas.pkl`` (scores por janela), ``metricas.json``,
``alertas.jsonl`` (contrato da seção 6), ``rotulos_analista.csv`` (semana 1)
e ``volume_previsto.csv``.
"""
import json
import warnings

import numpy as np
import pandas as pd

from avaliacao import avaliar, inicio_dos_ataques, rotulos_do_analista
from config import (DIAS_SEMANA_1, DIAS_TESTE, DIAS_TREINO, ORCAMENTO_ALERTAS_DIA,
                    PASTA_SAIDA, dia_no_intervalo)
from features import FEATURES, carregar_logs, criar_janelas
from modelos import DetectorPorVisao, deduplicar, escolher_limiar
from predicao_volume import ataques_com_pico, prever, volume_horario

MODELOS = {"isolation_forest": "Isolation Forest", "autoencoder": "Autoencoder"}
CENARIOS_CRITICOS = {"exfiltracao", "rajada_pix", "token_pais_asn_novo"}


def periodo(janelas, intervalo):
    """Filtra as janelas de um intervalo de dias."""
    return janelas[janelas["dia"].map(lambda d: dia_no_intervalo(d, intervalo))]


def treinar_modelos(janelas):
    """Treina os dois modelos no período de treino e define o limiar de cada um."""
    treino = periodo(janelas, DIAS_TREINO)
    dias_treino = DIAS_TREINO[1] - DIAS_TREINO[0] + 1
    limiares = {}
    for nome in MODELOS:
        detector = DetectorPorVisao(nome).fit(treino)
        coluna = f"score_{nome}"
        janelas[coluna] = detector.score(janelas)
        limiares[nome] = escolher_limiar(periodo(janelas, DIAS_TREINO), coluna,
                                         ORCAMENTO_ALERTAS_DIA, dias_treino)
    return limiares


def referencia_explicacao(janelas):
    """Mediana e IQR de cada feature no treino, por visão (para top_features)."""
    treino = periodo(janelas, DIAS_TREINO)
    referencia = {}
    for visao, grupo in treino.groupby("visao"):
        mediana = grupo[FEATURES].median()
        iqr = (grupo[FEATURES].quantile(0.75) - grupo[FEATURES].quantile(0.25))
        desvio = grupo[FEATURES].std().replace(0, 1)
        referencia[visao] = (mediana, iqr.where(iqr > 0, desvio))
    return referencia


def cenario_suspeito(linha):
    """Heurística legível sobre as features (nunca usa o rótulo)."""
    if linha.visao == "ip":
        if linha.taxa_falha >= 0.8 and linha.usuarios_distintos <= 1                 and linha.log_requisicoes >= np.log1p(8):
            return "forca_bruta"
        if linha.usuarios_distintos >= 2 or linha.taxa_falha >= 0.8:
            return "credential_stuffing"
    if linha.pix_acima_historico >= 3:
        return "rajada_pix"
    if linha.recursos_novos >= np.log1p(5):
        return "bola_enumeracao"
    if linha.entidade_tipo == "api_key" and linha.log_razao_bytes > 3:
        return "exfiltracao"
    if linha.entidade_tipo == "api_key" and (linha.razao_volume > 1.2
                                             or linha.taxa_falha >= 0.3):
        return "abuso_api_key"
    if linha.pais_novo or linha.asn_novo:
        return "token_pais_asn_novo"
    return "anomalia_comportamental"


def severidade(score, limiar, endpoint, cenario):
    """Regra de severidade da seção 6 das decisões.

    Alta: score a 3/4 do caminho entre o limiar e 1, ou endpoint de PIX/parceiro.
    """
    alta = (score >= limiar + 0.75 * (1 - limiar)
            or endpoint.startswith(("/pix", "/parceiros")))
    if alta and cenario in CENARIOS_CRITICOS:
        return "critica"
    return "alta" if alta else "media"


def montar_alertas(janelas, nome, limiar, referencia):
    """Converte os alertas deduplicados do teste no contrato JSON."""
    coluna = f"score_{nome}"
    alertas = deduplicar(periodo(janelas, DIAS_TESTE), coluna, limiar)
    registros, contador = [], {}
    for linha in alertas.itertuples(index=False):
        mediana, escala = referencia[linha.visao]
        valores = pd.Series({f: getattr(linha, f) for f in FEATURES})
        desvio = ((valores - mediana) / escala).sort_values(ascending=False)
        dia = linha.janela_fim.strftime("%Y%m%d")
        contador[dia] = contador.get(dia, 0) + 1
        cenario = cenario_suspeito(linha)
        score = round(float(linha.score_max), 4)
        registros.append({
            "alerta_id": f"ia-{dia}-{contador[dia]:06d}",
            "timestamp": linha.janela_fim.isoformat(),
            "janela_inicio": linha.janela_inicio.isoformat(),
            "janela_fim": linha.janela_fim.isoformat(),
            "origem": "ia",
            "modelo": nome,
            "entidade_tipo": linha.entidade_tipo,
            "entidade_hash": linha.entidade_hash,
            "ip_hash": linha.ip_hash,
            "ip": linha.ip,
            "pais": linha.pais,
            "endpoint_principal": linha.endpoint_principal,
            "score": score,
            "severidade": severidade(score, limiar, linha.endpoint_principal, cenario),
            "cenario_suspeito": cenario,
            "top_features": [{"nome": f, "valor": round(float(valores[f]), 3),
                              "mediana": round(float(mediana[f]), 3)}
                             for f in desvio[desvio > 0].index[:3]],
            "fora_horario": bool(linha.fora_horario),
            "_ataques": sorted(linha.ataques),
        })
    return registros


def salvar_alertas(registros):
    """Grava ``alertas.jsonl`` (sem o campo interno de avaliação)."""
    with open(PASTA_SAIDA / "alertas.jsonl", "w", encoding="utf-8") as arquivo:
        for registro in registros:
            publico = {k: v for k, v in registro.items() if not k.startswith("_")}
            arquivo.write(json.dumps(publico, ensure_ascii=False) + "\n")


def main():
    """Executa treino, avaliação, escolha do modelo e exportações."""
    warnings.filterwarnings("ignore", category=UserWarning)
    PASTA_SAIDA.mkdir(exist_ok=True)
    janelas, tabela = criar_janelas()
    # "Cofre" simulado: só o SOAR resolve pseudônimo -> identificador real.
    cofre = tabela.assign(cliente_real=tabela["usuario_id"].where(
        tabela["usuario_id"] != "", tabela["api_key_id"]))
    cofre["cliente_real"].rename_axis("entidade_hash").to_csv(
        PASTA_SAIDA / "tabela_pseudonimos.csv")
    logs = carregar_logs()
    inicios = inicio_dos_ataques(logs)
    limiares = treinar_modelos(janelas)

    metricas = {"orcamento_casos_dia": ORCAMENTO_ALERTAS_DIA, "modelos": {}}
    for nome in MODELOS:
        coluna = f"score_{nome}"
        metricas["modelos"][nome] = {
            "limiar": round(limiares[nome], 4),
            "treino": avaliar(periodo(janelas, DIAS_TREINO), coluna, limiares[nome], inicios),
            "semana_1": avaliar(periodo(janelas, DIAS_SEMANA_1), coluna, limiares[nome],
                                inicios),
            "teste": avaliar(periodo(janelas, DIAS_TESTE), coluna, limiares[nome], inicios),
        }

    # O modelo de produção é escolhido com o que o SOC sabe ao fim da semana 1.
    def chave(nome):
        semana = metricas["modelos"][nome]["semana_1"]
        return (semana["revocacao_ocorrencia"], -semana["falsos_positivos_por_dia"])

    principal = max(MODELOS, key=chave)
    metricas["modelo_principal"] = principal

    referencia = referencia_explicacao(janelas)
    registros = montar_alertas(janelas, principal, limiares[principal], referencia)
    salvar_alertas(registros)
    alertas = pd.DataFrame(registros)
    alertas["ataques"] = alertas["_ataques"].map(frozenset)
    # Triagem simulada de todos os alertas do teste, com tempo de resposta do
    # analista: 5–20 min no expediente e 10–40 min no plantão noturno.
    rotulos = rotulos_do_analista(alertas).drop(columns="entidade_hash")
    sorteio = np.random.default_rng(7)
    noturno = alertas["fora_horario"].to_numpy()
    rotulos["minutos_resposta"] = np.where(noturno, sorteio.integers(10, 41, len(alertas)),
                                           sorteio.integers(5, 21, len(alertas)))
    rotulos.to_csv(PASTA_SAIDA / "rotulos_analista.csv", index=False)
    metricas["alertas_exportados"] = len(registros)
    metricas["severidade"] = alertas["severidade"].value_counts().to_dict()
    metricas["cenario_suspeito_acerto"] = round(float(np.mean([
        r["cenario_suspeito"] in {a.rsplit("_", 1)[0] for a in r["_ataques"]}
        for r in registros if r["_ataques"]])), 3)

    tabela = volume_horario(logs)
    previsao = prever(tabela)
    previsao.to_csv(PASTA_SAIDA / "volume_previsto.csv", index=False)
    teste = previsao[previsao["hora"].dt.tz_convert(None) >= pd.Timestamp("2026-09-22")]
    picos = ataques_com_pico(teste, logs)
    metricas["predicao_volume"] = {
        "horas_avaliadas_teste": int(len(teste)),
        "alertas_teste": int(teste["alerta"].sum()),
        "alertas_por_endpoint": teste[teste["alerta"]].groupby("endpoint").size().to_dict(),
        "alertas_por_dia_cartoes": teste[teste["alerta"]
                                         & (teste["endpoint"] == "/cartoes/{id}")]
        .groupby(teste["hora"].dt.strftime("%Y-%m-%d")).size().astype(int).to_dict(),
        "ataques_com_pico_detectado": sorted(picos),
    }

    janelas.to_pickle(PASTA_SAIDA / "janelas.pkl")
    with open(PASTA_SAIDA / "metricas.json", "w", encoding="utf-8") as arquivo:
        json.dump(metricas, arquivo, ensure_ascii=False, indent=2, default=str)
    print(json.dumps({n: metricas["modelos"][n]["teste"] for n in MODELOS},
                     ensure_ascii=False, indent=2))
    print("modelo principal:", principal)
    print("predição de volume:", metricas["predicao_volume"])


if __name__ == "__main__":
    main()
