"""Gera os gráficos PNG do protótipo a partir dos artefatos em ``saida/``."""
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from config import (COR_AE, COR_ALERTA, COR_GRADE, COR_IF, COR_TEXTO, COR_TEXTO_2,  # noqa: E402
                    DIAS_TESTE, PASTA_SAIDA)
from treinar_avaliar import periodo  # noqa: E402

plt.rcParams.update({
    "font.size": 11, "axes.edgecolor": COR_GRADE, "axes.labelcolor": COR_TEXTO_2,
    "xtick.color": COR_TEXTO_2, "ytick.color": COR_TEXTO_2, "axes.titlecolor": COR_TEXTO,
    "axes.titlesize": 13, "axes.titleweight": "bold", "axes.grid": True,
    "grid.color": COR_GRADE, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
})
NOMES = {"isolation_forest": "Isolation Forest", "autoencoder": "Autoencoder"}
CORES = {"isolation_forest": COR_IF, "autoencoder": COR_AE}


def salvar(figura, nome):
    """Salva a figura em 150 dpi."""
    figura.tight_layout()
    figura.savefig(PASTA_SAIDA / nome, dpi=150)
    plt.close(figura)


def distribuicao_scores(janelas, nome, limiar):
    """Histograma do score no teste: janelas normais x janelas de ataque."""
    teste = periodo(janelas, DIAS_TESTE)
    coluna = f"score_{nome}"
    ataque = teste["ataque_id"] != ""
    figura, eixo = plt.subplots(figsize=(9, 4.2))
    bins = np.linspace(0, 1, 41)
    eixo.hist(teste.loc[~ataque, coluna], bins=bins, color=COR_IF, label="Janelas normais",
              histtype="step", linewidth=2)
    eixo.hist(teste.loc[ataque, coluna], bins=bins, color=COR_AE, label="Janelas de ataque",
              histtype="step", linewidth=2)
    eixo.axvline(limiar, color=COR_TEXTO, linestyle="--", linewidth=1.5)
    eixo.text(limiar - 0.01, eixo.get_ylim()[1] * 0.3, f"limiar {limiar:.2f}",
              color=COR_TEXTO, ha="right")
    eixo.set_yscale("log")
    eixo.set(title=f"Distribuição do score de anomalia ({NOMES[nome]}, dias 21–29)",
             xlabel="Score (1 = mais anômalo)", ylabel="Janelas (escala log)")
    eixo.legend()
    salvar(figura, "distribuicao_scores.png")


def comparacao_modelos(metricas):
    """Três painéis: casos/dia, falsos positivos/dia e MTTD médio no teste."""
    paineis = [("casos_por_dia", "Casos por dia"),
               ("falsos_positivos_por_dia", "Falsos positivos por dia"),
               ("mttd_min_medio", "MTTD médio (min)")]
    figura, eixos = plt.subplots(1, 3, figsize=(10, 3.6))
    for eixo, (chave, titulo) in zip(eixos, paineis):
        valores = [metricas["modelos"][n]["teste"][chave] for n in NOMES]
        barras = eixo.bar(list(NOMES.values()), valores,
                          color=[CORES[n] for n in NOMES], width=0.55)
        eixo.bar_label(barras, fmt="%.1f", color=COR_TEXTO, padding=2)
        eixo.set_title(titulo, fontsize=11)
        eixo.set_ylim(0, max(valores) * 1.25)
        eixo.grid(axis="x", visible=False)
    revocacoes = {n: metricas["modelos"][n]["teste"] for n in NOMES}
    texto = " | ".join(f"{NOMES[n]}: {r['detectadas']}/{r['ocorrencias']} ataques"
                       for n, r in revocacoes.items())
    figura.suptitle(f"Comparação no teste (dias 21–29) — {texto}", fontsize=12,
                    color=COR_TEXTO)
    salvar(figura, "comparacao_modelos.png")


def volume_login():
    """Série horária de /auth/login no teste com esperado, banda de 3σ e alertas."""
    previsao = pd.read_csv(PASTA_SAIDA / "volume_previsto.csv", parse_dates=["hora"])
    serie = previsao[previsao["endpoint"] == "/auth/login"].copy()
    serie["hora"] = pd.to_datetime(serie["hora"], utc=True).dt.tz_convert("America/Sao_Paulo")
    serie = serie[serie["hora"] >= pd.Timestamp("2026-09-22", tz="America/Sao_Paulo")]
    figura, eixo = plt.subplots(figsize=(11, 4.2))
    limite = serie["esperado"] + 3 * serie["desvio"]
    eixo.fill_between(serie["hora"], 0, limite, color=COR_IF, alpha=0.15,
                      label="Esperado + 3σ (robusto)")
    eixo.plot(serie["hora"], serie["esperado"], color=COR_IF, linewidth=2,
              label="Volume esperado")
    eixo.plot(serie["hora"], serie["observado"], color=COR_TEXTO_2, linewidth=1.2,
              label="Volume observado")
    alertas = serie[serie["alerta"]]
    eixo.scatter(alertas["hora"], alertas["observado"], color=COR_ALERTA, s=40, zorder=3,
                 label="Alerta de desvio")
    eixo.set(title="Predição de volume em /auth/login (requisições por hora, dias 21–29)",
             ylabel="Requisições por hora")
    eixo.legend(loc="upper left", ncols=4)
    salvar(figura, "volume_login.png")


def alertas_por_hora():
    """Alertas exportados por hora do dia, separando ataque de falso positivo."""
    janelas = pd.read_pickle(PASTA_SAIDA / "janelas.pkl")
    alertas = pd.read_json(PASTA_SAIDA / "alertas.jsonl", lines=True)
    rotulo = janelas.set_index(["entidade_hash", "janela_inicio"])["ataque_id"]
    chave = list(zip(alertas["entidade_hash"], pd.to_datetime(alertas["janela_inicio"])))
    alertas["ataque"] = [bool(rotulo.get(k, "")) for k in chave]
    alertas["hora"] = pd.to_datetime(alertas["janela_inicio"]).map(lambda t: t.hour)
    tabela = alertas.groupby(["hora", "ataque"]).size().unstack(fill_value=0)
    tabela = tabela.reindex(range(24), fill_value=0)
    figura, eixo = plt.subplots(figsize=(10, 3.8))
    eixo.axvspan(-0.5, 6.5, color=COR_GRADE, alpha=0.5)
    eixo.axvspan(18.5, 23.5, color=COR_GRADE, alpha=0.5)
    falsos = tabela.get(False, pd.Series(0, index=tabela.index))
    ataques = tabela.get(True, pd.Series(0, index=tabela.index))
    eixo.bar(tabela.index, ataques, color=COR_AE, label="Ataque", width=0.8)
    eixo.bar(tabela.index, falsos, bottom=ataques, color=COR_IF, label="Falso positivo",
             width=0.8)
    eixo.set(title="Alertas por hora do dia (faixas cinza = fora do expediente)",
             xlabel="Hora", ylabel="Alertas", xticks=range(0, 24, 2))
    eixo.legend()
    salvar(figura, "alertas_por_hora.png")


def aprendizado(resultado):
    """Semana 2 antes e depois do feedback do analista."""
    rotulos = {"antes": "Sem feedback", "so_allowlist": "Com allowlist",
               "depois": "Após ciclo completo"}
    semana = resultado["semana_2"]
    figura, eixos = plt.subplots(1, 2, figsize=(10, 3.8))
    for eixo, (chave, titulo) in zip(eixos, [("falsos_positivos_por_dia",
                                               "Falsos positivos por dia"),
                                              ("precisao_casos", "Precisão dos casos")]):
        valores = [semana[k][chave] for k in rotulos]
        barras = eixo.bar(list(rotulos.values()), valores, color=[COR_IF, COR_AE, COR_AE],
                          width=0.55)
        eixo.bar_label(barras, fmt="%.2f", color=COR_TEXTO, padding=2)
        eixo.set_title(titulo, fontsize=11)
        eixo.set_ylim(0, max(valores) * 1.25)
        eixo.grid(axis="x", visible=False)
    detectadas = semana["depois"]
    figura.suptitle(f"Aprendizado contínuo na semana 2 (dias 25–29) — ataques detectados: "
                    f"{detectadas['detectadas']}/{detectadas['ocorrencias']} antes e depois",
                    fontsize=12, color=COR_TEXTO)
    salvar(figura, "aprendizado_continuo.png")


def main():
    """Gera todos os gráficos."""
    janelas = pd.read_pickle(PASTA_SAIDA / "janelas.pkl")
    with open(PASTA_SAIDA / "metricas.json", encoding="utf-8") as arquivo:
        metricas = json.load(arquivo)
    with open(PASTA_SAIDA / "aprendizado_continuo.json", encoding="utf-8") as arquivo:
        resultado = json.load(arquivo)
    nome = metricas["modelo_principal"]
    distribuicao_scores(janelas, nome, metricas["modelos"][nome]["limiar"])
    comparacao_modelos(metricas)
    volume_login()
    alertas_por_hora()
    aprendizado(resultado)
    print("Gráficos gerados em", PASTA_SAIDA)


if __name__ == "__main__":
    main()
