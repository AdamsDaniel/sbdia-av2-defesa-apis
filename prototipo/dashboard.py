"""Painel do SOC (Streamlit) com os resultados do protótipo.

Uso: ``streamlit run dashboard.py`` depois de ``python executar_tudo.py``.
Em produção, o mesmo conteúdo ficaria no OpenSearch Dashboards/Grafana.
"""
import json

import altair as alt
import pandas as pd
import streamlit as st

from config import COR_AE, COR_ALERTA, COR_IF, PASTA_SAIDA

st.set_page_config(page_title="Painel SOC – Corvina", layout="wide")
CORES_ROTULO = alt.Scale(domain=["Ataque", "Falso positivo"], range=[COR_AE, COR_IF])


@st.cache_data
def carregar():
    """Lê os artefatos gerados pelo pipeline."""
    alertas = pd.read_json(PASTA_SAIDA / "alertas.jsonl", lines=True)
    rotulos = pd.read_csv(PASTA_SAIDA / "rotulos_analista.csv")
    alertas = alertas.merge(rotulos, on="alerta_id", how="left")
    alertas["rotulo"] = alertas["rotulo_analista"].map(
        {"verdadeiro": "Ataque", "falso_positivo": "Falso positivo"})
    alertas["instante"] = pd.to_datetime(alertas["timestamp"]).dt.tz_localize(None)
    alertas["dia"] = alertas["instante"].dt.strftime("%d/%m")
    alertas["hora"] = alertas["instante"].dt.hour
    with open(PASTA_SAIDA / "metricas.json", encoding="utf-8") as arquivo:
        metricas = json.load(arquivo)
    with open(PASTA_SAIDA / "aprendizado_continuo.json", encoding="utf-8") as arquivo:
        aprendizado = json.load(arquivo)
    with open(PASTA_SAIDA / "soar" / "metricas_soar.json", encoding="utf-8") as arquivo:
        soar = json.load(arquivo)
    acoes = pd.read_json(PASTA_SAIDA / "soar" / "acoes.jsonl", lines=True)
    acoes = acoes[acoes["tipo"].notna()]  # linhas de evento de reversão ficam fora
    volume = pd.read_csv(PASTA_SAIDA / "volume_previsto.csv")
    volume["hora"] = pd.to_datetime(volume["hora"], utc=True).dt.tz_convert(
        "America/Sao_Paulo").dt.tz_localize(None)
    return alertas, metricas, aprendizado, soar, acoes, volume


alertas, metricas, aprendizado, soar, acoes, volume = carregar()
modelo = metricas["modelo_principal"]
teste = metricas["modelos"][modelo]["teste"]

st.title("Painel SOC — Corvina Crédito Digital")
st.caption(f"Dados fictícios · período de teste 22/09 a 30/09/2026 · modelo em produção: "
           f"{modelo.replace('_', ' ').title()} · orçamento de "
           f"{metricas['orcamento_casos_dia']} casos/dia por analista de plantão")

colunas = st.columns(6)
colunas[0].metric("Ataques detectados", f"{teste['detectadas']}/{teste['ocorrencias']}")
colunas[1].metric("Casos por dia", f"{teste['casos_por_dia']:.1f}")
colunas[2].metric("Falsos positivos/dia", f"{teste['falsos_positivos_por_dia']:.1f}")
colunas[3].metric("MTTD médio", f"{teste['mttd_min_medio']:.1f} min")
colunas[4].metric("Tempo até contenção", f"{soar['tempo_ate_contencao_minutos']['alta']['media'] * 60:.0f} s")
colunas[5].metric("MTTR (alta)", f"{soar['mttr_simulado_minutos']['alta']:.0f} min")

esquerda, direita = st.columns(2)
with esquerda:
    st.subheader("Alertas por dia")
    grafico = alt.Chart(alertas).mark_bar(cornerRadiusEnd=3).encode(
        x=alt.X("dia:O", title="Dia", axis=alt.Axis(labelAngle=0)),
        y=alt.Y("count():Q", title="Alertas"),
        color=alt.Color("rotulo:N", scale=CORES_ROTULO, title="Triagem"),
        tooltip=["dia", "rotulo", "count()"])
    st.altair_chart(grafico, use_container_width=True)
with direita:
    st.subheader("Alertas por hora (fora do expediente: 19h–7h)")
    faixas = pd.DataFrame({"inicio": [-0.5, 18.5], "fim": [6.5, 23.5]})
    fundo = alt.Chart(faixas).mark_rect(color="#e4e3df", opacity=0.6).encode(
        x="inicio:Q", x2="fim:Q")
    barras = alt.Chart(alertas).mark_bar(size=14).encode(
        x=alt.X("hora:Q", title="Hora", scale=alt.Scale(domain=[-0.5, 23.5]),
                axis=alt.Axis(values=list(range(0, 24, 2)))),
        y=alt.Y("count():Q", title="Alertas"),
        color=alt.Color("rotulo:N", scale=CORES_ROTULO, title="Triagem"),
        tooltip=["hora", "rotulo", "count()"])
    st.altair_chart(fundo + barras, use_container_width=True)

st.subheader("Predição de volume por endpoint (esperado + 3σ robusto)")
endpoint = st.selectbox("Endpoint", sorted(volume["endpoint"].unique()),
                        index=sorted(volume["endpoint"].unique()).index("/auth/login"))
serie = volume[(volume["endpoint"] == endpoint) & (volume["hora"] >= "2026-09-22")].copy()
serie["limite"] = serie["esperado"] + 3 * serie["desvio"]
base = alt.Chart(serie).encode(x=alt.X("hora:T", title=None,
                                       axis=alt.Axis(format="%d/%m %Hh", labelAngle=0)))
banda = base.mark_area(color=COR_IF, opacity=0.15).encode(y=alt.Y("limite:Q", title="Requisições/hora"))
esperado = base.mark_line(color=COR_IF, strokeWidth=2).encode(y="esperado:Q")
observado = base.mark_line(color="#52514e", strokeWidth=1.2).encode(
    y="observado:Q", tooltip=["hora:T", "observado:Q", "esperado:Q"])
pontos = base.transform_filter("datum.alerta").mark_circle(color=COR_ALERTA, size=70).encode(
    y="observado:Q")
st.altair_chart(banda + esperado + observado + pontos, use_container_width=True)

esquerda, direita = st.columns(2)
with esquerda:
    st.subheader("Aprendizado contínuo (semana 2)")
    semana = aprendizado["semana_2"]
    tabela = pd.DataFrame({
        "Configuração": ["Sem feedback", "Com allowlist", "Ciclo completo"],
        "Falsos positivos/dia": [semana[k]["falsos_positivos_por_dia"]
                                 for k in ("antes", "so_allowlist", "depois")]})
    grafico = alt.Chart(tabela).mark_bar(color=COR_IF, cornerRadiusEnd=3).encode(
        x=alt.X("Configuração:N", sort=None, axis=alt.Axis(labelAngle=0)),
        y="Falsos positivos/dia:Q",
        tooltip=list(tabela.columns))
    st.altair_chart(grafico, use_container_width=True)
    st.caption(f"Ataques detectados: {semana['depois']['detectadas']}/"
               f"{semana['depois']['ocorrencias']} · PSI máximo "
               f"{aprendizado['psi_maximo']:.2f} (gatilho 0,20) · candidato implantado: "
               f"{'sim' if aprendizado['retreino']['candidato_implantado'] else 'não'}")
with direita:
    st.subheader("Ações do SOAR por tipo e estado")
    grafico = alt.Chart(acoes).mark_bar().encode(
        y=alt.Y("tipo:N", title=None), x=alt.X("count():Q", title="Ações"),
        color=alt.Color("estado:N", title="Estado",
                        scale=alt.Scale(range=[COR_IF, COR_AE, "#1baf7a", "#6250d6"])),
        tooltip=["tipo", "estado", "count()"])
    st.altair_chart(grafico, use_container_width=True)

st.subheader("Alertas recentes")
colunas_tabela = ["alerta_id", "timestamp", "severidade", "cenario_suspeito", "score",
                  "endpoint_principal", "pais", "rotulo"]
st.dataframe(alertas.sort_values("timestamp", ascending=False)[colunas_tabela],
             use_container_width=True, hide_index=True, height=320)
