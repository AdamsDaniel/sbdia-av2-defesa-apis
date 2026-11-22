"""Ciclo de aprendizado contínuo com o feedback do analista (semana 1 → semana 2).

1. O analista rotula os alertas dos dias 21–24.
2. Entidades marcadas como falso positivo entram na allowlist (TTL de 7 dias):
   continuam sendo pontuadas, mas geram só registro, sem caso nem contenção.
3. Um modelo candidato é retreinado com os 14 dias mais recentes (9–22), sem
   as janelas dos ataques confirmados (evita envenenar o treino), e recebe
   um limiar novo pelo orçamento de casos.
4. Portão de qualidade: o candidato só é implantado se, nos dias 23–24 já
   rotulados, detectar pelo menos o mesmo que o atual com menos falsos positivos.
5. Mede-se a semana 2 (dias 25–29) antes e depois, e o PSI de cada feature.

Lê os artefatos de ``treinar_avaliar.py``; não re-treina o modelo base.
"""
import json
import warnings

import numpy as np
import pandas as pd

from avaliacao import avaliar, inicio_dos_ataques, rotulos_do_analista
from config import (DIAS_SEMANA_1, DIAS_SEMANA_2, DIAS_TREINO, ORCAMENTO_ALERTAS_DIA,
                    PASTA_SAIDA, TTL_ALLOWLIST_DIAS)
from features import FEATURES, carregar_logs
from modelos import DetectorPorVisao, deduplicar, escolher_limiar
from treinar_avaliar import periodo

DIAS_RETREINO = (9, 22)
DIAS_VALIDACAO = (23, 24)
LIMITE_PSI = 0.2


def psi(referencia, atual, faixas=10):
    """Population Stability Index entre duas amostras de uma feature."""
    cortes = np.unique(np.quantile(referencia, np.linspace(0, 1, faixas + 1))[1:-1])
    bordas = np.concatenate([[-np.inf], cortes, [np.inf]])
    ref = np.histogram(referencia, bordas)[0] + 1
    atu = np.histogram(atual, bordas)[0] + 1
    ref, atu = ref / ref.sum(), atu / atu.sum()
    return float(np.sum((atu - ref) * np.log(atu / ref)))


def main():
    """Executa o ciclo e grava ``aprendizado_continuo.json``."""
    warnings.filterwarnings("ignore", category=UserWarning)
    janelas = pd.read_pickle(PASTA_SAIDA / "janelas.pkl")
    with open(PASTA_SAIDA / "metricas.json", encoding="utf-8") as arquivo:
        metricas = json.load(arquivo)
    nome = metricas["modelo_principal"]
    coluna = f"score_{nome}"
    limiar_atual = metricas["modelos"][nome]["limiar"]
    inicios = inicio_dos_ataques(carregar_logs())

    # 1–2. Rótulos da semana 1, ataques confirmados e allowlist
    alertas_s1 = deduplicar(periodo(janelas, DIAS_SEMANA_1), coluna, limiar_atual)
    alertas_s1["alerta_id"] = [f"s1-{i:04d}" for i in range(len(alertas_s1))]
    rotulos = rotulos_do_analista(alertas_s1)
    # Allowlist com TTL: vale 7 dias a partir do fim da janela que o analista revisou.
    falsos = alertas_s1[rotulos["rotulo_analista"].to_numpy() == "falso_positivo"]
    validade = pd.Timedelta(days=TTL_ALLOWLIST_DIAS)
    allowlist = (falsos.groupby("entidade_hash")["janela_fim"].max() + validade).to_dict()
    confirmados = set().union(*alertas_s1["ataques"]) if len(alertas_s1) else set()

    # 3. Candidato: 14 dias recentes, sem ataques confirmados
    base = periodo(janelas, DIAS_RETREINO)
    base = base[~base["ataque_id"].isin(confirmados)]
    candidato = DetectorPorVisao(nome).fit(base)
    janelas["score_candidato"] = candidato.score(janelas)
    calibracao = periodo(janelas, DIAS_RETREINO)
    calibracao = calibracao[~calibracao["entidade_hash"].isin(list(allowlist))]
    limiar_candidato = escolher_limiar(calibracao, "score_candidato",
                                       ORCAMENTO_ALERTAS_DIA,
                                       DIAS_RETREINO[1] - DIAS_RETREINO[0] + 1)

    # 4. Portão de qualidade nos dias já rotulados
    validacao = periodo(janelas, DIAS_VALIDACAO)
    # sem allowlist: ela foi montada com estes mesmos dias e favoreceria o atual
    val_atual = avaliar(validacao, coluna, limiar_atual, inicios)
    val_cand = avaliar(validacao, "score_candidato", limiar_candidato, inicios)
    implantar = (val_cand["detectadas"] >= val_atual["detectadas"]
                 and val_cand["falsos_positivos_por_dia"]
                 <= val_atual["falsos_positivos_por_dia"])

    # 5. Semana 2: antes e depois
    semana_2 = periodo(janelas, DIAS_SEMANA_2)
    antes = avaliar(semana_2, coluna, limiar_atual, inicios)
    so_allowlist = avaliar(semana_2, coluna, limiar_atual, inicios, allowlist)
    if implantar:
        depois = avaliar(semana_2, "score_candidato", limiar_candidato, inicios, allowlist)
    else:
        depois = so_allowlist

    treino = periodo(janelas, DIAS_TREINO)
    psis = {f: round(psi(treino[f].to_numpy(float), semana_2[f].to_numpy(float)), 4)
            for f in FEATURES}

    resultado = {
        "modelo": nome,
        "semana_1": {
            "alertas_rotulados": len(rotulos),
            "verdadeiros": int((rotulos["rotulo_analista"] == "verdadeiro").sum()),
            "falsos_positivos": int((rotulos["rotulo_analista"] == "falso_positivo").sum()),
            "ataques_confirmados": sorted(confirmados),
            "entidades_na_allowlist": len(allowlist),
            "ttl_allowlist_dias": TTL_ALLOWLIST_DIAS,
            "allowlist_expira_em": sorted(str(v) for v in allowlist.values()),
        },
        "retreino": {
            "dias": list(DIAS_RETREINO),
            "janelas_usadas": int(len(base)),
            "limiar_atual": round(limiar_atual, 4),
            "limiar_candidato": round(limiar_candidato, 4),
            "validacao_dias": list(DIAS_VALIDACAO),
            "validacao_atual": val_atual,
            "validacao_candidato": val_cand,
            "candidato_implantado": bool(implantar),
        },
        "semana_2": {"antes": antes, "so_allowlist": so_allowlist, "depois": depois},
        "psi_por_feature": psis,
        "psi_maximo": max(psis.values()),
        "retreino_por_deriva": max(psis.values()) > LIMITE_PSI,
    }
    with open(PASTA_SAIDA / "aprendizado_continuo.json", "w", encoding="utf-8") as arquivo:
        json.dump(resultado, arquivo, ensure_ascii=False, indent=2)
    janelas.to_pickle(PASTA_SAIDA / "janelas.pkl")
    resumo = {k: resultado["semana_2"][k] for k in ("antes", "so_allowlist", "depois")}
    for chave, valor in resumo.items():
        print(chave, {k: valor[k] for k in ("detectadas", "ocorrencias", "casos_por_dia",
                                             "falsos_positivos_por_dia", "precisao_casos")})
    print("candidato implantado:", implantar, "| PSI máximo:", resultado["psi_maximo"])


if __name__ == "__main__":
    main()
