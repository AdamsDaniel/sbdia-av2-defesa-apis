"""Repete geração, treino e avaliação com outras sementes (robustez dos resultados).

Cada semente gera um conjunto de dados diferente: outros clientes, horários e
ataques. Resultado em ``saida/robustez_sementes.json``. Leva cerca de 1 min
por semente.
"""
import json
import warnings

import numpy as np

from avaliacao import avaliar, inicio_dos_ataques
from config import DIAS_TESTE, PASTA_SAIDA
from features import carregar_logs, criar_janelas
from gerar_logs import GeradorLogs
from treinar_avaliar import MODELOS, periodo, treinar_modelos

SEMENTES = [1, 2, 3, 4, 5]


def main():
    """Avalia os dois modelos no teste para cada semente."""
    warnings.filterwarnings("ignore")
    pasta = PASTA_SAIDA / "sementes"
    pasta.mkdir(parents=True, exist_ok=True)
    resultados = {}
    for semente in SEMENTES:
        caminho = pasta / f"logs_semente_{semente}.csv"
        GeradorLogs(semente).gerar().to_csv(caminho, index=False)
        janelas, _ = criar_janelas(caminho)
        limiares = treinar_modelos(janelas)
        inicios = inicio_dos_ataques(carregar_logs(caminho))
        teste = periodo(janelas, DIAS_TESTE)
        resultados[semente] = {
            nome: avaliar(teste, f"score_{nome}", limiares[nome], inicios) for nome in MODELOS
        }
        caminho.unlink()
        resumo = {n: (r["detectadas"], r["ocorrencias"], r["falsos_positivos_por_dia"])
                  for n, r in resultados[semente].items()}
        print(f"semente {semente}: {resumo}")

    agregado = {}
    for nome in MODELOS:
        linhas = [resultados[s][nome] for s in SEMENTES]
        agregado[nome] = {
            "revocacao_media": round(float(np.mean([r["revocacao_ocorrencia"] for r in linhas])), 3),
            "revocacao_minima": round(float(np.min([r["revocacao_ocorrencia"] for r in linhas])), 3),
            "falsos_positivos_dia_media": round(float(np.mean(
                [r["falsos_positivos_por_dia"] for r in linhas])), 2),
            "casos_dia_media": round(float(np.mean([r["casos_por_dia"] for r in linhas])), 2),
            "mttd_medio": round(float(np.mean([r["mttd_min_medio"] for r in linhas])), 1),
            "nao_detectadas": sorted({a for r in linhas for a in r["nao_detectadas"]}),
        }
    saida = {"sementes": SEMENTES, "por_semente": resultados, "agregado": agregado}
    with open(PASTA_SAIDA / "robustez_sementes.json", "w", encoding="utf-8") as arquivo:
        json.dump(saida, arquivo, ensure_ascii=False, indent=2)
    print(json.dumps(agregado, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
