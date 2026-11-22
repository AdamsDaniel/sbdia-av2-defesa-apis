"""Roda o protótipo inteiro do zero, em ordem.

1. gera os logs fictícios;
2. treina e avalia os modelos e exporta os alertas;
3. simula o aprendizado contínuo;
4. desenha os gráficos;
5. envia os alertas ao simulador SOAR (pasta ``../soar``).

O painel é visto com ``streamlit run dashboard.py``; as capturas de tela são
geradas por ``python capturar_dashboard.py``.
"""
import subprocess
import sys
import time

import aprendizado_continuo
import gerar_logs
import graficos
import treinar_avaliar
from config import PASTA_SAIDA, RAIZ


def executar_soar():
    """Executa o simulador SOAR com os alertas e rótulos do protótipo."""
    simulador = RAIZ.parent / "soar" / "simulador_soar.py"
    subprocess.run([sys.executable, str(simulador),
                    "--entrada", str(PASTA_SAIDA / "alertas.jsonl"),
                    "--rotulos", str(PASTA_SAIDA / "rotulos_analista.csv"),
                    "--saida", str(PASTA_SAIDA / "soar"),
                    "--pseudonimos", str(PASTA_SAIDA / "tabela_pseudonimos.csv")],
                   check=True, stdout=subprocess.DEVNULL)
    print("Resultados do SOAR em", PASTA_SAIDA / "soar")


def main():
    """Gera dados, treina, avalia, simula o feedback, desenha e aciona o SOAR."""
    inicio = time.perf_counter()
    for etapa in (gerar_logs, treinar_avaliar, aprendizado_continuo, graficos):
        print(f"\n=== {etapa.__name__} ===")
        etapa.main()
    print("\n=== soar ===")
    executar_soar()
    print(f"\nConcluído em {time.perf_counter() - inicio:.0f} s.")


if __name__ == "__main__":
    main()
