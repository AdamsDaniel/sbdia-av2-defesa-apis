"""Sobe o painel Streamlit e salva capturas de tela em ``saida/``.

Usa o Playwright com o Microsoft Edge já instalado (``channel="msedge"``).
"""
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

from config import PASTA_SAIDA, RAIZ

PORTA = 8601
URL = f"http://localhost:{PORTA}"


def aguardar_servidor(limite_s=60):
    """Espera o servidor responder."""
    fim = time.time() + limite_s
    while time.time() < fim:
        try:
            urllib.request.urlopen(URL, timeout=2)
            return
        except OSError:
            time.sleep(1)
    raise TimeoutError("Streamlit não respondeu.")


def main():
    """Captura a página inteira e duas partes para o relatório."""
    servidor = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", str(RAIZ / "dashboard.py"),
         "--server.headless", "true", "--server.port", str(PORTA),
         "--browser.gatherUsageStats", "false", "--theme.base", "light"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        aguardar_servidor()
        with sync_playwright() as p:
            navegador = p.chromium.launch(channel="msedge")
            # O Streamlit rola dentro de um contêiner; uma janela alta mostra tudo.
            pagina = navegador.new_page(viewport={"width": 1440, "height": 2250},
                                        device_scale_factor=1.5)
            pagina.goto(URL)
            pagina.wait_for_selector("text=Alertas recentes", timeout=60000)
            pagina.wait_for_timeout(8000)  # gráficos Vega terminam de desenhar
            pagina.add_style_tag(content="header, [data-testid='stToolbar'],"
                                         "[data-testid='stDecoration'] {display:none}")
            pagina.wait_for_timeout(500)
            pagina.screenshot(path=PASTA_SAIDA / "dashboard_completo.png")
            for nome, inicio, altura in (("topo", 0, 1020), ("meio", 1000, 1150)):
                pagina.screenshot(path=PASTA_SAIDA / f"dashboard_{nome}.png",
                                  clip={"x": 0, "y": inicio, "width": 1440, "height": altura})
            navegador.close()
    finally:
        servidor.terminate()
    print("Capturas salvas em", PASTA_SAIDA)


if __name__ == "__main__":
    main()
