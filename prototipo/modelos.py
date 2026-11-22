"""Isolation Forest e autoencoder, com um modelo por visão e score de 0 a 1."""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from config import INTERVALO_DEDUP_MIN, SEMENTE
from features import FEATURES


def _normalizar(bruto, referencia):
    """Converte o score bruto para 0–1 (1 = mais anômalo) sem saturar.

    ``x = (bruto - mediana) / (p99 - mediana)`` do treino e ``score = x / (1 + x)``:
    a mediana do treino vira 0 e o percentil 99 vira 0,5.
    """
    mediana, p99 = np.quantile(referencia, [0.5, 0.99])
    x = np.clip((bruto - mediana) / max(p99 - mediana, 1e-9), 0, None)
    return x / (1 + x)


class Autoencoder:
    """Rede neural que reconstrói a própria entrada; o erro é o score."""

    def __init__(self):
        self.escalonador = StandardScaler()
        self.rede = MLPRegressor(hidden_layer_sizes=(10, 4, 10), activation="tanh",
                                 max_iter=500, early_stopping=True,
                                 random_state=SEMENTE)

    def fit(self, matriz):
        """Treina a rede para reproduzir as janelas de treino."""
        entrada = self.escalonador.fit_transform(matriz)
        self.rede.fit(entrada, entrada)
        return self

    def score_bruto(self, matriz):
        """Erro quadrático médio de reconstrução por janela."""
        entrada = self.escalonador.transform(matriz)
        return np.mean((self.rede.predict(entrada) - entrada) ** 2, axis=1)


class IsolationForestScore:
    """Isolation Forest com score bruto positivo para anomalia."""

    def __init__(self):
        self.modelo = IsolationForest(n_estimators=300, contamination="auto",
                                      random_state=SEMENTE)

    def fit(self, matriz):
        """Treina a floresta com as janelas de treino."""
        self.modelo.fit(matriz)
        return self

    def score_bruto(self, matriz):
        """``-score_samples``: quanto maior, mais fácil de isolar."""
        return -self.modelo.score_samples(matriz)


TIPOS_MODELO = {"isolation_forest": IsolationForestScore, "autoencoder": Autoencoder}


class DetectorPorVisao:
    """Treina um modelo por visão (principal e IP) e devolve score 0–1."""

    def __init__(self, tipo):
        self.tipo = tipo
        self.modelos = {}
        self.referencias = {}

    def fit(self, janelas):
        """Treina com as janelas recebidas (sem rótulos)."""
        for visao, grupo in janelas.groupby("visao"):
            matriz = grupo[FEATURES].to_numpy(dtype=float)
            modelo = TIPOS_MODELO[self.tipo]().fit(matriz)
            self.modelos[visao] = modelo
            self.referencias[visao] = modelo.score_bruto(matriz)
        return self

    def score(self, janelas):
        """Score normalizado de cada janela, na ordem do DataFrame."""
        resultado = np.zeros(len(janelas))
        for visao, modelo in self.modelos.items():
            mascara = (janelas["visao"] == visao).to_numpy()
            if mascara.any():
                bruto = modelo.score_bruto(janelas.loc[mascara, FEATURES].to_numpy(float))
                resultado[mascara] = _normalizar(bruto, self.referencias[visao])
        return resultado


def deduplicar(janelas, coluna_score, limiar):
    """Agrupa janelas acima do limiar da mesma entidade em até 15 min num só alerta.

    Retorna um DataFrame com a primeira janela de cada grupo, o maior score e o
    conjunto de ``ataque_id`` cobertos (usado só na avaliação).
    """
    acima = janelas[janelas[coluna_score] >= limiar].sort_values(
        ["visao", "entidade_hash", "janela_inicio"])
    if acima.empty:
        return acima.assign(grupo=[], score_max=[], ataques=[])
    chave = acima["visao"] + "|" + acima["entidade_hash"]
    intervalo = acima["janela_inicio"].diff().dt.total_seconds().div(60)
    novo = (chave != chave.shift()) | (intervalo > INTERVALO_DEDUP_MIN)
    acima = acima.assign(grupo=novo.cumsum())
    primeiros = acima.groupby("grupo").head(1).set_index("grupo")
    primeiros["score_max"] = acima.groupby("grupo")[coluna_score].max()
    primeiros["ataques"] = acima.groupby("grupo")["ataque_id"].agg(
        lambda s: frozenset(v for v in s if v))
    return primeiros.reset_index().sort_values("janela_inicio")


def agrupar_casos(alertas):
    """Agrupa alertas em casos para o analista.

    Na visão por IP, alertas de IPs diferentes em até 15 min formam uma única
    campanha (por exemplo, credential stuffing distribuído). Na visão principal,
    cada alerta deduplicado já é um caso.
    """
    if alertas.empty:
        return alertas.assign(caso=[])
    alertas = alertas.sort_values("janela_inicio").copy()
    eh_ip = alertas["visao"] == "ip"
    alertas["caso"] = np.arange(len(alertas))
    ips = alertas[eh_ip]
    if not ips.empty:
        intervalo = ips["janela_inicio"].diff().dt.total_seconds().div(60)
        campanha = (intervalo.isna() | (intervalo > INTERVALO_DEDUP_MIN)).cumsum()
        alertas.loc[eh_ip, "caso"] = len(alertas) + campanha.to_numpy()
    return alertas


def casos_por_dia(janelas, coluna_score, limiar, dias):
    """Casos (alertas deduplicados e agrupados em campanhas) por dia."""
    alertas = deduplicar(janelas, coluna_score, limiar)
    if alertas.empty:
        return 0.0
    return agrupar_casos(alertas)["caso"].nunique() / dias


def escolher_limiar(janelas, coluna_score, orcamento, dias):
    """Menor limiar cujo número de casos por dia cabe no orçamento.

    Usa só as janelas recebidas (o período de treino), nunca o teste.
    """
    candidatos = np.unique(np.quantile(janelas[coluna_score],
                                       np.linspace(0.97, 0.99999, 300)))
    for limiar in candidatos:
        if casos_por_dia(janelas, coluna_score, limiar, dias) <= orcamento:
            return float(limiar)
    return float(candidatos[-1])
