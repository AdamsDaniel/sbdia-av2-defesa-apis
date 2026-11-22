"""Gera 30 dias de logs fictícios de API Gateway + WAF da Corvina Crédito Digital.

O tráfego normal tem perfil por cliente (IPs, ASN, horário e contas próprias),
viajantes, parceiros com lote noturno, dias de pagamento, um parceiro novo
(dia 21) e uma versão nova do app (dia 22). Os ataques usam contas reais.
As colunas ``ataque_id`` e ``cenario`` servem só para avaliação.
"""
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

from config import (CAMINHO_LOGS, DATA_INICIO, ENDPOINTS, FUSO, SEMENTE,
                    TOTAL_DIAS)

COLUNAS = ["timestamp", "request_id", "ip", "pais", "asn", "usuario_id",
           "api_key_id", "cliente_tipo", "metodo", "endpoint", "recurso_id",
           "status", "latencia_ms", "bytes_resposta", "user_agent", "waf_acao",
           "waf_regra", "ataque_id", "cenario"]

BYTES_MEDIOS = {"login": 300, "token": 400, "saldo": 600, "extrato": 4000,
                "pix": 900, "cartao": 1200}
METODO = {"login": "POST", "token": "POST", "pix": "POST"}
HORAS_FORA = [0, 1, 2, 3, 4, 5, 20, 21, 22, 23]
DIAS_PAGAMENTO = {4, 19}  # dias 5 e 20 do mês (índice começa em 0)


class GeradorLogs:
    """Acumula as requisições sintéticas em memória."""

    def __init__(self, semente=SEMENTE):
        self.rng = np.random.default_rng(semente)
        self.inicio = datetime.fromisoformat(DATA_INICIO).replace(
            tzinfo=ZoneInfo(FUSO))
        self.linhas = []
        self.clientes = self._criar_clientes(300)
        self.parceiros = self._criar_parceiros()

    # ------------------------------------------------------------------ perfis
    def _criar_clientes(self, quantidade):
        """Cria clientes com IPs, ASN, user-agent, contas e horário típico."""
        clientes = []
        for i in range(quantidade):
            sorteio = self.rng.random()
            if sorteio < 0.80:
                centro = self.rng.uniform(9, 18)
            elif sorteio < 0.95:
                centro = self.rng.uniform(20, 24)
            else:
                centro = self.rng.uniform(1, 5)
            ips = [f"100.{64 + i % 60}.{i % 250}.{10 + k}"
                   for k in range(self.rng.integers(1, 3))]
            clientes.append({
                "usuario": f"cli{i:04d}",
                "ips": ips,
                "asn": f"AS{64512 + i % 6}",
                "ua": ["CorvinaApp/4.2 Android", "CorvinaApp/4.2 iOS",
                       "Mozilla/5.0 Web"][i % 3],
                "contas": [f"cc{i:04d}{k}" for k in range(self.rng.integers(1, 3))],
                "cartao": f"ct{i:04d}",
                "centro_hora": centro,
                "viagem": None,
            })
        # cerca de 3% viajam ao exterior por 3 a 7 dias seguidos
        viajantes = self.rng.choice(quantidade, size=9, replace=False)
        destinos = [("PT", "AS65010"), ("US", "AS65011"), ("AR", "AS65012")]
        for n, idx in enumerate(viajantes):
            inicio = int(self.rng.integers(3, 26))
            pais, asn = destinos[n % 3]
            clientes[idx]["viagem"] = {
                "dias": range(inicio, inicio + int(self.rng.integers(3, 8))),
                "ip": f"192.0.2.{20 + n}", "pais": pais, "asn": asn}
        return clientes

    @staticmethod
    def _criar_parceiros():
        """Quatro parceiros antigos e um parceiro novo (a partir do dia 21)."""
        return {
            "key_parceiro_1": {"ip": "100.127.1.10", "bytes": 20000},
            "key_parceiro_2": {"ip": "100.127.2.10", "bytes": 18000},
            "key_parceiro_3": {"ip": "100.127.3.10", "bytes": 22000},
            "key_parceiro_4": {"ip": "100.127.4.10", "bytes": 15000},
        }

    # ---------------------------------------------------------------- registro
    def registrar(self, ts, ip, endpoint_chave, recurso, *, usuario="",
                  api_key="", pais="BR", asn="AS64512", status=200,
                  bytes_resp=None, ua="CorvinaApp/4.2 Android",
                  cliente_tipo="app", waf_acao="ALLOW", waf_regra="",
                  ataque_id="", cenario=""):
        """Adiciona uma requisição à lista."""
        if bytes_resp is None:
            media = BYTES_MEDIOS.get(endpoint_chave, 1000)
            bytes_resp = max(80, int(self.rng.normal(media, media * 0.2)))
        self.linhas.append((
            ts.replace(microsecond=0), f"req-{len(self.linhas):08d}", ip, pais, asn, usuario, api_key,
            cliente_tipo, METODO.get(endpoint_chave, "GET"),
            ENDPOINTS[endpoint_chave], recurso, status,
            int(self.rng.integers(25, 400)), bytes_resp, ua, waf_acao,
            waf_regra, ataque_id, cenario))

    # ----------------------------------------------------------- tráfego normal
    def sessao_cliente(self, cliente, ts, dia, ip=None, pais="BR", asn=None):
        """Login, refresh do token e algumas consultas às próprias contas."""
        ip = ip or self.rng.choice(cliente["ips"])
        asn = asn or cliente["asn"]
        base = {"usuario": cliente["usuario"], "pais": pais, "asn": asn,
                "ua": cliente["ua"],
                "cliente_tipo": "web" if "Web" in cliente["ua"] else "app"}
        if self.rng.random() < 0.03:  # erro de senha ocasional
            for _ in range(self.rng.integers(1, 3)):
                self.registrar(ts, ip, "login", "", status=401, **base)
                ts += timedelta(seconds=int(self.rng.integers(5, 30)))
        self.registrar(ts, ip, "login", "", **base)
        ts += timedelta(seconds=int(self.rng.integers(1, 5)))
        self.registrar(ts, ip, "token", "", **base)
        acoes = list(self.rng.choice(["saldo", "extrato", "cartao"],
                                     size=self.rng.integers(2, 6),
                                     p=[0.5, 0.35, 0.15]))
        if dia >= 22:  # app 4.3 consulta o cartão em toda sessão (deriva)
            acoes += ["cartao"] * int(self.rng.integers(1, 3))
        chance_pix = 0.45 if dia in DIAS_PAGAMENTO else 0.2
        if self.rng.random() < chance_pix:
            acoes += ["pix"] * int(self.rng.integers(1, 3))
        for acao in acoes:
            ts += timedelta(seconds=int(self.rng.integers(5, 60)))
            recurso = (cliente["cartao"] if acao == "cartao"
                       else self.rng.choice(cliente["contas"]))
            self.registrar(ts, ip, acao, recurso, **base)

    def trafego_clientes(self, dia):
        """Gera as sessões de todos os clientes em um dia."""
        data = self.inicio + timedelta(days=dia)
        fator = 0.6 if data.weekday() >= 5 else 1.0
        fator *= 1.5 if dia in DIAS_PAGAMENTO else 1.0
        for cliente in self.clientes:
            viagem = cliente["viagem"]
            em_viagem = viagem is not None and dia in viagem["dias"]
            for _ in range(self.rng.poisson(1.6 * fator)):
                hora = (cliente["centro_hora"] + self.rng.normal(0, 1.3)) % 24
                ts = data + timedelta(hours=float(hora))
                if em_viagem:
                    self.sessao_cliente(cliente, ts, dia, viagem["ip"],
                                        viagem["pais"], viagem["asn"])
                else:
                    self.sessao_cliente(cliente, ts, dia)

    def trafego_parceiros(self, dia):
        """Parceiros em horário comercial, lote noturno e parceiro novo."""
        data = self.inicio + timedelta(days=dia)
        if data.weekday() < 5:
            for chave, info in self.parceiros.items():
                for hora in range(9, 18):
                    for _ in range(self.rng.integers(20, 40)):
                        ts = data + timedelta(hours=hora,
                                              seconds=int(self.rng.integers(3600)))
                        self.registrar(ts, info["ip"], "parceiro",
                                       f"pg{self.rng.integers(1, 51)}",
                                       api_key=chave, ua="ParceiroSDK/2.1",
                                       cliente_tipo="parceiro",
                                       bytes_resp=int(self.rng.normal(info["bytes"],
                                                                      info["bytes"] * 0.2)))
        # lote noturno legítimo do parceiro 2, às 2h, com bytes altos
        for n in range(self.rng.integers(250, 350)):
            ts = data + timedelta(hours=2, seconds=int(n * 8))
            self.registrar(ts, "100.127.2.10", "parceiro", f"pg{n % 50 + 1}",
                           api_key="key_parceiro_2", ua="ParceiroSDK/2.1",
                           cliente_tipo="parceiro",
                           bytes_resp=int(self.rng.normal(60000, 8000)))
        # parceiro novo homologado no dia 21, opera das 22h às 22h45
        if dia >= 21:
            for n in range(self.rng.integers(150, 250)):
                ts = data + timedelta(hours=22, seconds=int(n * 12))
                self.registrar(ts, "100.127.9.10", "parceiro", f"pg{n % 40 + 1}",
                               api_key="key_parceiro_5", ua="NovoParceiro/1.0",
                               cliente_tipo="parceiro",
                               bytes_resp=int(self.rng.normal(30000, 5000)))

    # ------------------------------------------------------------------ ataques
    def agenda_ataques(self):
        """Define dia e hora de cada ocorrência (1 no treino e 2 no teste; BOLA só no fim)."""
        cenarios = ["credential_stuffing", "forca_bruta", "bola_enumeracao",
                    "abuso_api_key", "token_pais_asn_novo", "exfiltracao",
                    "rajada_pix", "injecao_sql_xss"]
        agenda = []
        for cenario in cenarios:
            if cenario == "bola_enumeracao":
                dias = sorted(self.rng.choice(range(25, 30), 3, replace=False))
            else:
                dias = [int(self.rng.integers(8, 21))]
                dias += sorted(self.rng.choice(range(21, 30), 2, replace=False))
            no_expediente = int(self.rng.integers(0, 3))
            for ordem, dia in enumerate(dias):
                if ordem == no_expediente:
                    hora = int(self.rng.integers(10, 17))
                else:
                    hora = int(self.rng.choice(HORAS_FORA))
                inicio = (self.inicio + timedelta(days=int(dia), hours=hora,
                                                  minutes=int(self.rng.integers(0, 50))))
                agenda.append((cenario, f"{cenario}_{ordem + 1}", inicio))
        return agenda

    def _vitima(self):
        """Escolhe um cliente que não está em viagem."""
        while True:
            cliente = self.clientes[int(self.rng.integers(len(self.clientes)))]
            if cliente["viagem"] is None:
                return cliente

    def ataque(self, cenario, ataque_id, inicio):
        """Gera as requisições de uma ocorrência de ataque."""
        rotulo = {"ataque_id": ataque_id, "cenario": cenario}
        if cenario == "rajada_pix":  # golpe rápido: 5 a 15 min
            duracao = int(self.rng.integers(5, 16)) * 60
        else:
            duracao = int(self.rng.integers(10, 41)) * 60
        rng = self.rng

        def instante():
            return inicio + timedelta(seconds=int(rng.integers(0, duracao)))

        if cenario == "credential_stuffing":
            for n in range(rng.integers(40, 81)):
                ip = f"{['198.51.100', '203.0.113'][n % 2]}.{rng.integers(1, 255)}"
                for _ in range(rng.integers(3, 11)):
                    alvo = self.clientes[int(rng.integers(len(self.clientes)))]
                    status = 200 if rng.random() < 0.01 else 401
                    self.registrar(instante(), ip, "login", "",
                                   usuario=alvo["usuario"], pais="US",
                                   asn="AS65500", status=status,
                                   ua="python-requests/2.31", cliente_tipo="web",
                                   **rotulo)
        elif cenario == "forca_bruta":
            vitima, ip = self._vitima(), f"203.0.113.{rng.integers(1, 255)}"
            tentativas = int(rng.integers(30, 151))
            for n in range(tentativas):
                ts = inicio + timedelta(seconds=n * duracao // tentativas)
                self.registrar(ts, ip, "login", "", usuario=vitima["usuario"],
                               pais="BR", asn="AS65501", status=401,
                               ua="Hydra", cliente_tipo="web", **rotulo)
        elif cenario == "bola_enumeracao":
            vitima, ip = self._vitima(), f"198.51.100.{rng.integers(1, 255)}"
            for _ in range(rng.integers(100, 301)):
                alheio = self.clientes[int(rng.integers(len(self.clientes)))]
                status = 200 if rng.random() < 0.7 else 404
                self.registrar(instante(), ip,
                               str(rng.choice(["saldo", "extrato"])),
                               alheio["contas"][0], usuario=vitima["usuario"],
                               pais="NL", asn="AS65502", status=status,
                               ua=vitima["ua"], **rotulo)
        elif cenario == "abuso_api_key":
            ip = f"203.0.113.{rng.integers(1, 255)}"
            for n in range(rng.integers(600, 1501)):
                status = 429 if n > 400 and rng.random() < 0.5 else 200
                self.registrar(instante(), ip, "parceiro", f"pg{n % 500 + 1}",
                               api_key="key_parceiro_1", pais="US",
                               asn="AS65503", status=status, ua="scrapy/2.11",
                               cliente_tipo="parceiro", bytes_resp=20000, **rotulo)
        elif cenario == "token_pais_asn_novo":
            vitima = self._vitima()
            ip = f"198.51.100.{rng.integers(1, 255)}"
            acoes = ["saldo", "extrato", "saldo", "cartao"] + ["pix"] * int(rng.integers(1, 3))
            for acao in acoes + ["extrato"] * int(rng.integers(4, 15)):
                recurso = vitima["cartao"] if acao == "cartao" else vitima["contas"][0]
                self.registrar(instante(), ip, acao, recurso,
                               usuario=vitima["usuario"], pais="RO",
                               asn="AS65504", ua=vitima["ua"], **rotulo)
        elif cenario == "exfiltracao":
            info = self.parceiros["key_parceiro_3"]
            mediana = info["bytes"]
            for n in range(rng.integers(200, 601)):
                self.registrar(instante(), info["ip"], "parceiro",
                               f"pg{n + 1}", api_key="key_parceiro_3",
                               ua="ParceiroSDK/2.1", cliente_tipo="parceiro",
                               bytes_resp=int(mediana * rng.uniform(50, 200)),
                               **rotulo)
        elif cenario == "rajada_pix":
            vitima = self._vitima()
            ip = str(rng.choice(vitima["ips"]))  # malware no próprio aparelho
            for _ in range(rng.integers(20, 41)):
                self.registrar(instante(), ip, "pix", vitima["contas"][0],
                               usuario=vitima["usuario"], asn=vitima["asn"],
                               ua=vitima["ua"], **rotulo)
        elif cenario == "injecao_sql_xss":
            ip = f"203.0.113.{rng.integers(1, 255)}"
            for _ in range(rng.integers(20, 61)):
                regra = str(rng.choice(["AWS-AWSManagedRulesSQLiRuleSet",
                                        "AWS-AWSManagedRulesCommonRuleSet"]))
                self.registrar(instante(), ip, "extrato", "1 OR 1=1",
                               pais="US", asn="AS65505", status=403,
                               ua="sqlmap/1.8", cliente_tipo="web",
                               waf_acao="BLOCK", waf_regra=regra, **rotulo)

    # -------------------------------------------------------------------- geral
    def gerar(self):
        """Gera tudo e devolve um DataFrame ordenado por tempo."""
        for dia in range(TOTAL_DIAS):
            self.trafego_clientes(dia)
            self.trafego_parceiros(dia)
        for cenario, ataque_id, inicio in self.agenda_ataques():
            self.ataque(cenario, ataque_id, inicio)
        logs = pd.DataFrame(self.linhas, columns=COLUNAS)
        logs = logs.sort_values("timestamp", kind="stable").reset_index(drop=True)
        logs["timestamp"] = logs["timestamp"].map(lambda t: t.isoformat())
        return logs


def main():
    """Gera o arquivo CSV de logs."""
    logs = GeradorLogs().gerar()
    CAMINHO_LOGS.parent.mkdir(parents=True, exist_ok=True)
    logs.to_csv(CAMINHO_LOGS, index=False)
    ataques = logs[logs["ataque_id"] != ""]
    print(f"{len(logs):,} requisições geradas; "
          f"{ataques['ataque_id'].nunique()} ocorrências de ataque.")


if __name__ == "__main__":
    main()
