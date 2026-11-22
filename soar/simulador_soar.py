import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


SEVERIDADE_NIVEL = {"media": 6, "alta": 10, "critica": 14}
REPUTACAO = {
    "203.0.113.15": {"nivel": "maliciosa", "score": 0.92},
    "198.51.100.44": {"nivel": "suspeita", "score": 0.65},
}
GEOIP = {
    "203.0.113.15": {"pais": "BR", "asn": "AS64515", "pais_novo": False},
    "198.51.100.44": {"pais": "RO", "asn": "AS64544", "pais_novo": True},
}


def hash_entidade(valor):
    return "ent_" + hashlib.sha256(str(valor).encode("utf-8")).hexdigest()[:16]


def ler_jsonl(caminho):
    alertas = []
    with open(caminho, "r", encoding="utf-8") as arquivo:
        for linha in arquivo:
            if linha.strip():
                alertas.append(json.loads(linha))
    return alertas


def ler_rotulos(caminho):
    rotulos = {}
    if not caminho:
        return rotulos
    with open(caminho, "r", encoding="utf-8-sig", newline="") as arquivo:
        leitor = csv.DictReader(arquivo)
        for linha in leitor:
            alerta_id = linha.get("alerta_id")
            rotulo = (linha.get("rotulo_analista") or "").strip().lower()
            if alerta_id and rotulo in ("verdadeiro", "falso_positivo"):
                rotulos[alerta_id] = {
                    "rotulo": rotulo,
                    "comentario": linha.get("comentario", "").strip(),
                    "minutos_resposta": float(linha["minutos_resposta"]) if linha.get("minutos_resposta", "").strip() else None,
                }
    return rotulos


TABELA_PSEUDONIMOS = Path(__file__).resolve().parent / "exemplos" / "tabela_pseudonimos.csv"


def resolver_pseudonimo(entidade_hash):
    """Em producao, esta tabela fica num cofre e somente o SOAR tem acesso."""
    tabela = TABELA_PSEUDONIMOS
    if not tabela.exists():
        return "cliente-desconhecido"
    with open(tabela, "r", encoding="utf-8-sig", newline="") as arquivo:
        for linha in csv.DictReader(arquivo):
            if linha["entidade_hash"] == entidade_hash:
                return linha["cliente_real"]
    return "cliente-desconhecido"


def datahora(valor):
    return datetime.fromisoformat(valor.replace("Z", "+00:00"))


def enriquecer(alerta):
    ip = alerta.get("ip") or alerta.get("ip_hash")
    reputacao = REPUTACAO.get(ip, {"nivel": "desconhecida", "score": 0.20})
    geo = GEOIP.get(ip, {"pais": alerta.get("pais", "BR"), "asn": "AS0", "pais_novo": False})
    entidade = alerta.get("entidade_hash") or hash_entidade(
        (alerta.get("entidade_tipo"), alerta.get("entidade_hash"), alerta.get("ip_hash"))
    )
    return {
        "reputacao_ip": reputacao,
        "geoip": geo,
        "entidade_hash": entidade,
    }


def entidade_grupo(alerta):
    enriquecido = alerta["_enriquecimento"]
    tipo = alerta.get("entidade_tipo", "ip")
    return tipo + ":" + enriquecido["entidade_hash"]


def agrupar(alertas):
    grupos = defaultdict(list)
    for alerta in alertas:
        alerta["_enriquecimento"] = enriquecer(alerta)
        chave = entidade_grupo(alerta)
        instante = datahora(alerta["timestamp"])
        candidatos = sorted(grupos[chave], key=lambda item: item["_janela_inicio"])
        colocado = False
        for candidato in candidatos:
            inicio = candidato["_janela_inicio"]
            if abs((instante - inicio).total_seconds()) <= 15 * 60:
                candidato["_itens"].append(alerta)
                colocado = True
                break
        if not colocado:
            grupos[chave].append({"_janela_inicio": instante, "_itens": [alerta]})
    resultado = []
    for chave, janelas in grupos.items():
        for janela in janelas:
            resultado.append(janela["_itens"])
    return resultado


def severidade_max(grupo):
    ordem = {"media": 1, "alta": 2, "critica": 3}
    return max((a.get("severidade", "media") for a in grupo), key=lambda s: ordem.get(s, 0))


def adicionar_acao(lista, alerta, tipo, alvo, ttl_segundos, comando_aplicacao, comando_reversao,
                  aprovacao="sim", estado="aplicada"):
    aplicada_em = datahora(alerta["timestamp"])
    lista.append({
        "acao_id": "acao-" + hashlib.sha256(
            (alerta["alerta_id"] + tipo + alvo).encode("utf-8")
        ).hexdigest()[:12],
        "alerta_id": alerta["alerta_id"],
        "entidade_hash": alerta["_enriquecimento"]["entidade_hash"],
        "tipo": tipo,
        "alvo": alvo,
        "ttl_segundos": ttl_segundos,
        "comando_aplicacao": comando_aplicacao,
        "comando_reversao": comando_reversao,
        "aprovacao_humana": aprovacao,
        "estado": estado,
        "aplicada_em": aplicada_em.isoformat(),
        "expira_em": (aplicada_em + timedelta(seconds=ttl_segundos)).isoformat(),
    })


def principal():
    parser = argparse.ArgumentParser(description="Simulador SOAR da Corvina")
    parser.add_argument("--entrada", required=True)
    parser.add_argument("--rotulos")
    parser.add_argument("--saida", help="pasta de saida (padrao: soar/saida)")
    parser.add_argument("--pseudonimos", help="CSV entidade_hash,cliente_real (cofre simulado)")
    args = parser.parse_args()

    global TABELA_PSEUDONIMOS
    if args.pseudonimos:
        TABELA_PSEUDONIMOS = Path(args.pseudonimos)
    base = Path(__file__).resolve().parent
    saida = Path(args.saida) if args.saida else base / "saida"
    casos_dir = saida / "casos"
    casos_dir.mkdir(parents=True, exist_ok=True)
    (saida / "acoes.jsonl").unlink(missing_ok=True)
    for antigo in casos_dir.glob("*.json"):
        antigo.unlink()

    alertas = ler_jsonl(args.entrada)
    rotulos = ler_rotulos(args.rotulos)
    grupos = agrupar(alertas)
    rng = random.Random(20260925)
    inicio_relogio = min(datahora(a["timestamp"]) for a in alertas)
    fim_relogio = max(datahora(a["timestamp"]) for a in alertas)
    allowlist = {}

    acoes = []
    casos = []
    feedback = []
    pendentes_aprovacao = 0
    timeouts_plantao = 0
    contidos_por_severidade = defaultdict(int)
    grupos_por_severidade = defaultdict(int)
    mttr_por_severidade = defaultdict(list)
    contencao_por_severidade = defaultdict(list)
    revertidas_falso_positivo = 0
    revertidas_ttl = 0
    latencias_api = defaultdict(list)

    with open(saida / "feedback.jsonl", "w", encoding="utf-8") as arquivo_feedback:
        for grupo in grupos:
            primeiro = grupo[0]
            severidade = severidade_max(grupo)
            alerta_id = primeiro["alerta_id"]
            enriquecido = primeiro["_enriquecimento"]
            entidade = enriquecido["entidade_hash"]
            t_alerta = min(datahora(a["timestamp"]) for a in grupo)
            falso_positivo = any(
                rotulos.get(a["alerta_id"], {}).get("rotulo") == "falso_positivo"
                for a in grupo
            )
            em_allowlist = entidade in allowlist and allowlist[entidade] > t_alerta
            grupos_por_severidade[severidade] += 1
            t_contencao = None
            t_resolucao = t_alerta

            for alerta in grupo:
                rotulo = rotulos.get(alerta["alerta_id"])
                # Identificadores reais só existem no cofre do SOAR (o modelo vê pseudônimos).
                cliente_real = resolver_pseudonimo(alerta.get("entidade_hash", entidade))
                api_key = alerta.get("api_key_id") or (
                    cliente_real if alerta.get("entidade_tipo") == "api_key" else None)
                if rotulo:
                    feedback.append({
                        "alerta_id": alerta["alerta_id"],
                        "entidade_hash": alerta["_enriquecimento"]["entidade_hash"],
                        "rotulo_analista": rotulo["rotulo"],
                        "comentario": rotulo["comentario"],
                    })
                    arquivo_feedback.write(json.dumps(feedback[-1], ensure_ascii=False) + "\n")

                if not em_allowlist and severidade in ("alta", "critica"):
                    latencia = rng.randint(2, 8)
                    latencias_api[severidade].append(latencia)
                    t_contencao = t_contencao or t_alerta + timedelta(seconds=latencia)
                    ip = alerta.get("ip") or alerta.get("ip_hash") or "ip_desconhecido"
                    adicionar_acao(
                        acoes, alerta, "ip_set_waf", ip, 3600,
                        "AWS_WAF: add_ip_to_ip_set --ip " + str(ip),
                        "AWS_WAF: remove_ip_from_ip_set --ip " + str(ip),
                        aprovacao="nao",
                    )
                    if api_key:
                        adicionar_acao(
                            acoes, alerta, "rate_limit_usage_plan", api_key, 3600,
                            "APIGW: apply_rate_limit --api_key " + api_key + " --rps 5",
                            "APIGW: restore_rate_limit --api_key " + api_key,
                            aprovacao="nao",
                        )
                    else:
                        adicionar_acao(
                            acoes, alerta, "step_up_mfa", cliente_real, 3600,
                            "COGNITO: require_step_up_mfa --cliente " + cliente_real,
                            "COGNITO: clear_step_up_mfa --cliente " + cliente_real,
                            aprovacao="nao",
                        )

                if severidade == "critica" and not falso_positivo and not em_allowlist:
                    rotulo_critico = rotulos.get(alerta["alerta_id"])
                    aprovado = bool(rotulo_critico and rotulo_critico["rotulo"] == "verdadeiro")
                    noturno = t_alerta.hour >= 19 or t_alerta.hour < 7
                    resposta = (rotulo_critico or {}).get("minutos_resposta")
                    sem_resposta_15 = rotulo_critico is None or (
                        noturno and resposta is not None and resposta > 15)
                    if rotulo_critico is None:
                        pendentes_aprovacao += 1
                    if sem_resposta_15:
                        # Plantão sem resposta em 15 min: bloqueio temporário e escalonamento.
                        timeouts_plantao += 1
                        if api_key:
                            adicionar_acao(
                                acoes, alerta, "suspender_api_key_temporario", api_key, 7200,
                                "APIGW: suspend_api_key --api_key " + api_key + " --ttl 7200",
                                "APIGW: restore_api_key --api_key " + api_key,
                                aprovacao="timeout", estado="aplicada_por_timeout",
                            )
                        else:
                            adicionar_acao(
                                acoes, alerta, "bloqueio_pix_temporario", cliente_real, 7200,
                                "PIX: temporary_block --conta " + cliente_real + " --ttl 7200",
                                "PIX: reverse_temporary_block --conta " + cliente_real,
                                aprovacao="timeout", estado="aplicada_por_timeout",
                            )
                    if aprovado and api_key:
                        adicionar_acao(
                            acoes, alerta, "suspender_api_key", api_key, 86400,
                            "APIGW: suspend_api_key --api_key " + api_key,
                            "APIGW: restore_api_key --api_key " + api_key,
                            aprovacao="sim", estado="aplicada",
                        )
                    elif aprovado:
                        adicionar_acao(
                            acoes, alerta, "revogar_tokens", cliente_real, 0,
                            "COGNITO: admin_user_global_sign_out --cliente " + cliente_real,
                            "sem reversão: o cliente faz novo login com MFA",
                            aprovacao="sim", estado="aplicada",
                        )
                        adicionar_acao(
                            acoes, alerta, "bloqueio_pix", cliente_real, 86400,
                            "PIX: block_account_transfers --conta " + cliente_real,
                            "PIX: restore_account_transfers --conta " + cliente_real,
                            aprovacao="sim", estado="aplicada",
                        )

            inicio = t_alerta
            fim = max(datahora(a["timestamp"]) for a in grupo)

            if falso_positivo:
                for acao in list(acoes):
                    if acao["entidade_hash"] == entidade and acao["estado"] == "aplicada":
                        acao["estado"] = "revertida_falso_positivo"
                        acao["revertida_em"] = t_alerta.isoformat()
                        arquivo_reversao = {
                            "evento": "reversao",
                            "tipo_reversao": "falso_positivo",
                            "acao_id": acao["acao_id"],
                            "acao_tipo": acao["tipo"],
                            "entidade_hash": entidade,
                            "timestamp": t_alerta.isoformat(),
                            "estado": "revertida_falso_positivo",
                        }
                        acoes.append(arquivo_reversao)
                        revertidas_falso_positivo += 1
                allowlist[entidade] = t_alerta + timedelta(days=7)
                t_resolucao = t_alerta
            else:
                minutos_resposta = None
                for alerta in grupo:
                    candidato = rotulos.get(alerta["alerta_id"], {}).get("minutos_resposta")
                    if candidato is not None:
                        minutos_resposta = candidato
                        break

                if minutos_resposta is not None:
                    t_resolucao = t_alerta + timedelta(minutes=minutos_resposta)
                elif 19 <= t_alerta.hour or t_alerta.hour < 7:
                    t_resolucao = t_alerta + timedelta(minutes=15)
                else:
                    t_resolucao = fim_relogio

            if t_contencao is not None:
                contencao_por_severidade[severidade].append(
                    (t_contencao - t_alerta).total_seconds() / 60
                )
                contidos_por_severidade[severidade] += 1

            mttr_por_severidade[severidade].append(
                max(0, (t_resolucao - t_alerta).total_seconds()) / 60
            )

            caso = {
                "caseId": "COR-" + hashlib.sha256((entidade + str(inicio)).encode()).hexdigest()[:10],
                "title": "Evento " + primeiro["cenario_suspeito"] + " - " + entidade,
                "description": "Caso SOAR criado a partir de " + str(len(grupo)) + " alerta(s) agrupados.",
                "severity": SEVERIDADE_NIVEL[severidade],
                "status": "Closed" if falso_positivo else "Open",
                "tags": [primeiro["cenario_suspeito"], severidade, "LGPD", "Corvina"],
                "startDate": inicio.isoformat(),
                "endDate": fim.isoformat(),
                "t_alerta": t_alerta.isoformat(),
                "t_contencao": t_contencao.isoformat() if t_contencao else None,
                "t_resolucao": t_resolucao.isoformat(),
                "observables": [
                    {"dataType": "entity", "data": entidade},
                    {"dataType": "ip", "data": primeiro.get("ip_hash", "")},
                ],
                "top_features": primeiro.get("top_features", []),
                "enriquecimento": enriquecido,
                "contador_alertas": len(grupo),
                "pendente_aprovacao": pendentes_aprovacao if severidade == "critica" and not falso_positivo and rotulos.get(alerta_id) is None else False,
                "notificacao": "Plantao: caso " + severidade + " para " + primeiro["cenario_suspeito"],
                "mitigacao": "Fechar caso somente apos revisar regras WAF/rate limit e notificar ANPD/BACEN quando aplicavel.",
            }
            casos.append(caso)
            caso_arquivo = casos_dir / (caso["caseId"] + ".json")
            with open(caso_arquivo, "w", encoding="utf-8") as arquivo_caso:
                json.dump(caso, arquivo_caso, ensure_ascii=False, indent=2)

    fim_relogio = fim_relogio + timedelta(days=8)

    for acao in list(acoes):
        # Ações irreversíveis (TTL 0, ex.: revogar tokens) não expiram.
        if (acao.get("estado") in ("aplicada", "aplicada_por_timeout")
                and acao.get("ttl_segundos", 0) > 0):
            vence = datahora(acao["expira_em"])
            if vence <= fim_relogio:
                acao["estado"] = "revertida_ttl"
                acao["revertida_em"] = vence.isoformat()
                acoes.append({
                    "evento": "reversao",
                    "tipo_reversao": "ttl",
                    "acao_id": acao["acao_id"],
                    "acao_tipo": acao["tipo"],
                    "entidade_hash": acao["entidade_hash"],
                    "timestamp": vence.isoformat(),
                    "estado": "revertida_ttl",
                })
                revertidas_ttl += 1

    with open(saida / "acoes.jsonl", "w", encoding="utf-8") as arquivo_acoes:
        for acao in acoes:
            arquivo_acoes.write(json.dumps(acao, ensure_ascii=False) + "\n")

    def p90(valores):
        if not valores:
            return 0
        ordenados = sorted(valores)
        indice = int(round(0.90 * (len(ordenados) - 1)))
        return round(ordenados[indice], 2)

    metricas = {
        "mttr_simulado_minutos": {
            severidade: round(sum(valores) / len(valores), 2)
            for severidade, valores in mttr_por_severidade.items()
        },
        "tempo_ate_contencao_minutos": {
            severidade: {
                "media": round(sum(valores) / len(valores), 2),
                "p90": p90(valores),
            }
            for severidade, valores in contencao_por_severidade.items()
        },
        "contencao_automatica": {
            severidade: {
                "quantidade": contidos_por_severidade[severidade],
                "percentual_sobre_grupos": round(
                    100 * contidos_por_severidade[severidade] / grupos_por_severidade[severidade], 2
                ) if grupos_por_severidade[severidade] else 0,
            }
            for severidade in ("media", "alta", "critica")
        },
        "pendentes_aprovacao": pendentes_aprovacao,
        "timeouts_plantao_15min": timeouts_plantao,
        "acoes_revertidas_por_ttl": revertidas_ttl,
        "acoes_revertidas_por_falso_positivo": revertidas_falso_positivo,
        "alertas_total": len(alertas),
        "grupos_total": len(grupos),
        "taxa_falsos_positivos": round(
            100 * sum(
                1 for a in alertas
                if rotulos.get(a["alerta_id"], {}).get("rotulo") == "falso_positivo"
            ) / len(alertas), 2
        ) if alertas else 0,
    }
    with open(saida / "metricas_soar.json", "w", encoding="utf-8") as arquivo_metricas:
        json.dump(metricas, arquivo_metricas, ensure_ascii=False, indent=2)

    print(json.dumps({
        "alertas_processados": len(alertas),
        "grupos_15_min": len(grupos),
        "casos": len(casos),
        "acoes": len(acoes),
        "pendentes_aprovacao": pendentes_aprovacao,
        "timeouts_plantao_15min": timeouts_plantao,
        "metricas": metricas,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    principal()
