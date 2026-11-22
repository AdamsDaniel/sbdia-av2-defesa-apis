# AV2: defesa cibernética inteligente para APIs

Repositório do protótipo da Avaliação 2 da disciplina Segurança com Big Data e IA, sobre a Corvina Crédito Digital.

- **Autor:** Daniel Knebel Adams.
- **Dados:** a empresa, as pessoas e todos os dados são fictícios.
- **Relatório:** a proposta, os resultados e a discussão estão no relatório em PDF, entregue no AVA.

| Pasta | Conteúdo |
|---|---|
| `prototipo/` | Gerador de logs de API Gateway/WAF, features por entidade, Isolation Forest × autoencoder, predição de volume, aprendizado contínuo, gráficos e painel Streamlit |
| `soar/` | Simulador SOAR (contenção com TTL, aprovação humana, timeout do plantão, reversão, MTTR) e playbooks no estilo Shuffle |
| `regras/` | Regras Wazuh para API Gateway, WAF e alertas da IA, com logs de exemplo |
| `diagramas/` | Arquitetura, fluxo de resposta e ciclo de aprendizado contínuo |

## Como reproduzir

O `executar_tudo.py` faz o pipeline inteiro em cerca de 80 s:
1. gera os dados;
2. treina e avalia os modelos;
3. simula o feedback do analista;
4. gera os gráficos;
5. aciona o SOAR.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r prototipo\requirements.txt
cd prototipo
..\.venv\Scripts\python.exe executar_tudo.py              # pipeline completo
..\.venv\Scripts\python.exe -m streamlit run dashboard.py  # painel do SOC
..\.venv\Scripts\python.exe robustez_sementes.py           # opcional: repete o teste com 5 sementes (~5 min)
```

Os resultados vão para `prototipo/saida/`, e os do SOAR, para `prototipo/saida/soar/`. As pastas geradas (`prototipo/dados/`, `prototipo/saida/` e `soar/saida/`) não são versionadas.

## SOAR isolado

O simulador usa só a biblioteca padrão do Python. Ele não chama a AWS nem outros serviços externos: as ações (WAF, API Gateway, Cognito, PIX) são registradas com TTL e comando de reversão.

```powershell
.\.venv\Scripts\python.exe soar\simulador_soar.py --entrada soar\exemplos\alertas_exemplo.jsonl --rotulos soar\exemplos\rotulos_exemplo.csv
```

O CSV de rótulos tem as colunas `alerta_id`, `rotulo_analista` (`verdadeiro` ou `falso_positivo`) e `comentario`. A coluna `minutos_resposta` é opcional.

## Regras Wazuh

As regras do `regras/local_rules.xml` usam o decoder JSON nativo do Wazuh:

| IDs | Uso |
|---|---|
| 100200–100215 | API Gateway e WAF |
| 100220–100222 | Ingestão dos alertas da IA |

Elas esperam o access log do API Gateway neste formato personalizado:

```json
{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","usuario":"$context.authorizer.claims.sub","httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath","path":"$context.path","status":"$context.status","responseLength":"$context.responseLength","requestTime":"$context.requestTime"}
```

- `resourcePath` traz o template da rota (`/contas/{id}/saldo`), e `path`, o caminho real.
- O campo do usuário se chama `usuario`, para não colidir com o campo estático `user` do Wazuh.
- A regra 100213 (falha seguida de sucesso) deve ser validada com `wazuh-logtest` antes do uso em produção.
