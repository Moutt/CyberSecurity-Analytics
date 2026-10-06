# CyberSecurity-Analytics

Link para github: https://github.com/Moutt/CyberSecurity-Analytics

Case de Data Analytics em CyberSecurity: tratamento de qualidade de dados, criação de indicadores de risco e priorização de remediação de vulnerabilidades.

## Contexto

Estudo de dados da área de CyberSecurity

1. Qual é o nível atual de exposição ao risco?
2. Quais ativos demandam maior atenção?
3. Onde devem ser priorizados os esforços de correção?
4. O processo atual de tratamento de vulnerabilidades está sendo efetivo?

As bases vieram com os problemas de qualidade típicos de ambiente corporativo (datas em formatos diferentes, categorias escritas de várias formas, ativos que não existem no inventário etc.), então boa parte do trabalho foi entender e tratar esses dados antes de qualquer análise.

## Estrutura do projeto

```
CyberSecurity-Analytics/
├── data/
│   ├── raw/                  # bases originais (ativos.csv e vulnerabilidades.csv)
│   └── processed/            # bases tratadas, geradas pelo SQL
├── sql/
│   ├── data_clening.sql      # limpeza e modelagem final (dialeto DuckDB)
│   └── run_sql.py            # executa o SQL e grava os arquivos em data/processed
├── notebooks/
│   ├── exploracao_para_limpeza.ipynb   # diagnóstico da qualidade dos dados
│   └── analise_de_risco.ipynb          # análise de risco e efetividade
├── dashboards/
│   └── Acompanhamento indicadores.pbix # dashboard de acompanhamento (Power BI)
└── Apresentação de Cyber Security.pptx # apresentação executiva
```

## Bases de dados

| Arquivo | Conteúdo | Registros |
|---|---|---|
| `ativos.csv` | Inventário de ativos: sistema, criticidade, domínio, ambiente, localidade e status | 200 |
| `vulnerabilidades.csv` | Vulnerabilidades: ativo, severidade, origem, datas, status e CVSS | 2.000 |

Os dois arquivos usam `;` como separador e se relacionam por `ativo_id`.

## Problemas encontrados e como foram tratados

| Problema | Tratamento |
|---|---|
| Severidade informada não bate com o CVSS (só ~26% de concordância) | A severidade passou a ser derivada do `cvss_score` (0–3,9 Baixa, 4–6,9 Média, 7–8,9 Alta, 9–10 Crítica) |
| Datas de abertura em 3 formatos (`dd/mm/aaaa`, `mm-dd-aaaa`, `aaaa-mm-dd`) | Conversão por padrão de formato |
| Datas impossíveis (`31/02`, mês 13) | Viram nulo e ficam fora das métricas de tempo |
| Correções com data futura ou anterior à abertura | Sinalizadas com flag e removidas do tempo de correção |
| Vulnerabilidades ligadas ao ativo `A9999`, que não existe no inventário | Mantidas nos totais, mas fora dos rankings por ativo |
| Criticidade e ambiente vazios ou `N/A` | Categoria "Não Mapeado" |
| Grafias diferentes (`media`, `BaixA`, `Cloud-Security`...) | Normalização dos textos |

O detalhe de cada decisão está no notebook de exploração.

## Como executar

Requisitos: Python 3.11 com `pandas`, `numpy`, `matplotlib`, `seaborn` e `duckdb`.

```bash
pip install pandas numpy matplotlib seaborn duckdb
```

1. Gerar as bases tratadas (lê `data/raw` e grava em `data/processed`):

```bash
python sql/run_sql.py
```

2. Abrir os notebooks em `notebooks/`, nesta ordem:
   1. `exploracao_para_limpeza.ipynb`
   2. `analise_de_risco.ipynb`

Os notebooks usam caminhos relativos, então precisam ser executados a partir da própria pasta `notebooks/`.

## Principais resultados

- **Exposição:** 77% das vulnerabilidades (1.531 de 2.000) continuam sem correção, sendo 172 críticas pelo CVSS. Mais de 70% do backlog tem mais de 90 dias.
- **Ativos:** o risco está espalhado. Os 10 ativos com maior score somam apenas ~14% do risco total, e quase todos são de Produção.
- **Prioridade:** 75 itens entram na fila P1 (CVSS ≥ 9 em Produção ou CVSS ≥ 7 em ativo crítico de Produção). Cerca de 24% do backlog está em ativos em desativação, que podem ser resolvidos pelo descomissionamento.
- **Efetividade:** a taxa de correção é de 23% e quase não muda entre severidades, criticidades e ambientes. Entram cerca de 216 vulnerabilidades por mês e saem cerca de 43, então o backlog só cresce.
- **Riscos aceitos:** 157 dos 517 riscos aceitos têm CVSS ≥ 7 e merecem revisão.

## Indicadores criados

- **Score de risco por ativo:** CVSS × peso da criticidade (Crítica 4, Alta 3, Média 2, Baixa 1) × 1,5 quando o ativo está em Produção.
- **Fila de prioridade P1 a P4:** combina CVSS, ambiente e criticidade do ativo.
- **Idade do backlog:** faixas de 0–30, 31–60, 61–90, 91–180 e acima de 180 dias.
- **Taxa de correção e tempo de correção** por severidade, criticidade e ambiente.

Os pesos do score e os critérios da fila P1–P4 são premissas minhas e podem ser ajustados conforme a regra da área.

## Recomendações

1. Fazer um mutirão de correção nos itens P1.
2. Revisar os riscos aceitos com CVSS alto, definindo responsável e prazo de revisão.
3. Priorizar o descomissionamento dos ativos em desativação.
4. Formalizar a fila P1–P4 com SLA por prioridade.
5. Corrigir a qualidade dos dados na origem (inventário, datas e padronização de valores).

## Limitações

- A data de referência usada nos cálculos de idade e de datas futuras é 04/10/2026.
- A base não traz informações como exploitabilidade (EPSS/KEV) ou exposição à internet, que ajudariam a refinar a priorização.
- Os números têm caráter direcional por causa dos problemas de qualidade descritos acima.