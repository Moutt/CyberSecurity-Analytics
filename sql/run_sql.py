"""Executa data_clening.sql com DuckDB a partir da raiz do projeto.
Uso: python CyberSecurity-Analytics/sql/run_sql.py  (de qualquer pasta)"""
import os
from pathlib import Path
import duckdb

import sys
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

BASE = Path(__file__).resolve().parents[1]
os.chdir(BASE)  # caminhos relativos do SQL (data/raw, data/processed)
(BASE / 'data' / 'processed').mkdir(parents=True, exist_ok=True)

con = duckdb.connect()
con.execute((BASE / 'sql' / 'data_clening.sql').read_text(encoding='utf-8'))
# print(con.sql("SELECT COUNT(*) AS linhas, SUM(flag_ativo_orfao::INT) orfaos, SUM(flag_data_abertura_invalida::INT) datas_invalidas FROM vulnerabilidades_limpo"))
print('Arquivos gerados em', BASE / 'data' / 'processed')
