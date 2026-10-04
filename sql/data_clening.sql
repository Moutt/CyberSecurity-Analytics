-- Executar a partir da raiz do projeto (CyberSecurity-Analytics) -> use sql/run_sql.py

-- Leitura das bases brutas
CREATE OR REPLACE VIEW raw_ativos AS
SELECT * FROM read_csv('data/raw/ativos.csv', delim = ';', header = true, all_varchar = true, encoding = 'utf-8');

CREATE OR REPLACE VIEW raw_vulnerabilidades AS
SELECT * FROM read_csv('data/raw/vulnerabilidades.csv', delim = ';', header = true, all_varchar = true, encoding = 'utf-8');

-- Utilizando o TRIM para retirar possíveis espações em branco e padronizando colunas

CREATE OR REPLACE TABLE ativos_tratados AS
SELECT
    TRIM(ativo_id) AS ativo_id,
    TRIM(sistema)  AS sistema,
    CASE lower(strip_accents(TRIM(criticidade)))
        WHEN 'baixa'   THEN 'Baixa'
        WHEN 'media'   THEN 'Média'
        WHEN 'alta'    THEN 'Alta'
        WHEN 'alto'    THEN 'Alta'
        WHEN 'critica' THEN 'Crítica'
        ELSE 'Não Mapeado'
    END AS criticidade,
    TRIM(dominio) AS dominio,
    COALESCE(NULLIF(TRIM(ambiente), ''), 'Não Mapeado') AS ambiente,
    TRIM(localidade)   AS localidade,
    TRIM(status_ativo) AS status_ativo
FROM raw_ativos;

CREATE OR REPLACE TABLE vulnerabilidades_tratadas AS
SELECT
    TRIM(vuln_id)  AS vuln_id,
    TRIM(ativo_id) AS ativo_id,
    -- Regra de negócio: severidade pelo CVSS (a coluna manual diverge em ~74% dos casos)
    CASE
        WHEN TRY_CAST(cvss_score AS DOUBLE) >= 0.0 AND TRY_CAST(cvss_score AS DOUBLE) <= 3.9  THEN 'Baixa'
        WHEN TRY_CAST(cvss_score AS DOUBLE) >= 4.0 AND TRY_CAST(cvss_score AS DOUBLE) <= 6.9  THEN 'Média'
        WHEN TRY_CAST(cvss_score AS DOUBLE) >= 7.0 AND TRY_CAST(cvss_score AS DOUBLE) <= 8.9  THEN 'Alta'
        WHEN TRY_CAST(cvss_score AS DOUBLE) >= 9.0 AND TRY_CAST(cvss_score AS DOUBLE) <= 10.0 THEN 'Crítica'
        ELSE 'Desconhecida'
    END AS severidade_corrigida,
    TRY_CAST(cvss_score AS DOUBLE) AS cvss_score,
    -- Unifica 'CloudSecurity' / 'Cloud-Security'
    CASE WHEN lower(replace(replace(TRIM(origem), '-', ''), ' ', '')) = 'cloudsecurity'
         THEN 'Cloud Security' ELSE TRIM(origem) END AS origem,
    TRIM(status) AS status,
    -- Datas em 3 formatos
    CASE
        WHEN regexp_matches(TRIM(data_abertura), '^\d{2}/\d{2}/\d{4}$') THEN TRY_STRPTIME(TRIM(data_abertura), '%d/%m/%Y')
        WHEN regexp_matches(TRIM(data_abertura), '^\d{2}-\d{2}-\d{4}$') THEN TRY_STRPTIME(TRIM(data_abertura), '%m-%d-%Y')
        WHEN regexp_matches(TRIM(data_abertura), '^\d{4}-\d{2}-\d{2}$') THEN TRY_STRPTIME(TRIM(data_abertura), '%Y-%m-%d')
    END::DATE AS data_abertura,
    TRY_STRPTIME(NULLIF(TRIM(data_correcao), ''), '%d/%m/%Y')::DATE AS data_correcao
FROM raw_vulnerabilidades;

-- Modelo final
CREATE OR REPLACE TABLE vulnerabilidades_limpo AS
SELECT
    v.vuln_id,
    v.ativo_id,
    v.severidade_corrigida,
    v.cvss_score,
    v.origem,
    v.status AS status_vulnerabilidade,
    v.data_abertura,
    v.data_correcao,
    COALESCE(a.sistema, 'Sistema Desconhecido')    AS sistema,
    COALESCE(a.criticidade, 'Não Mapeado')         AS criticidade_ativo,
    COALESCE(a.ambiente, 'Ambiente Desconhecido')  AS ambiente,
    COALESCE(a.status_ativo, 'Desconhecido')       AS status_ativo,
    (a.ativo_id IS NULL)                           AS flag_ativo_orfao,
    (v.data_abertura IS NULL)                      AS flag_data_abertura_invalida,
    (v.data_correcao > DATE '2026-10-04')          AS flag_data_correcao_futura,
    CASE WHEN v.data_correcao < v.data_abertura THEN 1 ELSE 0 END AS flag_erro_data_sla,
    -- Tempo de resolução só para registros logicamente válidos
    CASE
        WHEN v.status = 'Corrigida' AND v.data_correcao >= v.data_abertura
             AND v.data_correcao <= DATE '2026-10-04'
        THEN DATEDIFF('day', v.data_abertura, v.data_correcao)
    END AS dias_para_correcao
FROM vulnerabilidades_tratadas v
LEFT JOIN ativos_tratados a ON v.ativo_id = a.ativo_id;

-- Saída em data/processed
COPY ativos_tratados TO 'data/processed/ativos_limpo.csv' (HEADER, DELIMITER ';');
COPY vulnerabilidades_limpo TO 'data/processed/vulnerabilidades_limpo.csv' (HEADER, DELIMITER ';');