/*******************************************************************************
 * RBAC STORED PROCEDURE: Governance Monitoring Dashboard
 * 
 * Purpose: Real-time monitoring of data governance policies, compliance,
 *          and protection coverage across the organization
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          GOVERNANCE
 *   Object Type:     PROCEDURES (~6)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN, SRF_*_DBADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and GOVERNANCE schema must exist
 *     - RBAC_SP_Data_Governance.sql must be deployed first
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DASHBOARD COMPONENTS:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Policy Coverage        - How much data is protected by policies
 *   • Classification Status  - Data classification coverage and gaps
 *   • Compliance Scorecard   - Overall governance compliance metrics
 *   • Sensitive Data Map     - Where sensitive data exists
 *   • Policy Effectiveness   - Policy usage and access patterns
 *   • Unprotected Data Scan  - Identify data needing governance
 * 
 * DEPLOYMENT: ADMIN.GOVERNANCE schema
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA GOVERNANCE;

-- #############################################################################
-- SECTION 1: POLICY COVERAGE DASHBOARD
-- #############################################################################

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_POLICY_COVERAGE_DASHBOARD(
    P_DATABASE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_total_tables INTEGER;
    v_tables_with_rls INTEGER;
    v_total_columns INTEGER;
    v_columns_with_masking INTEGER;
    v_by_policy_type VARIANT;
    v_by_database ARRAY;
    v_coverage_by_schema ARRAY;
    v_unprotected_sensitive ARRAY;
BEGIN
    -- Count tables with row access policies
    SELECT COUNT(DISTINCT TARGET_DATABASE || '.' || TARGET_SCHEMA || '.' || TARGET_OBJECT)
    INTO v_tables_with_rls
    FROM GOVERNANCE_POLICY_APPLICATIONS
    WHERE POLICY_TYPE = 'ROW_ACCESS_POLICY' AND STATUS = 'ACTIVE'
      AND (P_DATABASE IS NULL OR TARGET_DATABASE = P_DATABASE);
    
    -- Count columns with masking policies
    SELECT COUNT(*)
    INTO v_columns_with_masking
    FROM GOVERNANCE_POLICY_APPLICATIONS
    WHERE POLICY_TYPE = 'MASKING_POLICY' AND STATUS = 'ACTIVE'
      AND (P_DATABASE IS NULL OR TARGET_DATABASE = P_DATABASE);
    
    -- Get total counts from information schema
    SELECT COUNT(DISTINCT TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME)
    INTO v_total_tables
    FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
    WHERE DELETED IS NULL
      AND TABLE_TYPE = 'BASE TABLE'
      AND (P_DATABASE IS NULL OR TABLE_CATALOG = P_DATABASE);
    
    SELECT COUNT(*)
    INTO v_total_columns
    FROM SNOWFLAKE.ACCOUNT_USAGE.COLUMNS
    WHERE DELETED IS NULL
      AND (P_DATABASE IS NULL OR TABLE_CATALOG = P_DATABASE);
    
    -- Policies by type
    SELECT OBJECT_AGG(POLICY_TYPE, CNT) INTO v_by_policy_type
    FROM (
        SELECT POLICY_TYPE, COUNT(*) AS CNT
        FROM GOVERNANCE_POLICY_APPLICATIONS
        WHERE STATUS = 'ACTIVE'
          AND (P_DATABASE IS NULL OR TARGET_DATABASE = P_DATABASE)
        GROUP BY POLICY_TYPE
    );
    
    -- Coverage by database
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', DB,
        'masking_policies', MASK_CNT,
        'rls_policies', RLS_CNT,
        'classified_columns', CLASS_CNT
    )) INTO v_by_database
    FROM (
        SELECT 
            COALESCE(p.TARGET_DATABASE, c.DATABASE_NAME) AS DB,
            COUNT(DISTINCT CASE WHEN p.POLICY_TYPE = 'MASKING_POLICY' THEN p.APPLICATION_ID END) AS MASK_CNT,
            COUNT(DISTINCT CASE WHEN p.POLICY_TYPE = 'ROW_ACCESS_POLICY' THEN p.APPLICATION_ID END) AS RLS_CNT,
            COUNT(DISTINCT c.CLASSIFICATION_ID) AS CLASS_CNT
        FROM GOVERNANCE_POLICY_APPLICATIONS p
        FULL OUTER JOIN GOVERNANCE_DATA_CLASSIFICATIONS c
            ON p.TARGET_DATABASE = c.DATABASE_NAME
        WHERE (p.STATUS = 'ACTIVE' OR c.DATABASE_NAME IS NOT NULL)
          AND (P_DATABASE IS NULL OR COALESCE(p.TARGET_DATABASE, c.DATABASE_NAME) = P_DATABASE)
        GROUP BY DB
        HAVING DB IS NOT NULL
    );
    
    -- Unprotected sensitive columns
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', DATABASE_NAME,
        'schema', SCHEMA_NAME,
        'table', TABLE_NAME,
        'column', COLUMN_NAME,
        'classification', CLASSIFICATION_TAG,
        'sensitivity', SENSITIVITY_LEVEL,
        'data_type', DATA_TYPE_CATEGORY
    )) INTO v_unprotected_sensitive
    FROM GOVERNANCE_DATA_CLASSIFICATIONS c
    WHERE REQUIRES_MASKING = TRUE
      AND NOT EXISTS (
          SELECT 1 FROM GOVERNANCE_POLICY_APPLICATIONS p
          WHERE p.TARGET_DATABASE = c.DATABASE_NAME
            AND p.TARGET_SCHEMA = c.SCHEMA_NAME
            AND p.TARGET_OBJECT = c.TABLE_NAME
            AND p.TARGET_COLUMN = c.COLUMN_NAME
            AND p.POLICY_TYPE = 'MASKING_POLICY'
            AND p.STATUS = 'ACTIVE'
      )
      AND (P_DATABASE IS NULL OR DATABASE_NAME = P_DATABASE)
    LIMIT 50;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'POLICY_COVERAGE',
        'generated_at', CURRENT_TIMESTAMP(),
        'filter', OBJECT_CONSTRUCT('database', P_DATABASE),
        'summary', OBJECT_CONSTRUCT(
            'total_tables', v_total_tables,
            'tables_with_rls', v_tables_with_rls,
            'rls_coverage_pct', ROUND(v_tables_with_rls * 100.0 / NULLIF(v_total_tables, 0), 1),
            'total_columns', v_total_columns,
            'columns_with_masking', v_columns_with_masking,
            'masking_coverage_pct', ROUND(v_columns_with_masking * 100.0 / NULLIF(v_total_columns, 0), 2)
        ),
        'by_policy_type', COALESCE(v_by_policy_type, OBJECT_CONSTRUCT()),
        'by_database', COALESCE(v_by_database, ARRAY_CONSTRUCT()),
        'unprotected_sensitive_columns', COALESCE(v_unprotected_sensitive, ARRAY_CONSTRUCT()),
        'unprotected_count', ARRAY_SIZE(COALESCE(v_unprotected_sensitive, ARRAY_CONSTRUCT()))
    );
END;
$$;

-- #############################################################################
-- SECTION 2: CLASSIFICATION STATUS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Classification Status Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_CLASSIFICATION_STATUS_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_total_classified INTEGER;
    v_by_classification VARIANT;
    v_by_sensitivity VARIANT;
    v_by_data_type VARIANT;
    v_by_database ARRAY;
    v_needing_attention ARRAY;
    v_recent_classifications ARRAY;
BEGIN
    -- Total classified columns
    SELECT COUNT(*) INTO v_total_classified
    FROM GOVERNANCE_DATA_CLASSIFICATIONS;
    
    -- By classification tag
    SELECT OBJECT_AGG(CLASSIFICATION_TAG, CNT) INTO v_by_classification
    FROM (
        SELECT CLASSIFICATION_TAG, COUNT(*) AS CNT
        FROM GOVERNANCE_DATA_CLASSIFICATIONS
        GROUP BY CLASSIFICATION_TAG
    );
    
    -- By sensitivity level
    SELECT OBJECT_AGG(SENSITIVITY_LEVEL, CNT) INTO v_by_sensitivity
    FROM (
        SELECT SENSITIVITY_LEVEL, COUNT(*) AS CNT
        FROM GOVERNANCE_DATA_CLASSIFICATIONS
        GROUP BY SENSITIVITY_LEVEL
    );
    
    -- By data type category
    SELECT OBJECT_AGG(COALESCE(DATA_TYPE_CATEGORY, 'UNKNOWN'), CNT) INTO v_by_data_type
    FROM (
        SELECT DATA_TYPE_CATEGORY, COUNT(*) AS CNT
        FROM GOVERNANCE_DATA_CLASSIFICATIONS
        GROUP BY DATA_TYPE_CATEGORY
    );
    
    -- By database
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', DATABASE_NAME,
        'classified_columns', CNT,
        'pii_columns', PII_CNT,
        'critical_columns', CRIT_CNT,
        'needing_masking', MASK_NEEDED
    )) INTO v_by_database
    FROM (
        SELECT 
            DATABASE_NAME,
            COUNT(*) AS CNT,
            COUNT_IF(CLASSIFICATION_TAG = 'PII') AS PII_CNT,
            COUNT_IF(SENSITIVITY_LEVEL = 'CRITICAL') AS CRIT_CNT,
            COUNT_IF(REQUIRES_MASKING = TRUE) AS MASK_NEEDED
        FROM GOVERNANCE_DATA_CLASSIFICATIONS
        GROUP BY DATABASE_NAME
    );
    
    -- Columns needing attention (critical but not verified)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'column', DATABASE_NAME || '.' || SCHEMA_NAME || '.' || TABLE_NAME || '.' || COLUMN_NAME,
        'classification', CLASSIFICATION_TAG,
        'sensitivity', SENSITIVITY_LEVEL,
        'classified_at', CLASSIFIED_AT,
        'issue', CASE 
            WHEN VERIFIED_BY IS NULL AND SENSITIVITY_LEVEL = 'CRITICAL' THEN 'CRITICAL_NOT_VERIFIED'
            WHEN REQUIRES_MASKING = TRUE THEN 'NEEDS_MASKING'
            ELSE 'REVIEW_RECOMMENDED'
        END
    )) INTO v_needing_attention
    FROM GOVERNANCE_DATA_CLASSIFICATIONS
    WHERE (SENSITIVITY_LEVEL = 'CRITICAL' AND VERIFIED_BY IS NULL)
       OR (REQUIRES_MASKING = TRUE)
    LIMIT 30;
    
    -- Recent classifications
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'column', DATABASE_NAME || '.' || SCHEMA_NAME || '.' || TABLE_NAME || '.' || COLUMN_NAME,
        'classification', CLASSIFICATION_TAG,
        'sensitivity', SENSITIVITY_LEVEL,
        'classified_by', CLASSIFIED_BY,
        'classified_at', CLASSIFIED_AT
    )) INTO v_recent_classifications
    FROM GOVERNANCE_DATA_CLASSIFICATIONS
    LIMIT 20;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'CLASSIFICATION_STATUS',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_classified_columns', v_total_classified,
            'databases_with_classifications', ARRAY_SIZE(COALESCE(v_by_database, ARRAY_CONSTRUCT())),
            'columns_needing_attention', ARRAY_SIZE(COALESCE(v_needing_attention, ARRAY_CONSTRUCT()))
        ),
        'by_classification', COALESCE(v_by_classification, OBJECT_CONSTRUCT()),
        'by_sensitivity', COALESCE(v_by_sensitivity, OBJECT_CONSTRUCT()),
        'by_data_type', COALESCE(v_by_data_type, OBJECT_CONSTRUCT()),
        'by_database', COALESCE(v_by_database, ARRAY_CONSTRUCT()),
        'needing_attention', COALESCE(v_needing_attention, ARRAY_CONSTRUCT()),
        'recent_classifications', COALESCE(v_recent_classifications, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 3: COMPLIANCE SCORECARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Governance Compliance Scorecard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_GOVERNANCE_COMPLIANCE_SCORECARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_scores ARRAY := ARRAY_CONSTRUCT();
    v_total_score INTEGER := 0;
    v_max_score INTEGER := 0;
    v_classified_count INTEGER;
    v_masked_count INTEGER;
    v_rls_count INTEGER;
    v_tagged_count INTEGER;
    v_critical_unprotected INTEGER;
    v_recommendations ARRAY := ARRAY_CONSTRUCT();
    v_classification_score INTEGER;
    v_masking_score INTEGER;
    v_rls_score INTEGER;
    v_tagging_score INTEGER;
BEGIN
    -- Score 1: Classification Coverage (max 25 points)
    SELECT COUNT(*) INTO v_classified_count FROM GOVERNANCE_DATA_CLASSIFICATIONS;
    v_classification_score := LEAST(FLOOR(v_classified_count / 10), 25);
    v_scores := ARRAY_APPEND(v_scores, OBJECT_CONSTRUCT(
        'category', 'DATA_CLASSIFICATION',
        'score', v_classification_score,
        'max_score', 25,
        'metric', v_classified_count || ' columns classified',
        'status', CASE WHEN v_classification_score >= 20 THEN 'GOOD' WHEN v_classification_score >= 10 THEN 'FAIR' ELSE 'NEEDS_IMPROVEMENT' END
    ));
    v_total_score := v_total_score + v_classification_score;
    v_max_score := v_max_score + 25;
    
    -- Score 2: Masking Policy Coverage (max 25 points)
    SELECT COUNT(*) INTO v_masked_count 
    FROM GOVERNANCE_POLICY_APPLICATIONS 
    WHERE POLICY_TYPE = 'MASKING_POLICY' AND STATUS = 'ACTIVE';
    
    SELECT COUNT(*) INTO v_critical_unprotected
    FROM GOVERNANCE_DATA_CLASSIFICATIONS
    WHERE REQUIRES_MASKING = TRUE
      AND NOT EXISTS (
          SELECT 1 FROM GOVERNANCE_POLICY_APPLICATIONS p
          WHERE p.TARGET_DATABASE = GOVERNANCE_DATA_CLASSIFICATIONS.DATABASE_NAME
            AND p.TARGET_COLUMN = GOVERNANCE_DATA_CLASSIFICATIONS.COLUMN_NAME
            AND p.POLICY_TYPE = 'MASKING_POLICY'
            AND p.STATUS = 'ACTIVE'
      );
    
    v_masking_score := CASE 
        WHEN v_critical_unprotected = 0 AND v_masked_count > 0 THEN 25
        WHEN v_critical_unprotected <= 5 THEN 20
        WHEN v_critical_unprotected <= 10 THEN 15
        WHEN v_critical_unprotected <= 20 THEN 10
        ELSE 5
    END;
    v_scores := ARRAY_APPEND(v_scores, OBJECT_CONSTRUCT(
        'category', 'MASKING_COVERAGE',
        'score', v_masking_score,
        'max_score', 25,
        'metric', v_masked_count || ' columns masked, ' || v_critical_unprotected || ' sensitive unprotected',
        'status', CASE WHEN v_masking_score >= 20 THEN 'GOOD' WHEN v_masking_score >= 10 THEN 'FAIR' ELSE 'NEEDS_IMPROVEMENT' END
    ));
    v_total_score := v_total_score + v_masking_score;
    v_max_score := v_max_score + 25;
    
    IF (v_critical_unprotected > 0) THEN
        v_recommendations := ARRAY_APPEND(v_recommendations, OBJECT_CONSTRUCT(
            'priority', 'HIGH',
            'recommendation', 'Apply masking policies to ' || v_critical_unprotected || ' sensitive columns',
            'action', 'CALL ADMIN.GOVERNANCE.RBAC_APPLY_MASKING_TO_CLASSIFIED(''ADMIN'', ''GOVERNANCE'', NULL, NULL, FALSE);'
        ));
    END IF;
    
    -- Score 3: Row-Level Security (max 25 points)
    SELECT COUNT(DISTINCT TARGET_DATABASE || '.' || TARGET_SCHEMA || '.' || TARGET_OBJECT) INTO v_rls_count
    FROM GOVERNANCE_POLICY_APPLICATIONS
    WHERE POLICY_TYPE = 'ROW_ACCESS_POLICY' AND STATUS = 'ACTIVE';
    
    v_rls_score := LEAST(v_rls_count * 5, 25);
    v_scores := ARRAY_APPEND(v_scores, OBJECT_CONSTRUCT(
        'category', 'ROW_LEVEL_SECURITY',
        'score', v_rls_score,
        'max_score', 25,
        'metric', v_rls_count || ' tables with RLS',
        'status', CASE WHEN v_rls_score >= 20 THEN 'GOOD' WHEN v_rls_score >= 10 THEN 'FAIR' ELSE 'NEEDS_IMPROVEMENT' END
    ));
    v_total_score := v_total_score + v_rls_score;
    v_max_score := v_max_score + 25;
    
    -- Score 4: Tagging Coverage (max 25 points)
    SELECT COUNT(*) INTO v_tagged_count FROM GOVERNANCE_TAG_APPLICATIONS;
    v_tagging_score := LEAST(FLOOR(v_tagged_count / 5), 25);
    v_scores := ARRAY_APPEND(v_scores, OBJECT_CONSTRUCT(
        'category', 'DATA_TAGGING',
        'score', v_tagging_score,
        'max_score', 25,
        'metric', v_tagged_count || ' tags applied',
        'status', CASE WHEN v_tagging_score >= 20 THEN 'GOOD' WHEN v_tagging_score >= 10 THEN 'FAIR' ELSE 'NEEDS_IMPROVEMENT' END
    ));
    v_total_score := v_total_score + v_tagging_score;
    v_max_score := v_max_score + 25;
    
    -- Generate recommendations
    IF (v_classification_score < 15) THEN
        v_recommendations := ARRAY_APPEND(v_recommendations, OBJECT_CONSTRUCT(
            'priority', 'MEDIUM',
            'recommendation', 'Increase data classification coverage',
            'action', 'Run RBAC_AUTO_CLASSIFY_TABLE for key tables'
        ));
    END IF;
    
    IF (v_rls_score < 10) THEN
        v_recommendations := ARRAY_APPEND(v_recommendations, OBJECT_CONSTRUCT(
            'priority', 'MEDIUM',
            'recommendation', 'Implement row-level security on sensitive tables',
            'action', 'Create and apply row access policies'
        ));
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'GOVERNANCE_COMPLIANCE_SCORECARD',
        'generated_at', CURRENT_TIMESTAMP(),
        'overall', OBJECT_CONSTRUCT(
            'score', v_total_score,
            'max_score', v_max_score,
            'percentage', ROUND(v_total_score * 100.0 / v_max_score, 1),
            'grade', CASE 
                WHEN v_total_score >= 90 THEN 'A'
                WHEN v_total_score >= 75 THEN 'B'
                WHEN v_total_score >= 60 THEN 'C'
                WHEN v_total_score >= 40 THEN 'D'
                ELSE 'F'
            END,
            'status', CASE 
                WHEN v_total_score >= 80 THEN 'COMPLIANT'
                WHEN v_total_score >= 50 THEN 'PARTIALLY_COMPLIANT'
                ELSE 'NON_COMPLIANT'
            END
        ),
        'scores', v_scores,
        'recommendations', v_recommendations
    );
END;
$$;

-- #############################################################################
-- SECTION 4: SENSITIVE DATA MAP
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Sensitive Data Map
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_SENSITIVE_DATA_MAP(
    P_SENSITIVITY_LEVEL VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_by_database VARIANT;
    v_by_classification VARIANT;
    v_critical_data VARIANT;
    v_data_flow VARIANT;
    v_total_sensitive INTEGER;
BEGIN
    -- Total sensitive columns
    SELECT COUNT(*) INTO v_total_sensitive
    FROM GOVERNANCE_DATA_CLASSIFICATIONS
    WHERE (P_SENSITIVITY_LEVEL IS NULL OR SENSITIVITY_LEVEL = P_SENSITIVITY_LEVEL);
    
    -- By database with schema breakdown
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', DATABASE_NAME,
        'schemas', SCHEMAS,
        'total_sensitive', TOTAL,
        'critical', CRIT,
        'high', HIGH_CNT,
        'medium', MED
    )) INTO v_by_database
    FROM (
        SELECT 
            DATABASE_NAME,
            ARRAY_AGG(DISTINCT SCHEMA_NAME) AS SCHEMAS,
            COUNT(*) AS TOTAL,
            COUNT_IF(SENSITIVITY_LEVEL = 'CRITICAL') AS CRIT,
            COUNT_IF(SENSITIVITY_LEVEL = 'HIGH') AS HIGH_CNT,
            COUNT_IF(SENSITIVITY_LEVEL = 'MEDIUM') AS MED
        FROM GOVERNANCE_DATA_CLASSIFICATIONS
        WHERE (P_SENSITIVITY_LEVEL IS NULL OR SENSITIVITY_LEVEL = P_SENSITIVITY_LEVEL)
        GROUP BY DATABASE_NAME
    );
    
    -- By classification type with locations
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'classification', CLASSIFICATION_TAG,
        'count', CNT,
        'databases', DBS,
        'data_types', TYPES
    )) INTO v_by_classification
    FROM (
        SELECT 
            CLASSIFICATION_TAG,
            COUNT(*) AS CNT,
            ARRAY_AGG(DISTINCT DATABASE_NAME) AS DBS,
            ARRAY_AGG(DISTINCT DATA_TYPE_CATEGORY) AS TYPES
        FROM GOVERNANCE_DATA_CLASSIFICATIONS
        WHERE (P_SENSITIVITY_LEVEL IS NULL OR SENSITIVITY_LEVEL = P_SENSITIVITY_LEVEL)
        GROUP BY CLASSIFICATION_TAG
    );
    
    -- Critical data details
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'location', c.DATABASE_NAME || '.' || c.SCHEMA_NAME || '.' || c.TABLE_NAME || '.' || c.COLUMN_NAME,
        'classification', c.CLASSIFICATION_TAG,
        'data_type', c.DATA_TYPE_CATEGORY,
        'is_protected', IFF(p.TARGET_COLUMN IS NOT NULL, TRUE, FALSE)
    )) INTO v_critical_data
    FROM GOVERNANCE_DATA_CLASSIFICATIONS c
    LEFT JOIN GOVERNANCE_POLICY_APPLICATIONS p
        ON p.TARGET_DATABASE = c.DATABASE_NAME
        AND p.TARGET_COLUMN = c.COLUMN_NAME
        AND p.STATUS = 'ACTIVE'
    WHERE c.SENSITIVITY_LEVEL = 'CRITICAL'
    LIMIT 50;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'SENSITIVE_DATA_MAP',
        'generated_at', CURRENT_TIMESTAMP(),
        'filter', OBJECT_CONSTRUCT('sensitivity_level', P_SENSITIVITY_LEVEL),
        'summary', OBJECT_CONSTRUCT(
            'total_sensitive_columns', v_total_sensitive,
            'databases_with_sensitive_data', ARRAY_SIZE(COALESCE(v_by_database, ARRAY_CONSTRUCT())),
            'classification_types', ARRAY_SIZE(COALESCE(v_by_classification, ARRAY_CONSTRUCT()))
        ),
        'by_database', COALESCE(v_by_database, ARRAY_CONSTRUCT()),
        'by_classification', COALESCE(v_by_classification, ARRAY_CONSTRUCT()),
        'critical_data', COALESCE(v_critical_data, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 5: UNPROTECTED DATA SCAN
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Scan for Unprotected Sensitive Data
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_SCAN_UNPROTECTED_DATA(
    P_DATABASE VARCHAR DEFAULT NULL,
    P_SCHEMA VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_unprotected_classified ARRAY;
    v_potentially_sensitive ARRAY;
    v_tables_without_rls ARRAY;
    v_risk_summary VARIANT;
    v_critical_count INTEGER := 0;
    v_high_count INTEGER := 0;
BEGIN
    -- Classified but unprotected (no masking policy)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', DATABASE_NAME,
        'schema', SCHEMA_NAME,
        'table', TABLE_NAME,
        'column', COLUMN_NAME,
        'classification', CLASSIFICATION_TAG,
        'sensitivity', SENSITIVITY_LEVEL,
        'data_type', DATA_TYPE_CATEGORY,
        'risk', CASE 
            WHEN SENSITIVITY_LEVEL = 'CRITICAL' THEN 'CRITICAL'
            WHEN SENSITIVITY_LEVEL = 'HIGH' THEN 'HIGH'
            ELSE 'MEDIUM'
        END
    )) INTO v_unprotected_classified
    FROM GOVERNANCE_DATA_CLASSIFICATIONS c
    WHERE REQUIRES_MASKING = TRUE
      AND NOT EXISTS (
          SELECT 1 FROM GOVERNANCE_POLICY_APPLICATIONS p
          WHERE p.TARGET_DATABASE = c.DATABASE_NAME
            AND p.TARGET_SCHEMA = c.SCHEMA_NAME
            AND p.TARGET_OBJECT = c.TABLE_NAME
            AND p.TARGET_COLUMN = c.COLUMN_NAME
            AND p.POLICY_TYPE = 'MASKING_POLICY'
            AND p.STATUS = 'ACTIVE'
      )
      AND (P_DATABASE IS NULL OR DATABASE_NAME = P_DATABASE)
      AND (P_SCHEMA IS NULL OR SCHEMA_NAME = P_SCHEMA)
    LIMIT 100;
    
    -- Count by severity
    SELECT 
        COUNT_IF(SENSITIVITY_LEVEL = 'CRITICAL'),
        COUNT_IF(SENSITIVITY_LEVEL = 'HIGH')
    INTO v_critical_count, v_high_count
    FROM GOVERNANCE_DATA_CLASSIFICATIONS c
    WHERE REQUIRES_MASKING = TRUE
      AND NOT EXISTS (
          SELECT 1 FROM GOVERNANCE_POLICY_APPLICATIONS p
          WHERE p.TARGET_DATABASE = c.DATABASE_NAME
            AND p.TARGET_COLUMN = c.COLUMN_NAME
            AND p.POLICY_TYPE = 'MASKING_POLICY'
            AND p.STATUS = 'ACTIVE'
      );
    
    -- Potentially sensitive columns (name pattern match, not yet classified)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'database', TABLE_CATALOG,
        'schema', TABLE_SCHEMA,
        'table', TABLE_NAME,
        'column', COLUMN_NAME,
        'data_type', DATA_TYPE,
        'potential_type', CASE 
            WHEN UPPER(COLUMN_NAME) LIKE '%EMAIL%' THEN 'EMAIL'
            WHEN UPPER(COLUMN_NAME) LIKE '%SSN%' OR UPPER(COLUMN_NAME) LIKE '%SOCIAL%' THEN 'SSN'
            WHEN UPPER(COLUMN_NAME) LIKE '%PHONE%' OR UPPER(COLUMN_NAME) LIKE '%MOBILE%' THEN 'PHONE'
            WHEN UPPER(COLUMN_NAME) LIKE '%CREDIT%' OR UPPER(COLUMN_NAME) LIKE '%CARD%NUM%' THEN 'CREDIT_CARD'
            WHEN UPPER(COLUMN_NAME) LIKE '%PASSWORD%' OR UPPER(COLUMN_NAME) LIKE '%SECRET%' THEN 'CREDENTIAL'
            WHEN UPPER(COLUMN_NAME) LIKE '%SALARY%' OR UPPER(COLUMN_NAME) LIKE '%WAGE%' THEN 'FINANCIAL'
            ELSE 'PII'
        END
    )) INTO v_potentially_sensitive
    FROM SNOWFLAKE.ACCOUNT_USAGE.COLUMNS
    WHERE DELETED IS NULL
      AND (
          UPPER(COLUMN_NAME) LIKE '%EMAIL%'
          OR UPPER(COLUMN_NAME) LIKE '%SSN%'
          OR UPPER(COLUMN_NAME) LIKE '%PHONE%'
          OR UPPER(COLUMN_NAME) LIKE '%CREDIT%CARD%'
          OR UPPER(COLUMN_NAME) LIKE '%PASSWORD%'
          OR UPPER(COLUMN_NAME) LIKE '%SALARY%'
          OR UPPER(COLUMN_NAME) LIKE '%SOCIAL_SEC%'
      )
      AND NOT EXISTS (
          SELECT 1 FROM GOVERNANCE_DATA_CLASSIFICATIONS c
          WHERE c.DATABASE_NAME = TABLE_CATALOG
            AND c.SCHEMA_NAME = TABLE_SCHEMA
            AND c.TABLE_NAME = COLUMNS.TABLE_NAME
            AND c.COLUMN_NAME = COLUMNS.COLUMN_NAME
      )
      AND (P_DATABASE IS NULL OR TABLE_CATALOG = P_DATABASE)
      AND (P_SCHEMA IS NULL OR TABLE_SCHEMA = P_SCHEMA)
    LIMIT 100;
    
    -- Risk summary
    v_risk_summary := OBJECT_CONSTRUCT(
        'critical_unprotected', v_critical_count,
        'high_unprotected', v_high_count,
        'total_unprotected_classified', ARRAY_SIZE(COALESCE(v_unprotected_classified, ARRAY_CONSTRUCT())),
        'potentially_sensitive_unclassified', ARRAY_SIZE(COALESCE(v_potentially_sensitive, ARRAY_CONSTRUCT())),
        'risk_level', CASE 
            WHEN v_critical_count > 0 THEN 'CRITICAL'
            WHEN v_high_count > 5 THEN 'HIGH'
            WHEN ARRAY_SIZE(COALESCE(v_unprotected_classified, ARRAY_CONSTRUCT())) > 10 THEN 'MEDIUM'
            ELSE 'LOW'
        END
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'UNPROTECTED_DATA_SCAN',
        'generated_at', CURRENT_TIMESTAMP(),
        'filter', OBJECT_CONSTRUCT('database', P_DATABASE, 'schema', P_SCHEMA),
        'risk_summary', v_risk_summary,
        'unprotected_classified', COALESCE(v_unprotected_classified, ARRAY_CONSTRUCT()),
        'potentially_sensitive_unclassified', COALESCE(v_potentially_sensitive, ARRAY_CONSTRUCT()),
        'recommendations', ARRAY_CONSTRUCT(
            OBJECT_CONSTRUCT(
                'action', 'CLASSIFY_SENSITIVE',
                'description', 'Run auto-classification on tables with potentially sensitive data',
                'command', 'CALL ADMIN.GOVERNANCE.RBAC_AUTO_CLASSIFY_TABLE(database, schema, table);'
            ),
            OBJECT_CONSTRUCT(
                'action', 'APPLY_MASKING',
                'description', 'Apply masking policies to classified sensitive columns',
                'command', 'CALL ADMIN.GOVERNANCE.RBAC_APPLY_MASKING_TO_CLASSIFIED(''ADMIN'', ''GOVERNANCE'', NULL, NULL, FALSE);'
            )
        )
    );
END;
$$;

-- #############################################################################
-- SECTION 6: GOVERNANCE AUDIT REPORT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Governance Audit Report
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_GOVERNANCE_AUDIT_REPORT(
    P_START_DATE DATE DEFAULT NULL,
    P_END_DATE DATE DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_start DATE;
    v_end DATE;
    v_by_action VARIANT;
    v_by_object_type VARIANT;
    v_by_user ARRAY;
    v_recent_activity ARRAY;
    v_policy_changes ARRAY;
    v_total_actions INTEGER;
BEGIN
    v_start := COALESCE(P_START_DATE, DATEADD(DAY, -30, CURRENT_DATE()));
    v_end := COALESCE(P_END_DATE, CURRENT_DATE());
    
    -- Total actions
    SELECT COUNT(*) INTO v_total_actions
    FROM GOVERNANCE_AUDIT_LOG
    WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end;
    
    -- By action
    SELECT OBJECT_AGG(ACTION, CNT) INTO v_by_action
    FROM (
        SELECT ACTION, COUNT(*) AS CNT
        FROM GOVERNANCE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end
        GROUP BY ACTION
    );
    
    -- By object type
    SELECT OBJECT_AGG(OBJECT_TYPE, CNT) INTO v_by_object_type
    FROM (
        SELECT OBJECT_TYPE, COUNT(*) AS CNT
        FROM GOVERNANCE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end
        GROUP BY OBJECT_TYPE
    );
    
    -- By user
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', PERFORMED_BY,
        'action_count', CNT,
        'last_action', LAST_ACT
    )) INTO v_by_user
    FROM (
        SELECT PERFORMED_BY, COUNT(*) AS CNT, MAX(TIMESTAMP) AS LAST_ACT
        FROM GOVERNANCE_AUDIT_LOG
        WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end
        GROUP BY PERFORMED_BY
        LIMIT 20
    );
    
    -- Recent activity
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'timestamp', TIMESTAMP,
        'action', ACTION,
        'object_type', OBJECT_TYPE,
        'object_name', OBJECT_NAME,
        'target', COALESCE(TARGET_DATABASE || '.' || TARGET_SCHEMA || '.' || TARGET_OBJECT, 'N/A'),
        'performed_by', PERFORMED_BY,
        'status', STATUS
    )) INTO v_recent_activity
    FROM GOVERNANCE_AUDIT_LOG
    WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end
    LIMIT 50;
    
    -- Policy changes (creates and removes)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'timestamp', TIMESTAMP,
        'action', ACTION,
        'policy_type', OBJECT_TYPE,
        'policy_name', OBJECT_NAME,
        'performed_by', PERFORMED_BY
    )) INTO v_policy_changes
    FROM GOVERNANCE_AUDIT_LOG
    WHERE TIMESTAMP::DATE BETWEEN v_start AND v_end
      AND ACTION IN ('CREATE', 'REMOVE', 'DROP')
    LIMIT 30;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'GOVERNANCE_AUDIT_REPORT',
        'generated_at', CURRENT_TIMESTAMP(),
        'period', OBJECT_CONSTRUCT('start', v_start, 'end', v_end),
        'summary', OBJECT_CONSTRUCT(
            'total_actions', v_total_actions,
            'unique_users', ARRAY_SIZE(COALESCE(v_by_user, ARRAY_CONSTRUCT())),
            'policy_changes', ARRAY_SIZE(COALESCE(v_policy_changes, ARRAY_CONSTRUCT()))
        ),
        'by_action', COALESCE(v_by_action, OBJECT_CONSTRUCT()),
        'by_object_type', COALESCE(v_by_object_type, OBJECT_CONSTRUCT()),
        'by_user', COALESCE(v_by_user, ARRAY_CONSTRUCT()),
        'recent_activity', COALESCE(v_recent_activity, ARRAY_CONSTRUCT()),
        'policy_changes', COALESCE(v_policy_changes, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 7: UNIFIED GOVERNANCE MONITORING DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Governance Monitoring Dashboard (Unified)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_GOVERNANCE_MONITORING_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_coverage VARIANT;
    v_classification VARIANT;
    v_scorecard VARIANT;
    v_unprotected VARIANT;
    v_overall_health VARCHAR;
    v_alerts ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Gather dashboards
    CALL ADMIN.GOVERNANCE.RBAC_POLICY_COVERAGE_DASHBOARD(NULL) INTO v_coverage;
    CALL ADMIN.GOVERNANCE.RBAC_CLASSIFICATION_STATUS_DASHBOARD() INTO v_classification;
    CALL ADMIN.GOVERNANCE.RBAC_GOVERNANCE_COMPLIANCE_SCORECARD() INTO v_scorecard;
    CALL ADMIN.GOVERNANCE.RBAC_SCAN_UNPROTECTED_DATA(NULL, NULL) INTO v_unprotected;
    
    -- Determine overall health
    IF (v_unprotected:risk_summary:risk_level = 'CRITICAL') THEN
        v_overall_health := 'CRITICAL';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'CRITICAL',
            'message', 'Critical sensitive data is unprotected',
            'action', 'Apply masking policies immediately'
        ));
    ELSEIF (v_scorecard:overall:status = 'NON_COMPLIANT') THEN
        v_overall_health := 'WARNING';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'WARNING',
            'message', 'Governance compliance score is below threshold',
            'action', 'Review compliance scorecard recommendations'
        ));
    ELSEIF (v_coverage:unprotected_count > 10) THEN
        v_overall_health := 'ATTENTION';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'INFO',
            'message', v_coverage:unprotected_count || ' sensitive columns need protection',
            'action', 'Run RBAC_APPLY_MASKING_TO_CLASSIFIED()'
        ));
    ELSE
        v_overall_health := 'HEALTHY';
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'GOVERNANCE_MONITORING_UNIFIED',
        'generated_at', CURRENT_TIMESTAMP(),
        'overall_health', v_overall_health,
        'alerts', v_alerts,
        'quick_stats', OBJECT_CONSTRUCT(
            'compliance_score', v_scorecard:overall:percentage,
            'compliance_grade', v_scorecard:overall:grade,
            'classified_columns', v_classification:summary:total_classified_columns,
            'columns_with_masking', v_coverage:summary:columns_with_masking,
            'tables_with_rls', v_coverage:summary:tables_with_rls,
            'unprotected_sensitive', v_coverage:unprotected_count,
            'risk_level', v_unprotected:risk_summary:risk_level
        ),
        'coverage', v_coverage,
        'classification', v_classification,
        'compliance_scorecard', v_scorecard,
        'unprotected_scan', v_unprotected
    );
END;
$$;

-- #############################################################################
-- SECTION 8: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_POLICY_COVERAGE_DASHBOARD(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_CLASSIFICATION_STATUS_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_GOVERNANCE_COMPLIANCE_SCORECARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_SENSITIVE_DATA_MAP(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_SCAN_UNPROTECTED_DATA(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_GOVERNANCE_AUDIT_REPORT(DATE, DATE) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_GOVERNANCE_MONITORING_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;

-- Allow DBAdmins to view dashboards
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_POLICY_COVERAGE_DASHBOARD(VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_CLASSIFICATION_STATUS_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_GOVERNANCE_COMPLIANCE_SCORECARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_GOVERNANCE_MONITORING_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
