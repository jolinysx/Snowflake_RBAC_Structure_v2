/*******************************************************************************
 * RBAC STORED PROCEDURE: Data Governance
 * 
 * Purpose: Implement and manage data governance policies including:
 *          - Row-level security (RLS)
 *          - Dynamic data masking
 *          - Data classification and tagging
 *          - Sensitive data protection
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          GOVERNANCE
 *   Object Type:     TABLES (6), PROCEDURES (~15)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN, SRF_*_DBADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and GOVERNANCE schema must exist
 *     - Enterprise edition required for masking policies
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * CAPABILITIES:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Row Access Policies    - Control row visibility based on user context
 *   • Masking Policies       - Obfuscate sensitive data dynamically
 *   • Data Classification    - Tag and classify sensitive columns
 *   • Policy Templates       - Pre-built policies for common use cases
 *   • Bulk Application       - Apply policies across multiple objects
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
-- SECTION 1: GOVERNANCE TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.GOVERNANCE.GOVERNANCE_POLICY_REGISTRY (
    POLICY_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_NAME VARCHAR(255) NOT NULL,
    POLICY_TYPE VARCHAR(50) NOT NULL,
    POLICY_CATEGORY VARCHAR(50),
    DATABASE_NAME VARCHAR(255),
    SCHEMA_NAME VARCHAR(255),
    SIGNATURE VARCHAR(1000),
    RETURN_TYPE VARCHAR(100),
    BODY_HASH VARCHAR(64),
    DESCRIPTION TEXT,
    DATA_CLASSIFICATION VARCHAR(50),
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(255),
    UPDATED_AT TIMESTAMP_NTZ,
    STATUS VARCHAR(20) DEFAULT 'ACTIVE',
    METADATA VARIANT
);

CREATE TABLE IF NOT EXISTS ADMIN.GOVERNANCE.GOVERNANCE_POLICY_APPLICATIONS (
    APPLICATION_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_ID VARCHAR(36) NOT NULL,
    POLICY_NAME VARCHAR(255) NOT NULL,
    POLICY_TYPE VARCHAR(50) NOT NULL,
    TARGET_DATABASE VARCHAR(255) NOT NULL,
    TARGET_SCHEMA VARCHAR(255) NOT NULL,
    TARGET_OBJECT VARCHAR(255) NOT NULL,
    TARGET_COLUMN VARCHAR(255),
    APPLIED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    APPLIED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    STATUS VARCHAR(20) DEFAULT 'ACTIVE',
    FOREIGN KEY (POLICY_ID) REFERENCES GOVERNANCE_POLICY_REGISTRY(POLICY_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.GOVERNANCE.GOVERNANCE_DATA_CLASSIFICATIONS (
    CLASSIFICATION_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    DATABASE_NAME VARCHAR(255) NOT NULL,
    SCHEMA_NAME VARCHAR(255) NOT NULL,
    TABLE_NAME VARCHAR(255) NOT NULL,
    COLUMN_NAME VARCHAR(255) NOT NULL,
    CLASSIFICATION_TAG VARCHAR(50) NOT NULL,
    SENSITIVITY_LEVEL VARCHAR(20) NOT NULL,
    DATA_TYPE_CATEGORY VARCHAR(50),
    DETECTION_METHOD VARCHAR(50),
    CONFIDENCE_SCORE FLOAT,
    REQUIRES_MASKING BOOLEAN DEFAULT FALSE,
    REQUIRES_RLS BOOLEAN DEFAULT FALSE,
    CLASSIFIED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CLASSIFIED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    VERIFIED_BY VARCHAR(255),
    VERIFIED_AT TIMESTAMP_NTZ,
    METADATA VARIANT
);

CREATE TABLE IF NOT EXISTS ADMIN.GOVERNANCE.GOVERNANCE_TAGS (
    TAG_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TAG_DATABASE VARCHAR(255) NOT NULL,
    TAG_SCHEMA VARCHAR(255) NOT NULL,
    TAG_NAME VARCHAR(255) NOT NULL,
    TAG_TYPE VARCHAR(50),
    ALLOWED_VALUES ARRAY,
    DESCRIPTION TEXT,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    STATUS VARCHAR(20) DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS ADMIN.GOVERNANCE.GOVERNANCE_TAG_APPLICATIONS (
    APPLICATION_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TAG_ID VARCHAR(36) NOT NULL,
    TAG_NAME VARCHAR(255) NOT NULL,
    TAG_VALUE VARCHAR(255),
    TARGET_TYPE VARCHAR(50) NOT NULL,
    TARGET_DATABASE VARCHAR(255),
    TARGET_SCHEMA VARCHAR(255),
    TARGET_OBJECT VARCHAR(255),
    TARGET_COLUMN VARCHAR(255),
    APPLIED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    APPLIED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    FOREIGN KEY (TAG_ID) REFERENCES GOVERNANCE_TAGS(TAG_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.GOVERNANCE.GOVERNANCE_AUDIT_LOG (
    AUDIT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    ACTION VARCHAR(50) NOT NULL,
    OBJECT_TYPE VARCHAR(50),
    OBJECT_NAME VARCHAR(500),
    TARGET_DATABASE VARCHAR(255),
    TARGET_SCHEMA VARCHAR(255),
    TARGET_OBJECT VARCHAR(255),
    TARGET_COLUMN VARCHAR(255),
    PERFORMED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    PERFORMED_BY_ROLE VARCHAR(255) DEFAULT CURRENT_ROLE(),
    STATUS VARCHAR(20),
    DETAILS VARIANT,
    ERROR_MESSAGE TEXT
);

-- #############################################################################
-- SECTION 2: ROW ACCESS POLICIES (ROW-LEVEL SECURITY)
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Row Access Policy
 * 
 * Purpose: Creates a row access policy for row-level security
 * 
 * Policy Types:
 *   - ENVIRONMENT_BASED: Filter by user's environment access
 *   - ROLE_BASED: Filter by user's role membership
 *   - ATTRIBUTE_BASED: Filter by user attributes (department, region, etc.)
 *   - CUSTOM: Custom predicate expression
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_CREATE_ROW_ACCESS_POLICY(
    P_POLICY_NAME VARCHAR,
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR,
    P_POLICY_TYPE VARCHAR,
    P_FILTER_COLUMN VARCHAR,
    P_FILTER_EXPRESSION VARCHAR DEFAULT NULL,
    P_DESCRIPTION TEXT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_policy_id VARCHAR;
    v_full_policy_name VARCHAR;
    v_sql VARCHAR;
    v_body VARCHAR;
    v_signature VARCHAR;
BEGIN
    v_policy_id := UUID_STRING();
    v_full_policy_name := P_DATABASE || '.' || P_SCHEMA || '.' || P_POLICY_NAME;
    
    -- Build policy body based on type
    CASE P_POLICY_TYPE
        WHEN 'ENVIRONMENT_BASED' THEN
            v_signature := P_FILTER_COLUMN || ' VARCHAR';
            v_body := '
                CASE 
                    WHEN IS_ROLE_IN_SESSION(''SRS_SYSTEM_ADMIN'') THEN TRUE
                    WHEN IS_ROLE_IN_SESSION(''SRS_SECURITY_ADMIN'') THEN TRUE
                    WHEN ' || P_FILTER_COLUMN || ' = ''DEV'' AND IS_ROLE_IN_SESSION(''SRF_DEV_END_USER'') THEN TRUE
                    WHEN ' || P_FILTER_COLUMN || ' = ''TST'' AND IS_ROLE_IN_SESSION(''SRF_TST_END_USER'') THEN TRUE
                    WHEN ' || P_FILTER_COLUMN || ' = ''UAT'' AND IS_ROLE_IN_SESSION(''SRF_UAT_END_USER'') THEN TRUE
                    WHEN ' || P_FILTER_COLUMN || ' = ''PPE'' AND IS_ROLE_IN_SESSION(''SRF_PPE_END_USER'') THEN TRUE
                    WHEN ' || P_FILTER_COLUMN || ' = ''PRD'' AND IS_ROLE_IN_SESSION(''SRF_PRD_END_USER'') THEN TRUE
                    ELSE FALSE
                END';
        
        WHEN 'ROLE_BASED' THEN
            v_signature := P_FILTER_COLUMN || ' VARCHAR';
            v_body := '
                CASE
                    WHEN IS_ROLE_IN_SESSION(''SRS_SYSTEM_ADMIN'') THEN TRUE
                    WHEN IS_ROLE_IN_SESSION(' || P_FILTER_COLUMN || ') THEN TRUE
                    ELSE FALSE
                END';
        
        WHEN 'ATTRIBUTE_BASED' THEN
            v_signature := P_FILTER_COLUMN || ' VARCHAR';
            v_body := '
                CASE
                    WHEN IS_ROLE_IN_SESSION(''SRS_SYSTEM_ADMIN'') THEN TRUE
                    WHEN ' || P_FILTER_COLUMN || ' = CURRENT_USER() THEN TRUE
                    WHEN ' || P_FILTER_COLUMN || ' IN (
                        SELECT VALUE::VARCHAR 
                        FROM TABLE(FLATTEN(PARSE_JSON(
                            SYSTEM$GET_TAG(''USER_ATTRIBUTES'', CURRENT_USER(), ''USER'')
                        )))
                    ) THEN TRUE
                    ELSE FALSE
                END';
        
        WHEN 'CUSTOM' THEN
            IF (P_FILTER_EXPRESSION IS NULL) THEN
                RETURN OBJECT_CONSTRUCT(
                    'status', 'ERROR',
                    'message', 'CUSTOM policy type requires P_FILTER_EXPRESSION'
                );
            END IF;
            v_signature := P_FILTER_COLUMN || ' VARCHAR';
            v_body := P_FILTER_EXPRESSION;
        
        ELSE
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'message', 'Invalid policy type. Use: ENVIRONMENT_BASED, ROLE_BASED, ATTRIBUTE_BASED, CUSTOM'
            );
    END CASE;
    
    -- Create the row access policy
    v_sql := 'CREATE OR REPLACE ROW ACCESS POLICY ' || v_full_policy_name || 
             ' AS (' || v_signature || ') RETURNS BOOLEAN -> ' || v_body;
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Register the policy
    INSERT INTO GOVERNANCE_POLICY_REGISTRY (
        POLICY_ID, POLICY_NAME, POLICY_TYPE, POLICY_CATEGORY,
        DATABASE_NAME, SCHEMA_NAME, SIGNATURE, RETURN_TYPE,
        DESCRIPTION, STATUS
    ) VALUES (
        v_policy_id, P_POLICY_NAME, 'ROW_ACCESS_POLICY', P_POLICY_TYPE,
        P_DATABASE, P_SCHEMA, v_signature, 'BOOLEAN',
        P_DESCRIPTION, 'ACTIVE'
    );
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, STATUS, DETAILS)
    VALUES ('CREATE', 'ROW_ACCESS_POLICY', P_POLICY_NAME, P_DATABASE, P_SCHEMA, 'SUCCESS',
            OBJECT_CONSTRUCT('policy_type', P_POLICY_TYPE, 'filter_column', P_FILTER_COLUMN));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_id', v_policy_id,
        'policy_name', v_full_policy_name,
        'policy_type', P_POLICY_TYPE,
        'message', 'Row access policy created successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, ERROR_MESSAGE)
        VALUES ('CREATE', 'ROW_ACCESS_POLICY', P_POLICY_NAME, 'FAILED', SQLERRM);
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Apply Row Access Policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_APPLY_ROW_ACCESS_POLICY(
    P_POLICY_DATABASE VARCHAR,
    P_POLICY_SCHEMA VARCHAR,
    P_POLICY_NAME VARCHAR,
    P_TARGET_DATABASE VARCHAR,
    P_TARGET_SCHEMA VARCHAR,
    P_TARGET_TABLE VARCHAR,
    P_TARGET_COLUMN VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_policy_id VARCHAR;
    v_full_policy VARCHAR;
    v_full_table VARCHAR;
BEGIN
    v_full_policy := P_POLICY_DATABASE || '.' || P_POLICY_SCHEMA || '.' || P_POLICY_NAME;
    v_full_table := P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_TABLE;
    
    -- Get policy ID
    SELECT POLICY_ID INTO v_policy_id
    FROM GOVERNANCE_POLICY_REGISTRY
    WHERE POLICY_NAME = P_POLICY_NAME
      AND DATABASE_NAME = P_POLICY_DATABASE
      AND SCHEMA_NAME = P_POLICY_SCHEMA
      AND POLICY_TYPE = 'ROW_ACCESS_POLICY';
    
    -- Apply the policy
    v_sql := 'ALTER TABLE ' || v_full_table || 
             ' ADD ROW ACCESS POLICY ' || v_full_policy || 
             ' ON (' || P_TARGET_COLUMN || ')';
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Record application
    INSERT INTO GOVERNANCE_POLICY_APPLICATIONS (
        POLICY_ID, POLICY_NAME, POLICY_TYPE,
        TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN
    ) VALUES (
        v_policy_id, P_POLICY_NAME, 'ROW_ACCESS_POLICY',
        P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_TABLE, P_TARGET_COLUMN
    );
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN, STATUS)
    VALUES ('APPLY', 'ROW_ACCESS_POLICY', P_POLICY_NAME, P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_TABLE, P_TARGET_COLUMN, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy', v_full_policy,
        'applied_to', v_full_table || '.' || P_TARGET_COLUMN,
        'message', 'Row access policy applied successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, STATUS, ERROR_MESSAGE)
        VALUES ('APPLY', 'ROW_ACCESS_POLICY', P_POLICY_NAME, P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_TABLE, 'FAILED', SQLERRM);
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Remove Row Access Policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_REMOVE_ROW_ACCESS_POLICY(
    P_TARGET_DATABASE VARCHAR,
    P_TARGET_SCHEMA VARCHAR,
    P_TARGET_TABLE VARCHAR,
    P_POLICY_DATABASE VARCHAR,
    P_POLICY_SCHEMA VARCHAR,
    P_POLICY_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_full_policy VARCHAR;
    v_full_table VARCHAR;
BEGIN
    v_full_policy := P_POLICY_DATABASE || '.' || P_POLICY_SCHEMA || '.' || P_POLICY_NAME;
    v_full_table := P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_TABLE;
    
    v_sql := 'ALTER TABLE ' || v_full_table || ' DROP ROW ACCESS POLICY ' || v_full_policy;
    EXECUTE IMMEDIATE v_sql;
    
    -- Update application status
    UPDATE GOVERNANCE_POLICY_APPLICATIONS
    SET STATUS = 'REMOVED'
    WHERE POLICY_NAME = P_POLICY_NAME
      AND TARGET_DATABASE = P_TARGET_DATABASE
      AND TARGET_SCHEMA = P_TARGET_SCHEMA
      AND TARGET_OBJECT = P_TARGET_TABLE;
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, STATUS)
    VALUES ('REMOVE', 'ROW_ACCESS_POLICY', P_POLICY_NAME, P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_TABLE, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy', v_full_policy,
        'removed_from', v_full_table,
        'message', 'Row access policy removed successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 3: MASKING POLICIES (DATA OBFUSCATION)
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Masking Policy
 * 
 * Purpose: Creates a dynamic data masking policy
 * 
 * Masking Types:
 *   - FULL_MASK: Replace with fixed value (e.g., '****')
 *   - PARTIAL_MASK: Show first/last N characters
 *   - EMAIL_MASK: Show domain only (e.g., '***@domain.com')
 *   - PHONE_MASK: Show last 4 digits
 *   - SSN_MASK: Show last 4 digits (XXX-XX-1234)
 *   - CREDIT_CARD_MASK: Show last 4 digits
 *   - NULL_MASK: Return NULL
 *   - HASH_MASK: Return SHA-256 hash
 *   - CUSTOM: Custom masking expression
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
    P_POLICY_NAME VARCHAR,
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR,
    P_DATA_TYPE VARCHAR,
    P_MASKING_TYPE VARCHAR,
    P_UNMASKED_ROLES ARRAY DEFAULT NULL,
    P_PARTIAL_SHOW_FIRST INTEGER DEFAULT 0,
    P_PARTIAL_SHOW_LAST INTEGER DEFAULT 4,
    P_CUSTOM_EXPRESSION VARCHAR DEFAULT NULL,
    P_DESCRIPTION TEXT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_policy_id VARCHAR;
    v_full_policy_name VARCHAR;
    v_sql VARCHAR;
    v_body VARCHAR;
    v_role_check VARCHAR := '';
    v_return_type VARCHAR;
BEGIN
    v_policy_id := UUID_STRING();
    v_full_policy_name := P_DATABASE || '.' || P_SCHEMA || '.' || P_POLICY_NAME;
    v_return_type := P_DATA_TYPE;
    
    -- Build role check for unmasked access
    IF (P_UNMASKED_ROLES IS NOT NULL AND ARRAY_SIZE(P_UNMASKED_ROLES) > 0) THEN
        v_role_check := 'IS_ROLE_IN_SESSION(''SRS_SYSTEM_ADMIN'') OR IS_ROLE_IN_SESSION(''SRS_SECURITY_ADMIN'')';
        FOR i IN 0 TO ARRAY_SIZE(P_UNMASKED_ROLES) - 1 DO
            v_role_check := v_role_check || ' OR IS_ROLE_IN_SESSION(''' || P_UNMASKED_ROLES[i]::VARCHAR || ''')';
        END FOR;
    ELSE
        v_role_check := 'IS_ROLE_IN_SESSION(''SRS_SYSTEM_ADMIN'') OR IS_ROLE_IN_SESSION(''SRS_SECURITY_ADMIN'')';
    END IF;
    
    -- Build masking expression based on type
    CASE P_MASKING_TYPE
        WHEN 'FULL_MASK' THEN
            IF (P_DATA_TYPE IN ('VARCHAR', 'STRING', 'TEXT')) THEN
                v_body := 'CASE WHEN ' || v_role_check || ' THEN val ELSE ''********'' END';
            ELSEIF (P_DATA_TYPE IN ('NUMBER', 'INTEGER', 'FLOAT', 'DECIMAL')) THEN
                v_body := 'CASE WHEN ' || v_role_check || ' THEN val ELSE 0 END';
            ELSE
                v_body := 'CASE WHEN ' || v_role_check || ' THEN val ELSE NULL END';
            END IF;
        
        WHEN 'PARTIAL_MASK' THEN
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ' ||
                      'ELSE CONCAT(LEFT(val, ' || P_PARTIAL_SHOW_FIRST || '), ' ||
                      'REPEAT(''*'', GREATEST(LENGTH(val) - ' || (P_PARTIAL_SHOW_FIRST + P_PARTIAL_SHOW_LAST) || ', 0)), ' ||
                      'RIGHT(val, ' || P_PARTIAL_SHOW_LAST || ')) END';
        
        WHEN 'EMAIL_MASK' THEN
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ' ||
                      'ELSE CONCAT(''***'', SUBSTRING(val, POSITION(''@'' IN val))) END';
        
        WHEN 'PHONE_MASK' THEN
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ' ||
                      'ELSE CONCAT(''***-***-'', RIGHT(REGEXP_REPLACE(val, ''[^0-9]'', ''''), 4)) END';
        
        WHEN 'SSN_MASK' THEN
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ' ||
                      'ELSE CONCAT(''XXX-XX-'', RIGHT(REGEXP_REPLACE(val, ''[^0-9]'', ''''), 4)) END';
        
        WHEN 'CREDIT_CARD_MASK' THEN
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ' ||
                      'ELSE CONCAT(''****-****-****-'', RIGHT(REGEXP_REPLACE(val, ''[^0-9]'', ''''), 4)) END';
        
        WHEN 'NULL_MASK' THEN
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ELSE NULL END';
        
        WHEN 'HASH_MASK' THEN
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ELSE SHA2(val::VARCHAR, 256) END';
            v_return_type := 'VARCHAR';
        
        WHEN 'DATE_MASK' THEN
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ELSE DATE_TRUNC(''YEAR'', val) END';
        
        WHEN 'CUSTOM' THEN
            IF (P_CUSTOM_EXPRESSION IS NULL) THEN
                RETURN OBJECT_CONSTRUCT(
                    'status', 'ERROR',
                    'message', 'CUSTOM masking type requires P_CUSTOM_EXPRESSION'
                );
            END IF;
            v_body := 'CASE WHEN ' || v_role_check || ' THEN val ELSE ' || P_CUSTOM_EXPRESSION || ' END';
        
        ELSE
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'message', 'Invalid masking type. Use: FULL_MASK, PARTIAL_MASK, EMAIL_MASK, PHONE_MASK, SSN_MASK, CREDIT_CARD_MASK, NULL_MASK, HASH_MASK, DATE_MASK, CUSTOM'
            );
    END CASE;
    
    -- Create the masking policy
    v_sql := 'CREATE OR REPLACE MASKING POLICY ' || v_full_policy_name || 
             ' AS (val ' || P_DATA_TYPE || ') RETURNS ' || v_return_type || ' -> ' || v_body;
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Register the policy
    INSERT INTO GOVERNANCE_POLICY_REGISTRY (
        POLICY_ID, POLICY_NAME, POLICY_TYPE, POLICY_CATEGORY,
        DATABASE_NAME, SCHEMA_NAME, SIGNATURE, RETURN_TYPE,
        DESCRIPTION, DATA_CLASSIFICATION, STATUS, METADATA
    ) VALUES (
        v_policy_id, P_POLICY_NAME, 'MASKING_POLICY', P_MASKING_TYPE,
        P_DATABASE, P_SCHEMA, 'val ' || P_DATA_TYPE, v_return_type,
        P_DESCRIPTION, P_MASKING_TYPE, 'ACTIVE',
        OBJECT_CONSTRUCT('unmasked_roles', P_UNMASKED_ROLES, 'data_type', P_DATA_TYPE)
    );
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, STATUS, DETAILS)
    VALUES ('CREATE', 'MASKING_POLICY', P_POLICY_NAME, P_DATABASE, P_SCHEMA, 'SUCCESS',
            OBJECT_CONSTRUCT('masking_type', P_MASKING_TYPE, 'data_type', P_DATA_TYPE));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_id', v_policy_id,
        'policy_name', v_full_policy_name,
        'masking_type', P_MASKING_TYPE,
        'data_type', P_DATA_TYPE,
        'message', 'Masking policy created successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, ERROR_MESSAGE)
        VALUES ('CREATE', 'MASKING_POLICY', P_POLICY_NAME, 'FAILED', SQLERRM);
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Apply Masking Policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_APPLY_MASKING_POLICY(
    P_POLICY_DATABASE VARCHAR,
    P_POLICY_SCHEMA VARCHAR,
    P_POLICY_NAME VARCHAR,
    P_TARGET_DATABASE VARCHAR,
    P_TARGET_SCHEMA VARCHAR,
    P_TARGET_TABLE VARCHAR,
    P_TARGET_COLUMN VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_policy_id VARCHAR;
    v_full_policy VARCHAR;
    v_full_column VARCHAR;
BEGIN
    v_full_policy := P_POLICY_DATABASE || '.' || P_POLICY_SCHEMA || '.' || P_POLICY_NAME;
    v_full_column := P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_TABLE || '.' || P_TARGET_COLUMN;
    
    -- Get policy ID
    SELECT POLICY_ID INTO v_policy_id
    FROM GOVERNANCE_POLICY_REGISTRY
    WHERE POLICY_NAME = P_POLICY_NAME
      AND DATABASE_NAME = P_POLICY_DATABASE
      AND SCHEMA_NAME = P_POLICY_SCHEMA
      AND POLICY_TYPE = 'MASKING_POLICY';
    
    -- Apply the policy
    v_sql := 'ALTER TABLE ' || P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_TABLE ||
             ' MODIFY COLUMN ' || P_TARGET_COLUMN || 
             ' SET MASKING POLICY ' || v_full_policy;
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Record application
    INSERT INTO GOVERNANCE_POLICY_APPLICATIONS (
        POLICY_ID, POLICY_NAME, POLICY_TYPE,
        TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN
    ) VALUES (
        v_policy_id, P_POLICY_NAME, 'MASKING_POLICY',
        P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_TABLE, P_TARGET_COLUMN
    );
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN, STATUS)
    VALUES ('APPLY', 'MASKING_POLICY', P_POLICY_NAME, P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_TABLE, P_TARGET_COLUMN, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy', v_full_policy,
        'applied_to', v_full_column,
        'message', 'Masking policy applied successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN, STATUS, ERROR_MESSAGE)
        VALUES ('APPLY', 'MASKING_POLICY', P_POLICY_NAME, P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_TABLE, P_TARGET_COLUMN, 'FAILED', SQLERRM);
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Remove Masking Policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_REMOVE_MASKING_POLICY(
    P_TARGET_DATABASE VARCHAR,
    P_TARGET_SCHEMA VARCHAR,
    P_TARGET_TABLE VARCHAR,
    P_TARGET_COLUMN VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
BEGIN
    v_sql := 'ALTER TABLE ' || P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_TABLE ||
             ' MODIFY COLUMN ' || P_TARGET_COLUMN || ' UNSET MASKING POLICY';
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Update application status
    UPDATE GOVERNANCE_POLICY_APPLICATIONS
    SET STATUS = 'REMOVED'
    WHERE TARGET_DATABASE = P_TARGET_DATABASE
      AND TARGET_SCHEMA = P_TARGET_SCHEMA
      AND TARGET_OBJECT = P_TARGET_TABLE
      AND TARGET_COLUMN = P_TARGET_COLUMN
      AND POLICY_TYPE = 'MASKING_POLICY';
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN, STATUS)
    VALUES ('REMOVE', 'MASKING_POLICY', P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_TABLE, P_TARGET_COLUMN, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'column', P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_TABLE || '.' || P_TARGET_COLUMN,
        'message', 'Masking policy removed successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Standard Masking Policies
 * 
 * Purpose: Creates a set of pre-built masking policies for common data types
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_SETUP_STANDARD_MASKING_POLICIES(
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_policies_created ARRAY := ARRAY_CONSTRUCT();
    v_result VARIANT;
BEGIN
    -- Email masking
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_EMAIL', P_DATABASE, P_SCHEMA, 'VARCHAR', 'EMAIL_MASK',
        NULL, 0, 0, NULL, 'Standard email masking - shows domain only'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_EMAIL');
    END IF;
    
    -- Phone masking
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_PHONE', P_DATABASE, P_SCHEMA, 'VARCHAR', 'PHONE_MASK',
        NULL, 0, 4, NULL, 'Standard phone masking - shows last 4 digits'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_PHONE');
    END IF;
    
    -- SSN masking
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_SSN', P_DATABASE, P_SCHEMA, 'VARCHAR', 'SSN_MASK',
        NULL, 0, 4, NULL, 'Standard SSN masking - shows last 4 digits'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_SSN');
    END IF;
    
    -- Credit card masking
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_CREDIT_CARD', P_DATABASE, P_SCHEMA, 'VARCHAR', 'CREDIT_CARD_MASK',
        NULL, 0, 4, NULL, 'Standard credit card masking - shows last 4 digits'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_CREDIT_CARD');
    END IF;
    
    -- Full string mask
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_STRING_FULL', P_DATABASE, P_SCHEMA, 'VARCHAR', 'FULL_MASK',
        NULL, 0, 0, NULL, 'Full string masking - replaces with asterisks'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_STRING_FULL');
    END IF;
    
    -- Partial name mask (show first initial)
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_NAME_PARTIAL', P_DATABASE, P_SCHEMA, 'VARCHAR', 'PARTIAL_MASK',
        NULL, 1, 0, NULL, 'Partial name masking - shows first initial only'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_NAME_PARTIAL');
    END IF;
    
    -- Date masking (year only)
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_DATE_YEAR', P_DATABASE, P_SCHEMA, 'DATE', 'DATE_MASK',
        NULL, 0, 0, NULL, 'Date masking - shows year only'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_DATE_YEAR');
    END IF;
    
    -- Number mask (zero)
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_NUMBER_ZERO', P_DATABASE, P_SCHEMA, 'NUMBER', 'FULL_MASK',
        NULL, 0, 0, NULL, 'Number masking - returns zero'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_NUMBER_ZERO');
    END IF;
    
    -- Hash mask for IDs
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(
        'MASK_ID_HASH', P_DATABASE, P_SCHEMA, 'VARCHAR', 'HASH_MASK',
        NULL, 0, 0, NULL, 'ID masking - returns SHA-256 hash for consistent anonymization'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN
        v_policies_created := ARRAY_APPEND(v_policies_created, 'MASK_ID_HASH');
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'database', P_DATABASE,
        'schema', P_SCHEMA,
        'policies_created', v_policies_created,
        'count', ARRAY_SIZE(v_policies_created),
        'message', 'Standard masking policies created'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 4: DATA CLASSIFICATION AND TAGGING
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Governance Tag
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR,
    P_TAG_NAME VARCHAR,
    P_TAG_TYPE VARCHAR DEFAULT 'CLASSIFICATION',
    P_ALLOWED_VALUES ARRAY DEFAULT NULL,
    P_DESCRIPTION TEXT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_tag_id VARCHAR;
    v_sql VARCHAR;
    v_full_tag VARCHAR;
BEGIN
    v_tag_id := UUID_STRING();
    v_full_tag := P_DATABASE || '.' || P_SCHEMA || '.' || P_TAG_NAME;
    
    -- Create the tag
    IF (P_ALLOWED_VALUES IS NOT NULL AND ARRAY_SIZE(P_ALLOWED_VALUES) > 0) THEN
        v_sql := 'CREATE OR REPLACE TAG ' || v_full_tag || 
                 ' ALLOWED_VALUES ' || ARRAY_TO_STRING(P_ALLOWED_VALUES, ', ');
    ELSE
        v_sql := 'CREATE OR REPLACE TAG ' || v_full_tag;
    END IF;
    
    IF (P_DESCRIPTION IS NOT NULL) THEN
        v_sql := v_sql || ' COMMENT = ''' || P_DESCRIPTION || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Register the tag
    INSERT INTO GOVERNANCE_TAGS (
        TAG_ID, TAG_DATABASE, TAG_SCHEMA, TAG_NAME, TAG_TYPE,
        ALLOWED_VALUES, DESCRIPTION
    ) VALUES (
        v_tag_id, P_DATABASE, P_SCHEMA, P_TAG_NAME, P_TAG_TYPE,
        P_ALLOWED_VALUES, P_DESCRIPTION
    );
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, STATUS)
    VALUES ('CREATE', 'TAG', P_TAG_NAME, P_DATABASE, P_SCHEMA, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'tag_id', v_tag_id,
        'tag_name', v_full_tag,
        'tag_type', P_TAG_TYPE,
        'allowed_values', P_ALLOWED_VALUES,
        'message', 'Tag created successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Standard Governance Tags
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_SETUP_STANDARD_GOVERNANCE_TAGS(
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_tags_created ARRAY := ARRAY_CONSTRUCT();
    v_result VARIANT;
BEGIN
    -- Data Classification tag
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
        P_DATABASE, P_SCHEMA, 'DATA_CLASSIFICATION', 'CLASSIFICATION',
        ARRAY_CONSTRUCT('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET'),
        'Data classification level'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN v_tags_created := ARRAY_APPEND(v_tags_created, 'DATA_CLASSIFICATION'); END IF;
    
    -- PII tag
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
        P_DATABASE, P_SCHEMA, 'PII', 'SENSITIVITY',
        ARRAY_CONSTRUCT('YES', 'NO'),
        'Contains Personally Identifiable Information'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN v_tags_created := ARRAY_APPEND(v_tags_created, 'PII'); END IF;
    
    -- PHI tag
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
        P_DATABASE, P_SCHEMA, 'PHI', 'SENSITIVITY',
        ARRAY_CONSTRUCT('YES', 'NO'),
        'Contains Protected Health Information'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN v_tags_created := ARRAY_APPEND(v_tags_created, 'PHI'); END IF;
    
    -- PCI tag
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
        P_DATABASE, P_SCHEMA, 'PCI', 'SENSITIVITY',
        ARRAY_CONSTRUCT('YES', 'NO'),
        'Contains Payment Card Industry data'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN v_tags_created := ARRAY_APPEND(v_tags_created, 'PCI'); END IF;
    
    -- Data Type tag
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
        P_DATABASE, P_SCHEMA, 'DATA_TYPE', 'CLASSIFICATION',
        ARRAY_CONSTRUCT('EMAIL', 'PHONE', 'SSN', 'ADDRESS', 'NAME', 'DOB', 'FINANCIAL', 'MEDICAL', 'CREDENTIAL', 'OTHER'),
        'Type of sensitive data'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN v_tags_created := ARRAY_APPEND(v_tags_created, 'DATA_TYPE'); END IF;
    
    -- Retention tag
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
        P_DATABASE, P_SCHEMA, 'RETENTION_PERIOD', 'GOVERNANCE',
        ARRAY_CONSTRUCT('30_DAYS', '90_DAYS', '1_YEAR', '3_YEARS', '7_YEARS', 'INDEFINITE'),
        'Data retention period requirement'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN v_tags_created := ARRAY_APPEND(v_tags_created, 'RETENTION_PERIOD'); END IF;
    
    -- Data Owner tag
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
        P_DATABASE, P_SCHEMA, 'DATA_OWNER', 'OWNERSHIP',
        NULL,
        'Data owner department or team'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN v_tags_created := ARRAY_APPEND(v_tags_created, 'DATA_OWNER'); END IF;
    
    -- Masking Required tag
    CALL ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(
        P_DATABASE, P_SCHEMA, 'MASKING_REQUIRED', 'GOVERNANCE',
        ARRAY_CONSTRUCT('YES', 'NO'),
        'Whether masking is required for this data'
    ) INTO v_result;
    IF (v_result:status = 'SUCCESS') THEN v_tags_created := ARRAY_APPEND(v_tags_created, 'MASKING_REQUIRED'); END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'database', P_DATABASE,
        'schema', P_SCHEMA,
        'tags_created', v_tags_created,
        'count', ARRAY_SIZE(v_tags_created),
        'message', 'Standard governance tags created'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Apply Tag to Object
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_APPLY_TAG(
    P_TAG_DATABASE VARCHAR,
    P_TAG_SCHEMA VARCHAR,
    P_TAG_NAME VARCHAR,
    P_TAG_VALUE VARCHAR,
    P_TARGET_TYPE VARCHAR,
    P_TARGET_DATABASE VARCHAR,
    P_TARGET_SCHEMA VARCHAR DEFAULT NULL,
    P_TARGET_OBJECT VARCHAR DEFAULT NULL,
    P_TARGET_COLUMN VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_full_tag VARCHAR;
    v_target VARCHAR;
    v_tag_id VARCHAR;
BEGIN
    v_full_tag := P_TAG_DATABASE || '.' || P_TAG_SCHEMA || '.' || P_TAG_NAME;
    
    -- Get tag ID
    SELECT TAG_ID INTO v_tag_id
    FROM GOVERNANCE_TAGS
    WHERE TAG_DATABASE = P_TAG_DATABASE
      AND TAG_SCHEMA = P_TAG_SCHEMA
      AND TAG_NAME = P_TAG_NAME;
    
    -- Build target and SQL based on target type
    CASE UPPER(P_TARGET_TYPE)
        WHEN 'DATABASE' THEN
            v_target := P_TARGET_DATABASE;
            v_sql := 'ALTER DATABASE ' || P_TARGET_DATABASE || ' SET TAG ' || v_full_tag || ' = ''' || P_TAG_VALUE || '''';
        
        WHEN 'SCHEMA' THEN
            v_target := P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA;
            v_sql := 'ALTER SCHEMA ' || v_target || ' SET TAG ' || v_full_tag || ' = ''' || P_TAG_VALUE || '''';
        
        WHEN 'TABLE' THEN
            v_target := P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_OBJECT;
            v_sql := 'ALTER TABLE ' || v_target || ' SET TAG ' || v_full_tag || ' = ''' || P_TAG_VALUE || '''';
        
        WHEN 'VIEW' THEN
            v_target := P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_OBJECT;
            v_sql := 'ALTER VIEW ' || v_target || ' SET TAG ' || v_full_tag || ' = ''' || P_TAG_VALUE || '''';
        
        WHEN 'COLUMN' THEN
            v_target := P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_OBJECT || '.' || P_TARGET_COLUMN;
            v_sql := 'ALTER TABLE ' || P_TARGET_DATABASE || '.' || P_TARGET_SCHEMA || '.' || P_TARGET_OBJECT ||
                     ' MODIFY COLUMN ' || P_TARGET_COLUMN || ' SET TAG ' || v_full_tag || ' = ''' || P_TAG_VALUE || '''';
        
        ELSE
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'message', 'Invalid target type. Use: DATABASE, SCHEMA, TABLE, VIEW, COLUMN'
            );
    END CASE;
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Record application
    INSERT INTO GOVERNANCE_TAG_APPLICATIONS (
        TAG_ID, TAG_NAME, TAG_VALUE, TARGET_TYPE,
        TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN
    ) VALUES (
        v_tag_id, P_TAG_NAME, P_TAG_VALUE, P_TARGET_TYPE,
        P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_OBJECT, P_TARGET_COLUMN
    );
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN, STATUS, DETAILS)
    VALUES ('APPLY', 'TAG', P_TAG_NAME, P_TARGET_DATABASE, P_TARGET_SCHEMA, P_TARGET_OBJECT, P_TARGET_COLUMN, 'SUCCESS',
            OBJECT_CONSTRUCT('tag_value', P_TAG_VALUE, 'target_type', P_TARGET_TYPE));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'tag', v_full_tag,
        'value', P_TAG_VALUE,
        'applied_to', v_target,
        'target_type', P_TARGET_TYPE,
        'message', 'Tag applied successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Classify Column
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_CLASSIFY_COLUMN(
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR,
    P_TABLE VARCHAR,
    P_COLUMN VARCHAR,
    P_CLASSIFICATION_TAG VARCHAR,
    P_SENSITIVITY_LEVEL VARCHAR,
    P_DATA_TYPE_CATEGORY VARCHAR DEFAULT NULL,
    P_REQUIRES_MASKING BOOLEAN DEFAULT FALSE,
    P_REQUIRES_RLS BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_classification_id VARCHAR;
BEGIN
    v_classification_id := UUID_STRING();
    
    -- Insert or update classification
    MERGE INTO GOVERNANCE_DATA_CLASSIFICATIONS t
    USING (SELECT 
        P_DATABASE AS DATABASE_NAME,
        P_SCHEMA AS SCHEMA_NAME,
        P_TABLE AS TABLE_NAME,
        P_COLUMN AS COLUMN_NAME
    ) s
    ON t.DATABASE_NAME = s.DATABASE_NAME
       AND t.SCHEMA_NAME = s.SCHEMA_NAME
       AND t.TABLE_NAME = s.TABLE_NAME
       AND t.COLUMN_NAME = s.COLUMN_NAME
    WHEN MATCHED THEN UPDATE SET
        CLASSIFICATION_TAG = P_CLASSIFICATION_TAG,
        SENSITIVITY_LEVEL = P_SENSITIVITY_LEVEL,
        DATA_TYPE_CATEGORY = P_DATA_TYPE_CATEGORY,
        REQUIRES_MASKING = P_REQUIRES_MASKING,
        REQUIRES_RLS = P_REQUIRES_RLS,
        CLASSIFIED_BY = CURRENT_USER(),
        CLASSIFIED_AT = CURRENT_TIMESTAMP()
    WHEN NOT MATCHED THEN INSERT (
        CLASSIFICATION_ID, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME,
        CLASSIFICATION_TAG, SENSITIVITY_LEVEL, DATA_TYPE_CATEGORY,
        DETECTION_METHOD, REQUIRES_MASKING, REQUIRES_RLS
    ) VALUES (
        v_classification_id, P_DATABASE, P_SCHEMA, P_TABLE, P_COLUMN,
        P_CLASSIFICATION_TAG, P_SENSITIVITY_LEVEL, P_DATA_TYPE_CATEGORY,
        'MANUAL', P_REQUIRES_MASKING, P_REQUIRES_RLS
    );
    
    -- Audit log
    INSERT INTO GOVERNANCE_AUDIT_LOG (ACTION, OBJECT_TYPE, TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN, STATUS, DETAILS)
    VALUES ('CLASSIFY', 'COLUMN', P_DATABASE, P_SCHEMA, P_TABLE, P_COLUMN, 'SUCCESS',
            OBJECT_CONSTRUCT('classification', P_CLASSIFICATION_TAG, 'sensitivity', P_SENSITIVITY_LEVEL));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'column', P_DATABASE || '.' || P_SCHEMA || '.' || P_TABLE || '.' || P_COLUMN,
        'classification', P_CLASSIFICATION_TAG,
        'sensitivity', P_SENSITIVITY_LEVEL,
        'requires_masking', P_REQUIRES_MASKING,
        'requires_rls', P_REQUIRES_RLS,
        'message', 'Column classified successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Auto-Classify Table (Pattern-Based)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_AUTO_CLASSIFY_TABLE(
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR,
    P_TABLE VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_columns_classified INTEGER := 0;
    v_classifications ARRAY := ARRAY_CONSTRUCT();
    v_result VARIANT;
    v_col_upper VARCHAR;
    v_classification VARCHAR;
    v_sensitivity VARCHAR;
    v_data_type VARCHAR;
    v_needs_masking BOOLEAN;
BEGIN
    -- Classify columns based on name patterns
    FOR col_rec IN (
        SELECT COLUMN_NAME, DATA_TYPE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_CATALOG = P_DATABASE
          AND TABLE_SCHEMA = P_SCHEMA
          AND TABLE_NAME = P_TABLE
    ) DO
        v_col_upper := UPPER(col_rec.COLUMN_NAME);
        v_classification := NULL;
        v_sensitivity := 'LOW';
        v_data_type := NULL;
        v_needs_masking := FALSE;
        
        -- Email patterns
        IF (v_col_upper LIKE '%EMAIL%' OR v_col_upper LIKE '%E_MAIL%') THEN
            v_classification := 'PII';
            v_sensitivity := 'HIGH';
            v_data_type := 'EMAIL';
            v_needs_masking := TRUE;
        
        -- Phone patterns
        ELSEIF (v_col_upper LIKE '%PHONE%' OR v_col_upper LIKE '%MOBILE%' OR v_col_upper LIKE '%TEL%' OR v_col_upper LIKE '%FAX%') THEN
            v_classification := 'PII';
            v_sensitivity := 'HIGH';
            v_data_type := 'PHONE';
            v_needs_masking := TRUE;
        
        -- SSN patterns
        ELSEIF (v_col_upper LIKE '%SSN%' OR v_col_upper LIKE '%SOCIAL_SEC%' OR v_col_upper LIKE '%TAX_ID%' OR v_col_upper LIKE '%TIN%') THEN
            v_classification := 'PII';
            v_sensitivity := 'CRITICAL';
            v_data_type := 'SSN';
            v_needs_masking := TRUE;
        
        -- Name patterns
        ELSEIF (v_col_upper LIKE '%FIRST_NAME%' OR v_col_upper LIKE '%LAST_NAME%' OR v_col_upper LIKE '%FULL_NAME%' 
               OR v_col_upper LIKE '%FIRSTNAME%' OR v_col_upper LIKE '%LASTNAME%') THEN
            v_classification := 'PII';
            v_sensitivity := 'MEDIUM';
            v_data_type := 'NAME';
            v_needs_masking := TRUE;
        
        -- Address patterns
        ELSEIF (v_col_upper LIKE '%ADDRESS%' OR v_col_upper LIKE '%STREET%' OR v_col_upper LIKE '%CITY%' 
               OR v_col_upper LIKE '%ZIP%' OR v_col_upper LIKE '%POSTAL%') THEN
            v_classification := 'PII';
            v_sensitivity := 'MEDIUM';
            v_data_type := 'ADDRESS';
            v_needs_masking := TRUE;
        
        -- Date of birth patterns
        ELSEIF (v_col_upper LIKE '%DOB%' OR v_col_upper LIKE '%BIRTH%' OR v_col_upper LIKE '%BIRTHDAY%') THEN
            v_classification := 'PII';
            v_sensitivity := 'HIGH';
            v_data_type := 'DOB';
            v_needs_masking := TRUE;
        
        -- Credit card patterns
        ELSEIF (v_col_upper LIKE '%CREDIT%CARD%' OR v_col_upper LIKE '%CC_NUM%' OR v_col_upper LIKE '%CARD_NUM%') THEN
            v_classification := 'PCI';
            v_sensitivity := 'CRITICAL';
            v_data_type := 'FINANCIAL';
            v_needs_masking := TRUE;
        
        -- Account/routing patterns
        ELSEIF (v_col_upper LIKE '%ACCOUNT%NUM%' OR v_col_upper LIKE '%ROUTING%' OR v_col_upper LIKE '%BANK%') THEN
            v_classification := 'PCI';
            v_sensitivity := 'HIGH';
            v_data_type := 'FINANCIAL';
            v_needs_masking := TRUE;
        
        -- Salary/compensation patterns
        ELSEIF (v_col_upper LIKE '%SALARY%' OR v_col_upper LIKE '%WAGE%' OR v_col_upper LIKE '%COMPENSATION%' OR v_col_upper LIKE '%INCOME%') THEN
            v_classification := 'CONFIDENTIAL';
            v_sensitivity := 'HIGH';
            v_data_type := 'FINANCIAL';
            v_needs_masking := TRUE;
        
        -- Password/credential patterns
        ELSEIF (v_col_upper LIKE '%PASSWORD%' OR v_col_upper LIKE '%PWD%' OR v_col_upper LIKE '%SECRET%' OR v_col_upper LIKE '%TOKEN%') THEN
            v_classification := 'RESTRICTED';
            v_sensitivity := 'CRITICAL';
            v_data_type := 'CREDENTIAL';
            v_needs_masking := TRUE;
        
        -- Medical patterns
        ELSEIF (v_col_upper LIKE '%DIAGNOSIS%' OR v_col_upper LIKE '%MEDICAL%' OR v_col_upper LIKE '%HEALTH%' 
               OR v_col_upper LIKE '%PATIENT%' OR v_col_upper LIKE '%PRESCRIPTION%') THEN
            v_classification := 'PHI';
            v_sensitivity := 'CRITICAL';
            v_data_type := 'MEDICAL';
            v_needs_masking := TRUE;
        END IF;
        
        -- If classification found, apply it
        IF (v_classification IS NOT NULL) THEN
            CALL ADMIN.GOVERNANCE.RBAC_CLASSIFY_COLUMN(
                P_DATABASE, P_SCHEMA, P_TABLE, col_rec.COLUMN_NAME,
                v_classification, v_sensitivity, v_data_type, v_needs_masking, FALSE
            ) INTO v_result;
            
            IF (v_result:status = 'SUCCESS') THEN
                v_columns_classified := v_columns_classified + 1;
                v_classifications := ARRAY_APPEND(v_classifications, OBJECT_CONSTRUCT(
                    'column', col_rec.COLUMN_NAME,
                    'classification', v_classification,
                    'sensitivity', v_sensitivity,
                    'data_type', v_data_type
                ));
            END IF;
        END IF;
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'table', P_DATABASE || '.' || P_SCHEMA || '.' || P_TABLE,
        'columns_classified', v_columns_classified,
        'classifications', v_classifications,
        'message', 'Auto-classification complete'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 5: BULK OPERATIONS
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Apply Masking to Classified Columns
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_APPLY_MASKING_TO_CLASSIFIED(
    P_POLICY_DATABASE VARCHAR,
    P_POLICY_SCHEMA VARCHAR,
    P_TARGET_DATABASE VARCHAR DEFAULT NULL,
    P_TARGET_SCHEMA VARCHAR DEFAULT NULL,
    P_DRY_RUN BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_applied INTEGER := 0;
    v_skipped INTEGER := 0;
    v_applications ARRAY := ARRAY_CONSTRUCT();
    v_result VARIANT;
    v_policy_name VARCHAR;
BEGIN
    FOR class_rec IN (
        SELECT 
            DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME,
            DATA_TYPE_CATEGORY, SENSITIVITY_LEVEL
        FROM GOVERNANCE_DATA_CLASSIFICATIONS
        WHERE REQUIRES_MASKING = TRUE
          AND (P_TARGET_DATABASE IS NULL OR DATABASE_NAME = P_TARGET_DATABASE)
          AND (P_TARGET_SCHEMA IS NULL OR SCHEMA_NAME = P_TARGET_SCHEMA)
    ) DO
        v_policy_name := NULL;
        
        -- Map data type to policy
        CASE class_rec.DATA_TYPE_CATEGORY
            WHEN 'EMAIL' THEN v_policy_name := 'MASK_EMAIL';
            WHEN 'PHONE' THEN v_policy_name := 'MASK_PHONE';
            WHEN 'SSN' THEN v_policy_name := 'MASK_SSN';
            WHEN 'NAME' THEN v_policy_name := 'MASK_NAME_PARTIAL';
            WHEN 'FINANCIAL' THEN v_policy_name := 'MASK_STRING_FULL';
            WHEN 'DOB' THEN v_policy_name := 'MASK_DATE_YEAR';
            WHEN 'CREDENTIAL' THEN v_policy_name := 'MASK_STRING_FULL';
            WHEN 'MEDICAL' THEN v_policy_name := 'MASK_STRING_FULL';
            ELSE v_policy_name := 'MASK_STRING_FULL';
        END CASE;
        
        IF (NOT P_DRY_RUN AND v_policy_name IS NOT NULL) THEN
            CALL ADMIN.GOVERNANCE.RBAC_APPLY_MASKING_POLICY(
                P_POLICY_DATABASE, P_POLICY_SCHEMA, v_policy_name,
                class_rec.DATABASE_NAME, class_rec.SCHEMA_NAME, 
                class_rec.TABLE_NAME, class_rec.COLUMN_NAME
            ) INTO v_result;
            
            IF (v_result:status = 'SUCCESS') THEN
                v_applied := v_applied + 1;
            ELSE
                v_skipped := v_skipped + 1;
            END IF;
        ELSE
            v_applied := v_applied + 1;
        END IF;
        
        v_applications := ARRAY_APPEND(v_applications, OBJECT_CONSTRUCT(
            'column', class_rec.DATABASE_NAME || '.' || class_rec.SCHEMA_NAME || '.' || class_rec.TABLE_NAME || '.' || class_rec.COLUMN_NAME,
            'policy', v_policy_name,
            'data_type', class_rec.DATA_TYPE_CATEGORY
        ));
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'EXECUTED'),
        'policies_applied', v_applied,
        'skipped', v_skipped,
        'applications', v_applications,
        'message', IFF(P_DRY_RUN, 'Dry run complete. Set P_DRY_RUN=FALSE to apply.', 'Masking policies applied to classified columns')
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 6: LISTING AND REPORTING
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Policies
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_GOVERNANCE_POLICIES(
    P_POLICY_TYPE VARCHAR DEFAULT NULL,
    P_DATABASE VARCHAR DEFAULT NULL,
    P_STATUS VARCHAR DEFAULT 'ACTIVE'
)
RETURNS TABLE (
    POLICY_ID VARCHAR,
    POLICY_NAME VARCHAR,
    POLICY_TYPE VARCHAR,
    POLICY_CATEGORY VARCHAR,
    DATABASE_NAME VARCHAR,
    SCHEMA_NAME VARCHAR,
    DESCRIPTION TEXT,
    CREATED_AT TIMESTAMP_NTZ,
    STATUS VARCHAR
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT 
            POLICY_ID, POLICY_NAME, POLICY_TYPE, POLICY_CATEGORY,
            DATABASE_NAME, SCHEMA_NAME, DESCRIPTION, CREATED_AT, STATUS
        FROM GOVERNANCE_POLICY_REGISTRY
        WHERE (P_POLICY_TYPE IS NULL OR POLICY_TYPE = P_POLICY_TYPE)
          AND (P_DATABASE IS NULL OR DATABASE_NAME = P_DATABASE)
          AND (P_STATUS IS NULL OR STATUS = P_STATUS)
        ORDER BY POLICY_TYPE, POLICY_NAME
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Policy Applications
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_POLICY_APPLICATIONS(
    P_POLICY_TYPE VARCHAR DEFAULT NULL,
    P_TARGET_DATABASE VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    APPLICATION_ID VARCHAR,
    POLICY_NAME VARCHAR,
    POLICY_TYPE VARCHAR,
    TARGET_DATABASE VARCHAR,
    TARGET_SCHEMA VARCHAR,
    TARGET_OBJECT VARCHAR,
    TARGET_COLUMN VARCHAR,
    APPLIED_BY VARCHAR,
    APPLIED_AT TIMESTAMP_NTZ,
    STATUS VARCHAR
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT 
            APPLICATION_ID, POLICY_NAME, POLICY_TYPE,
            TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT, TARGET_COLUMN,
            APPLIED_BY, APPLIED_AT, STATUS
        FROM GOVERNANCE_POLICY_APPLICATIONS
        WHERE (P_POLICY_TYPE IS NULL OR POLICY_TYPE = P_POLICY_TYPE)
          AND (P_TARGET_DATABASE IS NULL OR TARGET_DATABASE = P_TARGET_DATABASE)
          AND STATUS = 'ACTIVE'
        ORDER BY TARGET_DATABASE, TARGET_SCHEMA, TARGET_OBJECT
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Data Classifications
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_DATA_CLASSIFICATIONS(
    P_DATABASE VARCHAR DEFAULT NULL,
    P_SCHEMA VARCHAR DEFAULT NULL,
    P_SENSITIVITY_LEVEL VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    DATABASE_NAME VARCHAR,
    SCHEMA_NAME VARCHAR,
    TABLE_NAME VARCHAR,
    COLUMN_NAME VARCHAR,
    CLASSIFICATION_TAG VARCHAR,
    SENSITIVITY_LEVEL VARCHAR,
    DATA_TYPE_CATEGORY VARCHAR,
    REQUIRES_MASKING BOOLEAN,
    REQUIRES_RLS BOOLEAN,
    CLASSIFIED_BY VARCHAR,
    CLASSIFIED_AT TIMESTAMP_NTZ
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT 
            DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME,
            CLASSIFICATION_TAG, SENSITIVITY_LEVEL, DATA_TYPE_CATEGORY,
            REQUIRES_MASKING, REQUIRES_RLS, CLASSIFIED_BY, CLASSIFIED_AT
        FROM GOVERNANCE_DATA_CLASSIFICATIONS
        WHERE (P_DATABASE IS NULL OR DATABASE_NAME = P_DATABASE)
          AND (P_SCHEMA IS NULL OR SCHEMA_NAME = P_SCHEMA)
          AND (P_SENSITIVITY_LEVEL IS NULL OR SENSITIVITY_LEVEL = P_SENSITIVITY_LEVEL)
        ORDER BY DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, COLUMN_NAME
    );
    RETURN TABLE(res);
END;
$$;

-- #############################################################################
-- SECTION 7: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_CREATE_ROW_ACCESS_POLICY(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_APPLY_ROW_ACCESS_POLICY(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_REMOVE_ROW_ACCESS_POLICY(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_CREATE_MASKING_POLICY(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, ARRAY, INTEGER, INTEGER, VARCHAR, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_APPLY_MASKING_POLICY(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_REMOVE_MASKING_POLICY(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_SETUP_STANDARD_MASKING_POLICIES(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_CREATE_GOVERNANCE_TAG(VARCHAR, VARCHAR, VARCHAR, VARCHAR, ARRAY, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_SETUP_STANDARD_GOVERNANCE_TAGS(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_APPLY_TAG(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_CLASSIFY_COLUMN(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, BOOLEAN, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_AUTO_CLASSIFY_TABLE(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_APPLY_MASKING_TO_CLASSIFIED(VARCHAR, VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;

GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_GOVERNANCE_POLICIES(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_POLICY_APPLICATIONS(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_DATA_CLASSIFICATIONS(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- DBAdmins can view and apply (but not create) policies
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_GOVERNANCE_POLICIES(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_POLICY_APPLICATIONS(VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.GOVERNANCE.RBAC_LIST_DATA_CLASSIFICATIONS(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
