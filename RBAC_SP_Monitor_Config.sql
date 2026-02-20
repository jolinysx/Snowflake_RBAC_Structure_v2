/*******************************************************************************
 * RBAC STORED PROCEDURE: Monitor RBAC Configuration
 * 
 * Purpose: Monitors and validates RBAC configuration against expected state
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     PROCEDURES
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the procedures)
 *   Execution Role:  SRS_SECURITY_ADMIN (caller must have this role)
 * 
 *   Dependencies:    
 *     - ADMIN database and RBAC schema must exist
 *     - SNOWFLAKE.ACCOUNT_USAGE access required
 * 
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Monitor RBAC Configuration
 * 
 * Purpose: Validates current RBAC security configuration against the standard
 *          configuration for a given environment and schema
 * 
 * Checks:
 *   - Database and schema existence
 *   - Managed access configuration
 *   - Database role existence (SRD_*)
 *   - Object ownership compliance
 *   - Future grants configuration
 *   - Access role linkage (SRA_* to SRD_*)
 * 
 * Parameters:
 *   P_ENVIRONMENT     - Environment code: DEV, TST, UAT, PPE, PRD
 *   P_DATABASE_NAME   - Name of the database (without environment suffix)
 *   P_SCHEMA_NAME     - Name of the schema to check (optional, NULL = all schemas)
 * 
 * Returns: VARIANT containing compliance status and detailed findings
 * 
 * Execution Role: SRF_<ENV>_DBADMIN or SRS_SECURITY_ADMIN
 * 
 * Usage Examples:
 *   CALL RBAC_MONITOR_CONFIG('DEV', 'HR', NULL);          -- Check all schemas
 *   CALL RBAC_MONITOR_CONFIG('PRD', 'SALES', 'ORDERS');   -- Check specific schema
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_MONITOR_CONFIG(
    P_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_full_db_name VARCHAR;
    v_dbadmin_role VARCHAR;
    v_developer_role VARCHAR;
    v_end_user_role VARCHAR;
    v_devops_role VARCHAR := 'SRS_DEVOPS';
    v_is_dev BOOLEAN;
    v_object_owner_role VARCHAR;
    v_findings ARRAY := ARRAY_CONSTRUCT();
    v_schemas ARRAY := ARRAY_CONSTRUCT();
    v_schema_name VARCHAR;
    v_read_db_role VARCHAR;
    v_write_db_role VARCHAR;
    v_compliant BOOLEAN := TRUE;
    v_schema_count INTEGER := 0;
    v_issue_count INTEGER := 0;
    
    -- Cursors
    c_schemas CURSOR FOR
        SELECT SCHEMA_NAME 
        FROM INFORMATION_SCHEMA.SCHEMATA 
        WHERE CATALOG_NAME = v_full_db_name
          AND SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA', 'PUBLIC')
          AND (P_SCHEMA_NAME IS NULL OR SCHEMA_NAME = P_SCHEMA_NAME);
BEGIN
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    -- Derive names
    v_full_db_name := P_DATABASE_NAME || '_' || P_ENVIRONMENT;
    v_dbadmin_role := 'SRF_' || P_ENVIRONMENT || '_DBADMIN';
    v_developer_role := 'SRF_' || P_ENVIRONMENT || '_DEVELOPER';
    v_end_user_role := 'SRF_' || P_ENVIRONMENT || '_END_USER';
    v_is_dev := (P_ENVIRONMENT = 'DEV');
    v_object_owner_role := IFF(v_is_dev, v_developer_role, v_devops_role);
    
    -- =========================================================================
    -- CHECK 1: Verify Database Exists
    -- =========================================================================
    LET v_db_exists BOOLEAN := (
        SELECT COUNT(*) > 0 
        FROM INFORMATION_SCHEMA.DATABASES 
        WHERE DATABASE_NAME = :v_full_db_name
    );
    
    IF (NOT v_db_exists) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Database does not exist',
            'database', v_full_db_name
        );
    END IF;
    
    EXECUTE IMMEDIATE 'USE DATABASE ' || v_full_db_name;
    
    -- =========================================================================
    -- CHECK 2: Iterate through schemas
    -- =========================================================================
    OPEN c_schemas;
    
    FOR record IN c_schemas DO
        v_schema_name := record.SCHEMA_NAME;
        v_schema_count := v_schema_count + 1;
        v_read_db_role := 'SRD_' || v_full_db_name || '_' || v_schema_name || '_READ';
        v_write_db_role := 'SRD_' || v_full_db_name || '_' || v_schema_name || '_WRITE';
        
        LET v_schema_findings ARRAY := ARRAY_CONSTRUCT();
        LET v_schema_compliant BOOLEAN := TRUE;
        
        -- ---------------------------------------------------------------------
        -- CHECK 2.1: Schema is MANAGED ACCESS
        -- ---------------------------------------------------------------------
        LET v_is_managed BOOLEAN := (
            SELECT IS_MANAGED_ACCESS = 'YES'
            FROM INFORMATION_SCHEMA.SCHEMATA
            WHERE CATALOG_NAME = :v_full_db_name AND SCHEMA_NAME = :v_schema_name
        );
        
        IF (NOT v_is_managed) THEN
            v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                'check', 'MANAGED_ACCESS',
                'status', 'FAIL',
                'expected', TRUE,
                'actual', FALSE,
                'message', 'Schema is not configured with MANAGED ACCESS'
            ));
            v_schema_compliant := FALSE;
            v_issue_count := v_issue_count + 1;
        ELSE
            v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                'check', 'MANAGED_ACCESS',
                'status', 'PASS'
            ));
        END IF;
        
        -- ---------------------------------------------------------------------
        -- CHECK 2.2: READ Database Role Exists
        -- ---------------------------------------------------------------------
        LET v_read_role_exists BOOLEAN := (
            SELECT COUNT(*) > 0
            FROM INFORMATION_SCHEMA.DATABASE_ROLES
            WHERE NAME = :v_read_db_role
        );
        
        IF (NOT v_read_role_exists) THEN
            v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                'check', 'READ_DATABASE_ROLE',
                'status', 'FAIL',
                'expected_role', v_read_db_role,
                'message', 'READ database role does not exist'
            ));
            v_schema_compliant := FALSE;
            v_issue_count := v_issue_count + 1;
        ELSE
            v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                'check', 'READ_DATABASE_ROLE',
                'status', 'PASS',
                'role', v_read_db_role
            ));
        END IF;
        
        -- ---------------------------------------------------------------------
        -- CHECK 2.3: WRITE Database Role Exists (DEV only)
        -- ---------------------------------------------------------------------
        IF (v_is_dev) THEN
            LET v_write_role_exists BOOLEAN := (
                SELECT COUNT(*) > 0
                FROM INFORMATION_SCHEMA.DATABASE_ROLES
                WHERE NAME = :v_write_db_role
            );
            
            IF (NOT v_write_role_exists) THEN
                v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                    'check', 'WRITE_DATABASE_ROLE',
                    'status', 'FAIL',
                    'expected_role', v_write_db_role,
                    'message', 'WRITE database role does not exist (required for DEV)'
                ));
                v_schema_compliant := FALSE;
                v_issue_count := v_issue_count + 1;
            ELSE
                v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                    'check', 'WRITE_DATABASE_ROLE',
                    'status', 'PASS',
                    'role', v_write_db_role
                ));
            END IF;
        ELSE
            -- Non-DEV: WRITE role should NOT exist for functional users
            LET v_write_role_exists_non_dev BOOLEAN := (
                SELECT COUNT(*) > 0
                FROM INFORMATION_SCHEMA.DATABASE_ROLES
                WHERE NAME = :v_write_db_role
            );
            
            IF (v_write_role_exists_non_dev) THEN
                v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                    'check', 'WRITE_DATABASE_ROLE',
                    'status', 'WARNING',
                    'role', v_write_db_role,
                    'message', 'WRITE database role exists in non-DEV environment (may be intentional for DBADMIN)'
                ));
            ELSE
                v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                    'check', 'WRITE_DATABASE_ROLE',
                    'status', 'PASS',
                    'message', 'No WRITE database role (correct for non-DEV)'
                ));
            END IF;
        END IF;
        
        -- ---------------------------------------------------------------------
        -- CHECK 2.4: Object Ownership Compliance
        -- ---------------------------------------------------------------------
        LET v_incorrect_owners ARRAY := (
            SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
                'object_type', TABLE_TYPE,
                'object_name', TABLE_NAME,
                'current_owner', TABLE_OWNER,
                'expected_owner', :v_object_owner_role
            ))
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = :v_schema_name
              AND TABLE_OWNER != :v_object_owner_role
              AND TABLE_TYPE IN ('BASE TABLE', 'VIEW', 'MATERIALIZED VIEW')
        );
        
        IF (ARRAY_SIZE(v_incorrect_owners) > 0 AND v_incorrect_owners IS NOT NULL) THEN
            v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                'check', 'OBJECT_OWNERSHIP',
                'status', 'FAIL',
                'expected_owner', v_object_owner_role,
                'incorrect_objects', v_incorrect_owners,
                'message', 'Some objects have incorrect ownership'
            ));
            v_schema_compliant := FALSE;
            v_issue_count := v_issue_count + ARRAY_SIZE(v_incorrect_owners);
        ELSE
            v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                'check', 'OBJECT_OWNERSHIP',
                'status', 'PASS',
                'expected_owner', v_object_owner_role
            ));
        END IF;
        
        -- ---------------------------------------------------------------------
        -- CHECK 2.5: Future Grants Configuration
        -- ---------------------------------------------------------------------
        LET v_future_grants ARRAY := (
            SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
                'privilege', PRIVILEGE,
                'grant_to', GRANT_TO,
                'grantee', GRANTEE
            ))
            FROM INFORMATION_SCHEMA.FUTURE_GRANTS
            WHERE GRANT_ON = 'TABLE'
              AND (GRANTEE = :v_read_db_role OR GRANTEE = :v_write_db_role OR GRANTEE = :v_object_owner_role)
        );
        
        LET v_has_future_ownership BOOLEAN := (
            SELECT COUNT(*) > 0
            FROM INFORMATION_SCHEMA.FUTURE_GRANTS
            WHERE PRIVILEGE = 'OWNERSHIP'
              AND GRANTEE = :v_object_owner_role
        );
        
        IF (NOT v_has_future_ownership) THEN
            v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                'check', 'FUTURE_OWNERSHIP_GRANT',
                'status', 'FAIL',
                'expected_grantee', v_object_owner_role,
                'message', 'Future ownership grants not configured for ' || v_object_owner_role
            ));
            v_schema_compliant := FALSE;
            v_issue_count := v_issue_count + 1;
        ELSE
            v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                'check', 'FUTURE_OWNERSHIP_GRANT',
                'status', 'PASS',
                'owner', v_object_owner_role
            ));
        END IF;
        
        -- ---------------------------------------------------------------------
        -- CHECK 2.6: Database Role Grant to Functional Roles
        -- ---------------------------------------------------------------------
        IF (v_read_role_exists) THEN
            LET v_read_granted_to_enduser BOOLEAN := FALSE;
            
            -- Check if READ role is granted to END_USER
            BEGIN
                LET v_grant_check RESULTSET := (
                    EXECUTE IMMEDIATE 'SHOW GRANTS OF DATABASE ROLE ' || :v_full_db_name || '.' || :v_read_db_role
                );
                LET v_grant_cursor CURSOR FOR v_grant_check;
                FOR grant_row IN v_grant_cursor DO
                    IF (grant_row."grantee_name" = v_end_user_role) THEN
                        v_read_granted_to_enduser := TRUE;
                    END IF;
                END FOR;
            EXCEPTION
                WHEN OTHER THEN
                    v_read_granted_to_enduser := FALSE;
            END;
            
            IF (NOT v_read_granted_to_enduser) THEN
                v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                    'check', 'READ_ROLE_GRANT',
                    'status', 'FAIL',
                    'database_role', v_read_db_role,
                    'expected_grantee', v_end_user_role,
                    'message', 'READ database role not granted to END_USER functional role'
                ));
                v_schema_compliant := FALSE;
                v_issue_count := v_issue_count + 1;
            ELSE
                v_schema_findings := ARRAY_APPEND(v_schema_findings, OBJECT_CONSTRUCT(
                    'check', 'READ_ROLE_GRANT',
                    'status', 'PASS',
                    'database_role', v_read_db_role,
                    'grantee', v_end_user_role
                ));
            END IF;
        END IF;
        
        -- Update overall compliance
        IF (NOT v_schema_compliant) THEN
            v_compliant := FALSE;
        END IF;
        
        -- Add schema findings to results
        v_schemas := ARRAY_APPEND(v_schemas, OBJECT_CONSTRUCT(
            'schema_name', v_schema_name,
            'compliant', v_schema_compliant,
            'findings', v_schema_findings
        ));
    END FOR;
    
    CLOSE c_schemas;
    
    -- =========================================================================
    -- CHECK 3: Environment-Level Role Hierarchy
    -- =========================================================================
    LET v_role_findings ARRAY := ARRAY_CONSTRUCT();
    
    -- Check functional role hierarchy exists
    LET v_roles_to_check ARRAY := ARRAY_CONSTRUCT(
        v_end_user_role,
        'SRF_' || P_ENVIRONMENT || '_ANALYST',
        v_developer_role,
        'SRF_' || P_ENVIRONMENT || '_TEAM_LEADER',
        'SRF_' || P_ENVIRONMENT || '_DATA_SCIENTIST',
        v_dbadmin_role
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_roles_to_check) - 1 DO
        LET v_role_to_check VARCHAR := v_roles_to_check[i];
        LET v_role_exists BOOLEAN := (
            SELECT COUNT(*) > 0
            FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
            WHERE NAME = :v_role_to_check
              AND DELETED_ON IS NULL
        );
        
        IF (NOT v_role_exists) THEN
            v_role_findings := ARRAY_APPEND(v_role_findings, OBJECT_CONSTRUCT(
                'role', v_role_to_check,
                'status', 'FAIL',
                'message', 'Functional role does not exist'
            ));
            v_compliant := FALSE;
            v_issue_count := v_issue_count + 1;
        ELSE
            v_role_findings := ARRAY_APPEND(v_role_findings, OBJECT_CONSTRUCT(
                'role', v_role_to_check,
                'status', 'PASS'
            ));
        END IF;
    END FOR;
    
    -- =========================================================================
    -- Return Results
    -- =========================================================================
    RETURN OBJECT_CONSTRUCT(
        'status', IFF(v_compliant, 'COMPLIANT', 'NON-COMPLIANT'),
        'environment', P_ENVIRONMENT,
        'database', v_full_db_name,
        'schemas_checked', v_schema_count,
        'total_issues', v_issue_count,
        'expected_object_owner', v_object_owner_role,
        'is_dev_environment', v_is_dev,
        'schema_results', v_schemas,
        'role_hierarchy', v_role_findings,
        'timestamp', CURRENT_TIMESTAMP()
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'environment', P_ENVIRONMENT,
            'database', v_full_db_name
        );
END;
$$;

-- Grant execute to DBADMIN and SECURITY_ADMIN roles
GRANT USAGE ON PROCEDURE RBAC_MONITOR_CONFIG(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_MONITOR_CONFIG(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_DEV_DBADMIN;
GRANT USAGE ON PROCEDURE RBAC_MONITOR_CONFIG(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_TST_DBADMIN;
GRANT USAGE ON PROCEDURE RBAC_MONITOR_CONFIG(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_UAT_DBADMIN;
GRANT USAGE ON PROCEDURE RBAC_MONITOR_CONFIG(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_PPE_DBADMIN;
GRANT USAGE ON PROCEDURE RBAC_MONITOR_CONFIG(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_PRD_DBADMIN;
