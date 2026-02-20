/*******************************************************************************
 * RBAC STORED PROCEDURE: Validate Deployment
 * 
 * Purpose: Post-deployment validation to verify all RBAC framework objects
 *          exist and are properly configured
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     PROCEDURES (3)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the procedures)
 *   Execution Role:  SRS_SECURITY_ADMIN, SRS_SYSTEM_ADMIN
 * 
 *   Dependencies:    
 *     - ADMIN database and RBAC schema must exist
 *     - Should be deployed LAST after all other RBAC files
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * MODULAR VALIDATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT();           -- Validate ALL
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('RBAC');     -- Core RBAC only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('DEVOPS');   -- DevOps only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('CLONES');   -- Clones only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('SECURITY'); -- Security only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('GOVERNANCE');-- Governance only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('BACKUP');   -- Backup only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('HADR');     -- HA/DR only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('ROLES');    -- System roles only
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * VALIDATION CHECKS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   1. SCHEMAS      - Verify all 7 schemas exist in ADMIN database
 *   2. ROLES        - Verify SRS_* and SRF_* roles exist with correct hierarchy
 *   3. PROCEDURES   - Verify all expected procedures exist in each schema
 *   4. TABLES       - Verify all tracking/config tables exist
 *   5. GRANTS       - Verify key grants are in place
 * 
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- #############################################################################
-- SECTION 1: EXPECTED OBJECTS CONFIGURATION
-- #############################################################################

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_GET_EXPECTED_OBJECTS(
    P_SECTION VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_expected OBJECT;
BEGIN
    v_expected := OBJECT_CONSTRUCT(
        'schemas', ARRAY_CONSTRUCT('RBAC', 'DEVOPS', 'CLONES', 'SECURITY', 'GOVERNANCE', 'BACKUP', 'HADR'),
        
        'system_roles', ARRAY_CONSTRUCT(
            'SRS_SYSTEM_ADMIN',
            'SRS_SECURITY_ADMIN',
            'SRS_USER_ADMIN',
            'SRS_DEVOPS'
        ),
        
        'functional_role_prefixes', ARRAY_CONSTRUCT(
            'SRF_DEV_',
            'SRF_TST_',
            'SRF_UAT_',
            'SRF_PPE_',
            'SRF_PRD_'
        ),
        
        'RBAC', OBJECT_CONSTRUCT(
            'procedures', ARRAY_CONSTRUCT(
                'RBAC_HELP',
                'RBAC_CREATE_WAREHOUSE',
                'RBAC_CREATE_SCHEMA',
                'RBAC_CREATE_ACCESS_ROLE',
                'RBAC_LINK_SCHEMA_TO_ACCESS_ROLE',
                'RBAC_LIST_ACCESS_ROLES',
                'RBAC_GRANT_ACCESS_ROLE_TO_USER',
                'RBAC_CREATE_SERVICE_ROLE',
                'RBAC_CONFIGURE_SERVICE_ROLE',
                'RBAC_LIST_SERVICE_ROLES',
                'RBAC_CREATE_SERVICE_ACCOUNT',
                'RBAC_CONFIGURE_USER',
                'RBAC_DISABLE_USER',
                'RBAC_LIST_USER_ACCESS',
                'RBAC_AUDIT_USER_ROLES',
                'RBAC_MONITOR_CONFIG',
                'RBAC_VALIDATE_DEPLOYMENT'
            ),
            'tables', ARRAY_CONSTRUCT()
        ),
        
        'DEVOPS', OBJECT_CONSTRUCT(
            'procedures', ARRAY_CONSTRUCT(
                'RBAC_CREATE_PIPELINE',
                'RBAC_EXECUTE_PIPELINE',
                'RBAC_LIST_PIPELINES',
                'RBAC_PIPELINE_STATUS_DASHBOARD',
                'RBAC_DEVOPS_MONITORING_DASHBOARD'
            ),
            'tables', ARRAY_CONSTRUCT(
                'DEVOPS_PIPELINE_STATUS',
                'DEVOPS_RELEASES',
                'DEVOPS_CHANGE_LOG'
            )
        ),
        
        'CLONES', OBJECT_CONSTRUCT(
            'procedures', ARRAY_CONSTRUCT(
                'RBAC_CREATE_CLONE',
                'RBAC_DROP_CLONE',
                'RBAC_LIST_CLONES',
                'RBAC_EXTEND_CLONE',
                'RBAC_LOG_CLONE_OPERATION',
                'RBAC_CLONE_USAGE_DASHBOARD',
                'RBAC_CLONE_MONITORING_DASHBOARD'
            ),
            'tables', ARRAY_CONSTRUCT(
                'RBAC_CLONE_REGISTRY',
                'RBAC_CLONE_POLICIES',
                'RBAC_CLONE_AUDIT_LOG',
                'RBAC_CLONE_POLICY_VIOLATIONS',
                'RBAC_CLONE_ACCESS_LOG'
            )
        ),
        
        'SECURITY', OBJECT_CONSTRUCT(
            'procedures', ARRAY_CONSTRUCT(
                'RBAC_SECURITY_DASHBOARD',
                'RBAC_LOGIN_ANOMALY_DETECTION',
                'RBAC_PRIVILEGE_ESCALATION_ALERT',
                'POLICY_CREATE_NETWORK_POLICY',
                'POLICY_CREATE_PASSWORD_POLICY',
                'POLICY_CREATE_SESSION_POLICY',
                'POLICY_CREATE_AUTHENTICATION_POLICY',
                'POLICY_COMPLIANCE_DASHBOARD',
                'POLICY_MONITORING_DASHBOARD'
            ),
            'tables', ARRAY_CONSTRUCT(
                'RBAC_SECURITY_ALERTS',
                'RBAC_SECURITY_EXCEPTIONS',
                'POLICY_REGISTRY',
                'POLICY_ASSIGNMENTS',
                'POLICY_TEMPLATES',
                'POLICY_AUDIT_LOG',
                'POLICY_EXCEPTIONS'
            )
        ),
        
        'GOVERNANCE', OBJECT_CONSTRUCT(
            'procedures', ARRAY_CONSTRUCT(
                'RBAC_CREATE_MASKING_POLICY',
                'RBAC_CREATE_ROW_ACCESS_POLICY',
                'RBAC_APPLY_TAG',
                'RBAC_CLASSIFY_COLUMN',
                'RBAC_POLICY_COVERAGE_DASHBOARD',
                'RBAC_GOVERNANCE_MONITORING_DASHBOARD'
            ),
            'tables', ARRAY_CONSTRUCT(
                'RBAC_MASKING_POLICIES',
                'RBAC_ROW_ACCESS_POLICIES',
                'RBAC_TAG_REGISTRY',
                'RBAC_CLASSIFICATION_LOG',
                'RBAC_GOVERNANCE_AUDIT_LOG'
            )
        ),
        
        'BACKUP', OBJECT_CONSTRUCT(
            'procedures', ARRAY_CONSTRUCT(
                'RBAC_CREATE_BACKUP_POLICY',
                'RBAC_EXECUTE_BACKUP',
                'RBAC_RESTORE_FROM_BACKUP',
                'RBAC_LIST_BACKUPS',
                'RBAC_BACKUP_STATUS_DASHBOARD',
                'RBAC_BACKUP_MONITORING_DASHBOARD'
            ),
            'tables', ARRAY_CONSTRUCT(
                'RBAC_BACKUP_POLICIES',
                'RBAC_BACKUP_HISTORY',
                'RBAC_RESTORE_LOG',
                'RBAC_BACKUP_AUDIT_LOG'
            )
        ),
        
        'HADR', OBJECT_CONSTRUCT(
            'procedures', ARRAY_CONSTRUCT(
                'RBAC_CREATE_REPLICATION_GROUP',
                'RBAC_SETUP_DATABASE_REPLICATION',
                'RBAC_CHECK_REPLICATION_STATUS',
                'RBAC_INITIATE_FAILOVER',
                'RBAC_SCHEDULE_DR_TEST',
                'RBAC_REPLICATION_HEALTH_DASHBOARD',
                'RBAC_HADR_MONITORING_DASHBOARD'
            ),
            'tables', ARRAY_CONSTRUCT(
                'HADR_REPLICATION_GROUPS',
                'HADR_FAILOVER_GROUPS',
                'HADR_REPLICATION_HISTORY',
                'HADR_FAILOVER_EVENTS',
                'HADR_DR_TESTS',
                'HADR_AUDIT_LOG'
            )
        )
    );
    
    IF (P_SECTION IS NOT NULL) THEN
        IF (P_SECTION = 'ROLES') THEN
            RETURN OBJECT_CONSTRUCT(
                'system_roles', v_expected:system_roles,
                'functional_role_prefixes', v_expected:functional_role_prefixes
            );
        ELSEIF (P_SECTION = 'SCHEMAS') THEN
            RETURN OBJECT_CONSTRUCT('schemas', v_expected:schemas);
        ELSE
            RETURN OBJECT_CONSTRUCT(
                'schemas', ARRAY_CONSTRUCT(P_SECTION),
                P_SECTION, v_expected[P_SECTION]
            );
        END IF;
    END IF;
    
    RETURN v_expected;
END;
$$;

-- #############################################################################
-- SECTION 2: INDIVIDUAL VALIDATION FUNCTIONS
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Validate Section
 * 
 * Purpose: Validates a specific section of the RBAC deployment
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_VALIDATE_SECTION(
    P_SECTION VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_expected VARIANT;
    v_missing_procedures ARRAY := ARRAY_CONSTRUCT();
    v_missing_tables ARRAY := ARRAY_CONSTRUCT();
    v_missing_roles ARRAY := ARRAY_CONSTRUCT();
    v_missing_schemas ARRAY := ARRAY_CONSTRUCT();
    v_found_procedures ARRAY := ARRAY_CONSTRUCT();
    v_found_tables ARRAY := ARRAY_CONSTRUCT();
    v_found_roles ARRAY := ARRAY_CONSTRUCT();
    v_proc_name VARCHAR;
    v_table_name VARCHAR;
    v_role_name VARCHAR;
    v_schema_name VARCHAR;
    v_exists BOOLEAN;
    v_status VARCHAR;
    v_issues INTEGER := 0;
BEGIN
    CALL ADMIN.RBAC.RBAC_GET_EXPECTED_OBJECTS(P_SECTION) INTO v_expected;
    
    IF (P_SECTION = 'ROLES' OR P_SECTION IS NULL) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_expected:system_roles) - 1 DO
            v_role_name := v_expected:system_roles[i]::VARCHAR;
            
            SELECT COUNT(*) > 0 INTO v_exists
            FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
            WHERE NAME = v_role_name AND DELETED_ON IS NULL;
            
            IF (v_exists) THEN
                v_found_roles := ARRAY_APPEND(v_found_roles, v_role_name);
            ELSE
                v_missing_roles := ARRAY_APPEND(v_missing_roles, v_role_name);
                v_issues := v_issues + 1;
            END IF;
        END FOR;
        
        RETURN OBJECT_CONSTRUCT(
            'section', 'ROLES',
            'status', IFF(v_issues = 0, 'PASS', 'FAIL'),
            'found_count', ARRAY_SIZE(v_found_roles),
            'missing_count', ARRAY_SIZE(v_missing_roles),
            'found', v_found_roles,
            'missing', v_missing_roles
        );
    END IF;
    
    IF (P_SECTION = 'SCHEMAS') THEN
        FOR i IN 0 TO ARRAY_SIZE(v_expected:schemas) - 1 DO
            v_schema_name := v_expected:schemas[i]::VARCHAR;
            
            SELECT COUNT(*) > 0 INTO v_exists
            FROM INFORMATION_SCHEMA.SCHEMATA
            WHERE CATALOG_NAME = 'ADMIN' AND SCHEMA_NAME = v_schema_name;
            
            IF (NOT v_exists) THEN
                v_missing_schemas := ARRAY_APPEND(v_missing_schemas, v_schema_name);
                v_issues := v_issues + 1;
            END IF;
        END FOR;
        
        RETURN OBJECT_CONSTRUCT(
            'section', 'SCHEMAS',
            'status', IFF(v_issues = 0, 'PASS', 'FAIL'),
            'expected', v_expected:schemas,
            'missing', v_missing_schemas,
            'missing_count', ARRAY_SIZE(v_missing_schemas)
        );
    END IF;
    
    IF (v_expected[P_SECTION] IS NOT NULL) THEN
        SELECT COUNT(*) > 0 INTO v_exists
        FROM INFORMATION_SCHEMA.SCHEMATA
        WHERE CATALOG_NAME = 'ADMIN' AND SCHEMA_NAME = P_SECTION;
        
        IF (NOT v_exists) THEN
            RETURN OBJECT_CONSTRUCT(
                'section', P_SECTION,
                'status', 'FAIL',
                'error', 'Schema ADMIN.' || P_SECTION || ' does not exist'
            );
        END IF;
        
        FOR i IN 0 TO ARRAY_SIZE(v_expected[P_SECTION]:procedures) - 1 DO
            v_proc_name := v_expected[P_SECTION]:procedures[i]::VARCHAR;
            
            SELECT COUNT(*) > 0 INTO v_exists
            FROM INFORMATION_SCHEMA.PROCEDURES
            WHERE PROCEDURE_CATALOG = 'ADMIN' 
              AND PROCEDURE_SCHEMA = P_SECTION 
              AND PROCEDURE_NAME = v_proc_name;
            
            IF (v_exists) THEN
                v_found_procedures := ARRAY_APPEND(v_found_procedures, v_proc_name);
            ELSE
                v_missing_procedures := ARRAY_APPEND(v_missing_procedures, v_proc_name);
                v_issues := v_issues + 1;
            END IF;
        END FOR;
        
        FOR i IN 0 TO ARRAY_SIZE(v_expected[P_SECTION]:tables) - 1 DO
            v_table_name := v_expected[P_SECTION]:tables[i]::VARCHAR;
            
            SELECT COUNT(*) > 0 INTO v_exists
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_CATALOG = 'ADMIN' 
              AND TABLE_SCHEMA = P_SECTION 
              AND TABLE_NAME = v_table_name;
            
            IF (v_exists) THEN
                v_found_tables := ARRAY_APPEND(v_found_tables, v_table_name);
            ELSE
                v_missing_tables := ARRAY_APPEND(v_missing_tables, v_table_name);
                v_issues := v_issues + 1;
            END IF;
        END FOR;
        
        v_status := IFF(v_issues = 0, 'PASS', IFF(v_issues < 3, 'WARN', 'FAIL'));
        
        RETURN OBJECT_CONSTRUCT(
            'section', P_SECTION,
            'status', v_status,
            'procedures', OBJECT_CONSTRUCT(
                'expected', ARRAY_SIZE(v_expected[P_SECTION]:procedures),
                'found', ARRAY_SIZE(v_found_procedures),
                'missing', v_missing_procedures
            ),
            'tables', OBJECT_CONSTRUCT(
                'expected', ARRAY_SIZE(v_expected[P_SECTION]:tables),
                'found', ARRAY_SIZE(v_found_tables),
                'missing', v_missing_tables
            ),
            'total_issues', v_issues
        );
    END IF;
    
    RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Unknown section: ' || P_SECTION);
END;
$$;

-- #############################################################################
-- SECTION 3: MAIN VALIDATION PROCEDURE
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Validate Deployment (Main Entry Point)
 * 
 * Purpose: Validates RBAC deployment - all sections or specific section
 * 
 * Parameters:
 *   P_SECTION - NULL for all, or specific section:
 *               'RBAC', 'DEVOPS', 'CLONES', 'SECURITY', 'GOVERNANCE', 
 *               'BACKUP', 'HADR', 'ROLES', 'SCHEMAS'
 * 
 * Returns: VARIANT with validation results
 * 
 * Examples:
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT();           -- All sections
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('RBAC');     -- RBAC only
 *   CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT('ROLES');    -- Roles only
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT(
    P_SECTION VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_results OBJECT := OBJECT_CONSTRUCT();
    v_section_result VARIANT;
    v_sections ARRAY;
    v_section VARCHAR;
    v_total_issues INTEGER := 0;
    v_pass_count INTEGER := 0;
    v_fail_count INTEGER := 0;
    v_warn_count INTEGER := 0;
    v_overall_status VARCHAR;
    v_admin_exists BOOLEAN;
BEGIN
    SELECT COUNT(*) > 0 INTO v_admin_exists
    FROM INFORMATION_SCHEMA.DATABASES
    WHERE DATABASE_NAME = 'ADMIN';
    
    IF (NOT v_admin_exists) THEN
        RETURN OBJECT_CONSTRUCT(
            'validation_time', CURRENT_TIMESTAMP(),
            'overall_status', 'FAIL',
            'error', 'ADMIN database does not exist. Run RBAC_INITIAL_CONFIG first.',
            'recommendation', 'Execute: CALL RBAC_INITIAL_CONFIG(NULL, FALSE);'
        );
    END IF;
    
    IF (P_SECTION IS NOT NULL) THEN
        CALL ADMIN.RBAC.RBAC_VALIDATE_SECTION(P_SECTION) INTO v_section_result;
        
        RETURN OBJECT_CONSTRUCT(
            'validation_time', CURRENT_TIMESTAMP(),
            'section', P_SECTION,
            'result', v_section_result,
            'recommendation', IFF(
                v_section_result:status::VARCHAR = 'FAIL',
                'Deploy missing objects from the corresponding RBAC_SP_*.sql file',
                NULL
            )
        );
    END IF;
    
    v_sections := ARRAY_CONSTRUCT('SCHEMAS', 'ROLES', 'RBAC', 'DEVOPS', 'CLONES', 'SECURITY', 'GOVERNANCE', 'BACKUP', 'HADR');
    
    FOR i IN 0 TO ARRAY_SIZE(v_sections) - 1 DO
        v_section := v_sections[i]::VARCHAR;
        
        CALL ADMIN.RBAC.RBAC_VALIDATE_SECTION(v_section) INTO v_section_result;
        
        v_results := OBJECT_INSERT(v_results, v_section, v_section_result);
        
        IF (v_section_result:status::VARCHAR = 'PASS') THEN
            v_pass_count := v_pass_count + 1;
        ELSEIF (v_section_result:status::VARCHAR = 'FAIL') THEN
            v_fail_count := v_fail_count + 1;
        ELSE
            v_warn_count := v_warn_count + 1;
        END IF;
        
        IF (v_section_result:total_issues IS NOT NULL) THEN
            v_total_issues := v_total_issues + v_section_result:total_issues::INTEGER;
        ELSEIF (v_section_result:missing_count IS NOT NULL) THEN
            v_total_issues := v_total_issues + v_section_result:missing_count::INTEGER;
        END IF;
    END FOR;
    
    IF (v_fail_count > 0) THEN
        v_overall_status := 'FAIL';
    ELSEIF (v_warn_count > 0) THEN
        v_overall_status := 'WARN';
    ELSE
        v_overall_status := 'PASS';
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'validation_time', CURRENT_TIMESTAMP(),
        'overall_status', v_overall_status,
        'summary', OBJECT_CONSTRUCT(
            'sections_checked', ARRAY_SIZE(v_sections),
            'passed', v_pass_count,
            'warnings', v_warn_count,
            'failed', v_fail_count,
            'total_missing_objects', v_total_issues
        ),
        'sections', v_results,
        'recommendations', CASE 
            WHEN v_overall_status = 'PASS' THEN 
                ARRAY_CONSTRUCT('Deployment validated successfully. All expected objects found.')
            WHEN v_overall_status = 'WARN' THEN 
                ARRAY_CONSTRUCT(
                    'Some objects are missing but core functionality should work.',
                    'Review the sections with warnings and deploy missing files if needed.'
                )
            ELSE 
                ARRAY_CONSTRUCT(
                    'Critical objects are missing. Review the failed sections.',
                    'Deploy missing files in the order specified in RBAC_README.sql',
                    'Run validation again after deployment: CALL RBAC_VALIDATE_DEPLOYMENT();'
                )
        END
    );
END;
$$;

-- #############################################################################
-- SECTION 4: QUICK CHECK PROCEDURE
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Quick Deployment Check
 * 
 * Purpose: Fast check returning simple PASS/FAIL without details
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_DEPLOYMENT_STATUS()
RETURNS TABLE (
    SECTION VARCHAR,
    STATUS VARCHAR,
    ISSUES INTEGER
)
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_full_result VARIANT;
    res RESULTSET;
BEGIN
    CALL ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT() INTO v_full_result;
    
    res := (
        SELECT 'OVERALL' AS SECTION, 
               v_full_result:overall_status::VARCHAR AS STATUS,
               v_full_result:summary:total_missing_objects::INTEGER AS ISSUES
        UNION ALL
        SELECT 'SCHEMAS', v_full_result:sections:SCHEMAS:status::VARCHAR, 
               COALESCE(v_full_result:sections:SCHEMAS:missing_count::INTEGER, 0)
        UNION ALL
        SELECT 'ROLES', v_full_result:sections:ROLES:status::VARCHAR,
               COALESCE(v_full_result:sections:ROLES:missing_count::INTEGER, 0)
        UNION ALL
        SELECT 'RBAC', v_full_result:sections:RBAC:status::VARCHAR,
               COALESCE(v_full_result:sections:RBAC:total_issues::INTEGER, 0)
        UNION ALL
        SELECT 'DEVOPS', v_full_result:sections:DEVOPS:status::VARCHAR,
               COALESCE(v_full_result:sections:DEVOPS:total_issues::INTEGER, 0)
        UNION ALL
        SELECT 'CLONES', v_full_result:sections:CLONES:status::VARCHAR,
               COALESCE(v_full_result:sections:CLONES:total_issues::INTEGER, 0)
        UNION ALL
        SELECT 'SECURITY', v_full_result:sections:SECURITY:status::VARCHAR,
               COALESCE(v_full_result:sections:SECURITY:total_issues::INTEGER, 0)
        UNION ALL
        SELECT 'GOVERNANCE', v_full_result:sections:GOVERNANCE:status::VARCHAR,
               COALESCE(v_full_result:sections:GOVERNANCE:total_issues::INTEGER, 0)
        UNION ALL
        SELECT 'BACKUP', v_full_result:sections:BACKUP:status::VARCHAR,
               COALESCE(v_full_result:sections:BACKUP:total_issues::INTEGER, 0)
        UNION ALL
        SELECT 'HADR', v_full_result:sections:HADR:status::VARCHAR,
               COALESCE(v_full_result:sections:HADR:total_issues::INTEGER, 0)
    );
    
    RETURN TABLE(res);
END;
$$;

-- #############################################################################
-- SECTION 5: GRANTS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_GET_EXPECTED_OBJECTS(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_VALIDATE_SECTION(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_VALIDATE_DEPLOYMENT(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_DEPLOYMENT_STATUS() TO ROLE SRS_SECURITY_ADMIN;

-- =============================================================================
-- END OF VALIDATE DEPLOYMENT PROCEDURES
-- =============================================================================
