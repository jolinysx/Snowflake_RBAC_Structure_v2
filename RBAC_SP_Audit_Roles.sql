/*******************************************************************************
 * RBAC STORED PROCEDURE: Audit User Role Assignments
 * 
 * Purpose: Validates existing user-role assignments against RBAC compliance rules
 *          and flags any non-compliant configurations
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
 * ═══════════════════════════════════════════════════════════════════════════════
 * COMPLIANCE RULES:
 *   1. PERSON accounts: Should only have SRF_* and SRA_* roles (not SRW_*)
 *   2. SERVICE/LEGACY_SERVICE accounts: Should only have SRW_* roles (not SRF_*|SRA_*)
 *   3. Orphaned roles: Roles granted but not matching naming conventions
 *   4. Missing roles: Service accounts without any SRW_* role
 * 
 * Parameters:
 *   P_ENVIRONMENT     - Environment to audit (NULL = all environments)
 *   P_INCLUDE_DETAILS - Include detailed role listings (default: TRUE)
 * 
 * Returns: VARIANT containing audit results and non-compliant findings
 * 
 * Execution Mode: OWNER (provides controlled access to ACCOUNT_USAGE views)
 * Procedure Owner: Should be owned by ACCOUNTADMIN or role with ACCOUNT_USAGE access
 * Grant USAGE to: SRS_SECURITY_ADMIN, SRS_ACCOUNT_ADMIN
 * 
 * Usage Examples:
 *   CALL RBAC_AUDIT_USER_ROLES(NULL, TRUE);    -- Audit all environments
 *   CALL RBAC_AUDIT_USER_ROLES('PRD', TRUE);   -- Audit PRD only
 *   CALL RBAC_AUDIT_USER_ROLES('DEV', FALSE);  -- Audit DEV, summary only
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_AUDIT_USER_ROLES
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_AUDIT_USER_ROLES(
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_INCLUDE_DETAILS BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_violations ARRAY := ARRAY_CONSTRUCT();
    v_warnings ARRAY := ARRAY_CONSTRUCT();
    v_summary OBJECT;
    v_total_users INTEGER := 0;
    v_total_service_accounts INTEGER := 0;
    v_total_person_accounts INTEGER := 0;
    v_compliant_users INTEGER := 0;
    v_non_compliant_users INTEGER := 0;
    v_env_filter VARCHAR;
BEGIN
    -- Build environment filter
    IF (P_ENVIRONMENT IS NOT NULL) THEN
        IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
            RETURN OBJECT_CONSTRUCT(
                'status', 'ERROR',
                'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD or NULL for all'
            );
        END IF;
        v_env_filter := '_' || P_ENVIRONMENT || '_';
    ELSE
        v_env_filter := '_%_';
    END IF;

    -- =========================================================================
    -- AUDIT 1: SERVICE accounts with SRF_* roles (VIOLATION)
    -- Service accounts should NOT have functional roles directly
    -- =========================================================================
    LET v_service_with_srf ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'user_name', u.NAME,
            'user_type', u.TYPE,
            'role_name', g.ROLE,
            'violation_type', 'SERVICE_ACCOUNT_WITH_SRF_ROLE',
            'severity', 'HIGH',
            'message', 'Service account has SRF_* functional role. Should use SRW_* wrapper role instead.',
            'remediation', 'REVOKE ROLE ' || g.ROLE || ' FROM USER ' || u.NAME || '; Use RBAC_GRANT_SERVICE_ACCOUNT instead.'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.NAME = g.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND u.TYPE IN ('SERVICE', 'LEGACY_SERVICE')
          AND g.ROLE LIKE 'SRF' || :v_env_filter || '%'
          AND g.DELETED_ON IS NULL
    );
    
    IF (v_service_with_srf IS NOT NULL AND ARRAY_SIZE(v_service_with_srf) > 0) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_service_with_srf) - 1 DO
            v_violations := ARRAY_APPEND(v_violations, v_service_with_srf[i]);
        END FOR;
    END IF;

    -- =========================================================================
    -- AUDIT 2: SERVICE accounts with SRA_* roles (VIOLATION)
    -- Service accounts should NOT have access roles directly
    -- =========================================================================
    LET v_service_with_sra ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'user_name', u.NAME,
            'user_type', u.TYPE,
            'role_name', g.ROLE,
            'violation_type', 'SERVICE_ACCOUNT_WITH_SRA_ROLE',
            'severity', 'HIGH',
            'message', 'Service account has SRA_* access role. Should use SRW_* wrapper role instead.',
            'remediation', 'REVOKE ROLE ' || g.ROLE || ' FROM USER ' || u.NAME || '; Use RBAC_GRANT_SERVICE_ACCOUNT instead.'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.NAME = g.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND u.TYPE IN ('SERVICE', 'LEGACY_SERVICE')
          AND g.ROLE LIKE 'SRA' || :v_env_filter || '%'
          AND g.DELETED_ON IS NULL
    );
    
    IF (v_service_with_sra IS NOT NULL AND ARRAY_SIZE(v_service_with_sra) > 0) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_service_with_sra) - 1 DO
            v_violations := ARRAY_APPEND(v_violations, v_service_with_sra[i]);
        END FOR;
    END IF;

    -- =========================================================================
    -- AUDIT 3: PERSON accounts with SRW_* roles (VIOLATION)
    -- Human users should NOT have service wrapper roles
    -- =========================================================================
    LET v_person_with_srw ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'user_name', u.NAME,
            'user_type', COALESCE(u.TYPE, 'PERSON'),
            'role_name', g.ROLE,
            'violation_type', 'PERSON_ACCOUNT_WITH_SRW_ROLE',
            'severity', 'HIGH',
            'message', 'Human user has SRW_* service wrapper role. Should use SRF_* and SRA_* roles instead.',
            'remediation', 'REVOKE ROLE ' || g.ROLE || ' FROM USER ' || u.NAME || '; Use RBAC_GRANT_USER_ACCESS instead.'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.NAME = g.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND (u.TYPE = 'PERSON' OR u.TYPE IS NULL)
          AND g.ROLE LIKE 'SRW' || :v_env_filter || '%'
          AND g.DELETED_ON IS NULL
    );
    
    IF (v_person_with_srw IS NOT NULL AND ARRAY_SIZE(v_person_with_srw) > 0) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_person_with_srw) - 1 DO
            v_violations := ARRAY_APPEND(v_violations, v_person_with_srw[i]);
        END FOR;
    END IF;

    -- =========================================================================
    -- AUDIT 4: SERVICE accounts without any SRW_* role (WARNING)
    -- Service accounts should have at least one wrapper role
    -- =========================================================================
    LET v_service_no_srw ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'user_name', u.NAME,
            'user_type', u.TYPE,
            'violation_type', 'SERVICE_ACCOUNT_NO_SRW_ROLE',
            'severity', 'MEDIUM',
            'message', 'Service account has no SRW_* wrapper role assigned.',
            'remediation', 'Use RBAC_CREATE_SERVICE_ROLE and RBAC_GRANT_SERVICE_ACCOUNT to assign appropriate access.'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        WHERE u.DELETED_ON IS NULL
          AND u.TYPE IN ('SERVICE', 'LEGACY_SERVICE')
          AND NOT EXISTS (
              SELECT 1 
              FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g
              WHERE g.GRANTEE_NAME = u.NAME
                AND g.ROLE LIKE 'SRW_%'
                AND g.DELETED_ON IS NULL
          )
    );
    
    IF (v_service_no_srw IS NOT NULL AND ARRAY_SIZE(v_service_no_srw) > 0) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_service_no_srw) - 1 DO
            v_warnings := ARRAY_APPEND(v_warnings, v_service_no_srw[i]);
        END FOR;
    END IF;

    -- =========================================================================
    -- AUDIT 5: PERSON accounts with SRF_* but no SRA_* role (WARNING)
    -- Human users with capability but no data access
    -- =========================================================================
    LET v_person_no_sra ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'user_name', u.NAME,
            'user_type', COALESCE(u.TYPE, 'PERSON'),
            'srf_roles', srf.roles,
            'violation_type', 'PERSON_ACCOUNT_NO_SRA_ROLE',
            'severity', 'LOW',
            'message', 'Human user has SRF_* functional role but no SRA_* access role. User has capability but no data access.',
            'remediation', 'Use RBAC_GRANT_USER_ACCESS to assign appropriate SRA_* access role.'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN (
            SELECT GRANTEE_NAME, ARRAY_AGG(ROLE) AS roles
            FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
            WHERE ROLE LIKE 'SRF_%'
              AND DELETED_ON IS NULL
            GROUP BY GRANTEE_NAME
        ) srf ON u.NAME = srf.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND (u.TYPE = 'PERSON' OR u.TYPE IS NULL)
          AND NOT EXISTS (
              SELECT 1 
              FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g
              WHERE g.GRANTEE_NAME = u.NAME
                AND g.ROLE LIKE 'SRA_%'
                AND g.DELETED_ON IS NULL
          )
    );
    
    IF (v_person_no_sra IS NOT NULL AND ARRAY_SIZE(v_person_no_sra) > 0) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_person_no_sra) - 1 DO
            v_warnings := ARRAY_APPEND(v_warnings, v_person_no_sra[i]);
        END FOR;
    END IF;

    -- =========================================================================
    -- AUDIT 6: PERSON accounts with SRA_* but no SRF_* role (WARNING)
    -- Human users with data access but no capability
    -- =========================================================================
    LET v_person_no_srf ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'user_name', u.NAME,
            'user_type', COALESCE(u.TYPE, 'PERSON'),
            'sra_roles', sra.roles,
            'violation_type', 'PERSON_ACCOUNT_NO_SRF_ROLE',
            'severity', 'LOW',
            'message', 'Human user has SRA_* access role but no SRF_* functional role. User has data access but no defined capability.',
            'remediation', 'Use RBAC_GRANT_USER_ACCESS with functional role parameter to assign appropriate SRF_* capability.'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN (
            SELECT GRANTEE_NAME, ARRAY_AGG(ROLE) AS roles
            FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
            WHERE ROLE LIKE 'SRA_%'
              AND DELETED_ON IS NULL
            GROUP BY GRANTEE_NAME
        ) sra ON u.NAME = sra.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND (u.TYPE = 'PERSON' OR u.TYPE IS NULL)
          AND NOT EXISTS (
              SELECT 1 
              FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g
              WHERE g.GRANTEE_NAME = u.NAME
                AND g.ROLE LIKE 'SRF_%'
                AND g.DELETED_ON IS NULL
          )
    );
    
    IF (v_person_no_srf IS NOT NULL AND ARRAY_SIZE(v_person_no_srf) > 0) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_person_no_srf) - 1 DO
            v_warnings := ARRAY_APPEND(v_warnings, v_person_no_srf[i]);
        END FOR;
    END IF;

    -- =========================================================================
    -- AUDIT 7: Users with non-standard RBAC roles (INFO)
    -- Users with roles that don't follow SRS/SRF/SRA/SRW/SRD naming convention
    -- =========================================================================
    LET v_non_standard_roles ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'user_name', u.NAME,
            'user_type', COALESCE(u.TYPE, 'PERSON'),
            'role_name', g.ROLE,
            'violation_type', 'NON_STANDARD_ROLE',
            'severity', 'INFO',
            'message', 'User has role that does not follow RBAC naming convention (SRS/SRF/SRA/SRW).',
            'remediation', 'Review if this role is necessary or should be migrated to standard RBAC roles.'
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.NAME = g.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND g.DELETED_ON IS NULL
          AND g.ROLE NOT LIKE 'SRS_%'
          AND g.ROLE NOT LIKE 'SRF_%'
          AND g.ROLE NOT LIKE 'SRA_%'
          AND g.ROLE NOT LIKE 'SRW_%'
          AND g.ROLE NOT IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'USERADMIN', 'SYSADMIN', 'ORGADMIN', 'PUBLIC')
    );
    
    -- Only add non-standard roles if details requested
    IF (P_INCLUDE_DETAILS AND v_non_standard_roles IS NOT NULL AND ARRAY_SIZE(v_non_standard_roles) > 0) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_non_standard_roles) - 1 DO
            v_warnings := ARRAY_APPEND(v_warnings, v_non_standard_roles[i]);
        END FOR;
    END IF;

    -- =========================================================================
    -- Calculate Summary Statistics
    -- =========================================================================
    v_total_users := (
        SELECT COUNT(*)
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE DELETED_ON IS NULL
    );
    
    v_total_service_accounts := (
        SELECT COUNT(*)
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE DELETED_ON IS NULL
          AND TYPE IN ('SERVICE', 'LEGACY_SERVICE')
    );
    
    v_total_person_accounts := (
        SELECT COUNT(*)
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE DELETED_ON IS NULL
          AND (TYPE = 'PERSON' OR TYPE IS NULL)
    );

    -- Count unique non-compliant users
    LET v_violation_users ARRAY := (
        SELECT ARRAY_UNIQUE_AGG(v.value:user_name::VARCHAR)
        FROM TABLE(FLATTEN(input => :v_violations)) v
    );
    
    v_non_compliant_users := COALESCE(ARRAY_SIZE(v_violation_users), 0);
    v_compliant_users := v_total_users - v_non_compliant_users;

    -- Build summary
    v_summary := OBJECT_CONSTRUCT(
        'total_users', v_total_users,
        'person_accounts', v_total_person_accounts,
        'service_accounts', v_total_service_accounts,
        'compliant_users', v_compliant_users,
        'non_compliant_users', v_non_compliant_users,
        'compliance_rate', ROUND((v_compliant_users / NULLIF(v_total_users, 0)) * 100, 2),
        'total_violations', ARRAY_SIZE(v_violations),
        'total_warnings', ARRAY_SIZE(v_warnings),
        'high_severity_count', (
            SELECT COUNT(*)
            FROM TABLE(FLATTEN(input => :v_violations))
            WHERE value:severity = 'HIGH'
        ),
        'medium_severity_count', (
            SELECT COUNT(*)
            FROM TABLE(FLATTEN(input => :v_violations))
            WHERE value:severity = 'MEDIUM'
        ) + (
            SELECT COUNT(*)
            FROM TABLE(FLATTEN(input => :v_warnings))
            WHERE value:severity = 'MEDIUM'
        )
    );

    -- =========================================================================
    -- Return Results
    -- =========================================================================
    RETURN OBJECT_CONSTRUCT(
        'status', IFF(ARRAY_SIZE(v_violations) = 0, 'COMPLIANT', 'NON-COMPLIANT'),
        'audit_timestamp', CURRENT_TIMESTAMP(),
        'environment_filter', COALESCE(P_ENVIRONMENT, 'ALL'),
        'summary', v_summary,
        'violations', IFF(P_INCLUDE_DETAILS, v_violations, ARRAY_CONSTRUCT()),
        'warnings', IFF(P_INCLUDE_DETAILS, v_warnings, ARRAY_CONSTRUCT()),
        'violation_count', ARRAY_SIZE(v_violations),
        'warning_count', ARRAY_SIZE(v_warnings)
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE
        );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Generate Remediation Script
 * 
 * Purpose: Generates SQL script to remediate non-compliant role assignments
 * 
 * Parameters:
 *   P_ENVIRONMENT - Environment to generate remediation for (NULL = all)
 * 
 * Returns: VARIANT containing remediation SQL statements
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_GENERATE_REMEDIATION_SCRIPT(
    P_ENVIRONMENT VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_remediation_statements ARRAY := ARRAY_CONSTRUCT();
    v_env_filter VARCHAR;
BEGIN
    -- Build environment filter
    IF (P_ENVIRONMENT IS NOT NULL) THEN
        v_env_filter := '_' || P_ENVIRONMENT || '_';
    ELSE
        v_env_filter := '_%_';
    END IF;

    -- Generate REVOKE statements for SERVICE accounts with SRF_* roles
    LET v_revoke_srf ARRAY := (
        SELECT ARRAY_AGG(
            'REVOKE ROLE ' || g.ROLE || ' FROM USER ' || u.NAME || ';'
        )
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.NAME = g.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND u.TYPE IN ('SERVICE', 'LEGACY_SERVICE')
          AND g.ROLE LIKE 'SRF' || :v_env_filter || '%'
          AND g.DELETED_ON IS NULL
    );
    
    IF (v_revoke_srf IS NOT NULL) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_revoke_srf) - 1 DO
            v_remediation_statements := ARRAY_APPEND(v_remediation_statements, 
                OBJECT_CONSTRUCT('type', 'REVOKE_SRF_FROM_SERVICE', 'sql', v_revoke_srf[i]));
        END FOR;
    END IF;

    -- Generate REVOKE statements for SERVICE accounts with SRA_* roles
    LET v_revoke_sra ARRAY := (
        SELECT ARRAY_AGG(
            'REVOKE ROLE ' || g.ROLE || ' FROM USER ' || u.NAME || ';'
        )
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.NAME = g.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND u.TYPE IN ('SERVICE', 'LEGACY_SERVICE')
          AND g.ROLE LIKE 'SRA' || :v_env_filter || '%'
          AND g.DELETED_ON IS NULL
    );
    
    IF (v_revoke_sra IS NOT NULL) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_revoke_sra) - 1 DO
            v_remediation_statements := ARRAY_APPEND(v_remediation_statements,
                OBJECT_CONSTRUCT('type', 'REVOKE_SRA_FROM_SERVICE', 'sql', v_revoke_sra[i]));
        END FOR;
    END IF;

    -- Generate REVOKE statements for PERSON accounts with SRW_* roles
    LET v_revoke_srw ARRAY := (
        SELECT ARRAY_AGG(
            'REVOKE ROLE ' || g.ROLE || ' FROM USER ' || u.NAME || ';'
        )
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.NAME = g.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND (u.TYPE = 'PERSON' OR u.TYPE IS NULL)
          AND g.ROLE LIKE 'SRW' || :v_env_filter || '%'
          AND g.DELETED_ON IS NULL
    );
    
    IF (v_revoke_srw IS NOT NULL) THEN
        FOR i IN 0 TO ARRAY_SIZE(v_revoke_srw) - 1 DO
            v_remediation_statements := ARRAY_APPEND(v_remediation_statements,
                OBJECT_CONSTRUCT('type', 'REVOKE_SRW_FROM_PERSON', 'sql', v_revoke_srw[i]));
        END FOR;
    END IF;

    -- Return results
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment_filter', COALESCE(P_ENVIRONMENT, 'ALL'),
        'statement_count', ARRAY_SIZE(v_remediation_statements),
        'remediation_statements', v_remediation_statements,
        'warning', 'Review statements before execution. You may need to create appropriate SRW_* roles for service accounts first.',
        'generated_at', CURRENT_TIMESTAMP()
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE
        );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List User Role Summary
 * 
 * Purpose: Provides a summary of role assignments for a specific user
 * 
 * Parameters:
 *   P_USER_NAME - Username to analyze
 * 
 * Returns: VARIANT containing user's role assignments and compliance status
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE RBAC_GET_USER_ROLE_SUMMARY(
    P_USER_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_user_type VARCHAR;
    v_srs_roles ARRAY;
    v_srf_roles ARRAY;
    v_sra_roles ARRAY;
    v_srw_roles ARRAY;
    v_other_roles ARRAY;
    v_is_compliant BOOLEAN := TRUE;
    v_compliance_issues ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Get user type
    v_user_type := (
        SELECT COALESCE(TYPE, 'PERSON')
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE NAME = :P_USER_NAME
          AND DELETED_ON IS NULL
    );
    
    IF (v_user_type IS NULL) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'User not found',
            'user_name', P_USER_NAME
        );
    END IF;

    -- Get SRS roles
    v_srs_roles := (
        SELECT ARRAY_AGG(ROLE)
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE GRANTEE_NAME = :P_USER_NAME
          AND ROLE LIKE 'SRS_%'
          AND DELETED_ON IS NULL
    );

    -- Get SRF roles
    v_srf_roles := (
        SELECT ARRAY_AGG(ROLE)
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE GRANTEE_NAME = :P_USER_NAME
          AND ROLE LIKE 'SRF_%'
          AND DELETED_ON IS NULL
    );

    -- Get SRA roles
    v_sra_roles := (
        SELECT ARRAY_AGG(ROLE)
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE GRANTEE_NAME = :P_USER_NAME
          AND ROLE LIKE 'SRA_%'
          AND DELETED_ON IS NULL
    );

    -- Get SRW roles
    v_srw_roles := (
        SELECT ARRAY_AGG(ROLE)
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE GRANTEE_NAME = :P_USER_NAME
          AND ROLE LIKE 'SRW_%'
          AND DELETED_ON IS NULL
    );

    -- Get other roles
    v_other_roles := (
        SELECT ARRAY_AGG(ROLE)
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE GRANTEE_NAME = :P_USER_NAME
          AND ROLE NOT LIKE 'SRS_%'
          AND ROLE NOT LIKE 'SRF_%'
          AND ROLE NOT LIKE 'SRA_%'
          AND ROLE NOT LIKE 'SRW_%'
          AND DELETED_ON IS NULL
    );

    -- Check compliance based on user type
    IF (v_user_type IN ('SERVICE', 'LEGACY_SERVICE')) THEN
        -- Service accounts should NOT have SRF_* or SRA_* roles
        IF (v_srf_roles IS NOT NULL AND ARRAY_SIZE(v_srf_roles) > 0) THEN
            v_is_compliant := FALSE;
            v_compliance_issues := ARRAY_APPEND(v_compliance_issues,
                'Service account has SRF_* functional roles (should use SRW_* instead)');
        END IF;
        IF (v_sra_roles IS NOT NULL AND ARRAY_SIZE(v_sra_roles) > 0) THEN
            v_is_compliant := FALSE;
            v_compliance_issues := ARRAY_APPEND(v_compliance_issues,
                'Service account has SRA_* access roles (should use SRW_* instead)');
        END IF;
        IF (v_srw_roles IS NULL OR ARRAY_SIZE(v_srw_roles) = 0) THEN
            v_compliance_issues := ARRAY_APPEND(v_compliance_issues,
                'Service account has no SRW_* wrapper role assigned');
        END IF;
    ELSE
        -- Person accounts should NOT have SRW_* roles
        IF (v_srw_roles IS NOT NULL AND ARRAY_SIZE(v_srw_roles) > 0) THEN
            v_is_compliant := FALSE;
            v_compliance_issues := ARRAY_APPEND(v_compliance_issues,
                'Person account has SRW_* service roles (should use SRF_* and SRA_* instead)');
        END IF;
    END IF;

    -- Return results
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'user_name', P_USER_NAME,
        'user_type', v_user_type,
        'is_compliant', v_is_compliant,
        'compliance_issues', v_compliance_issues,
        'roles', OBJECT_CONSTRUCT(
            'system_roles', COALESCE(v_srs_roles, ARRAY_CONSTRUCT()),
            'functional_roles', COALESCE(v_srf_roles, ARRAY_CONSTRUCT()),
            'access_roles', COALESCE(v_sra_roles, ARRAY_CONSTRUCT()),
            'service_wrapper_roles', COALESCE(v_srw_roles, ARRAY_CONSTRUCT()),
            'other_roles', COALESCE(v_other_roles, ARRAY_CONSTRUCT())
        ),
        'expected_role_types', IFF(v_user_type IN ('SERVICE', 'LEGACY_SERVICE'),
            'SRW_* (service wrapper roles only)',
            'SRF_* (functional) + SRA_* (access)')
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'user_name', P_USER_NAME
        );
END;
$$;

-- Grant execute permissions
GRANT USAGE ON PROCEDURE RBAC_AUDIT_USER_ROLES(VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_AUDIT_USER_ROLES(VARCHAR, BOOLEAN) TO ROLE SRS_ACCOUNT_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_GENERATE_REMEDIATION_SCRIPT(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_GET_USER_ROLE_SUMMARY(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_GET_USER_ROLE_SUMMARY(VARCHAR) TO ROLE SRS_USER_ADMIN;
