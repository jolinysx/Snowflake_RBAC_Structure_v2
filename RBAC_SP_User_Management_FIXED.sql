-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_CREATE_SERVICE_ACCOUNT
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_SERVICE_ACCOUNT(
    P_ACCOUNT_NAME VARCHAR,
    P_RSA_PUBLIC_KEY VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN VARCHAR,
    P_CAPABILITY_LEVEL VARCHAR,
    P_DEFAULT_WAREHOUSE VARCHAR,
    P_COMMENT VARCHAR DEFAULT 'Service account',
    P_RSA_PUBLIC_KEY_2 VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_service_role VARCHAR;
    v_sql VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
    v_account_exists BOOLEAN;
    v_role_exists BOOLEAN;
BEGIN
    IF P_ACCOUNT_NAME IS NULL OR LENGTH(P_ACCOUNT_NAME) < 3 THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid account name. Must be at least 3 characters.',
            'recommendation', 'Use naming convention: SVC_<APPLICATION>_<PURPOSE>'
        );
    END IF;
    
    IF P_RSA_PUBLIC_KEY IS NULL OR LENGTH(P_RSA_PUBLIC_KEY) < 100 THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'RSA public key is required for service accounts.',
            'hint', 'Generate key pair using: openssl genrsa -out rsa_key.p8 2048'
        );
    END IF;
    
    IF P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD'
        );
    END IF;
    
    IF P_CAPABILITY_LEVEL NOT IN ('END_USER', 'ANALYST', 'DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST', 'DBADMIN') THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid capability level. Must be one of: END_USER, ANALYST, DEVELOPER, TEAM_LEADER, DATA_SCIENTIST, DBADMIN'
        );
    END IF;
    
    SELECT COUNT(*) > 0 INTO :v_account_exists
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
    WHERE NAME = UPPER(:P_ACCOUNT_NAME)
      AND DELETED_ON IS NULL;
    
    IF v_account_exists THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Account already exists',
            'account_name', P_ACCOUNT_NAME,
            'hint', 'Use RBAC_GRANT_SERVICE_ACCOUNT to assign roles to existing accounts'
        );
    END IF;
    
    v_service_role := 'SRW_' || P_ENVIRONMENT || '_' || UPPER(P_DOMAIN) || '_' || P_CAPABILITY_LEVEL;
    
    SELECT COUNT(*) > 0 INTO :v_role_exists
    FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
    WHERE NAME = :v_service_role
      AND DELETED_ON IS NULL;
    
    IF NOT v_role_exists THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Service wrapper role does not exist. Create it first.',
            'required_role', v_service_role,
            'hint', 'Run RBAC_CREATE_SERVICE_ROLE(''' || P_ENVIRONMENT || ''', ''' || P_DOMAIN || ''', ''' || P_CAPABILITY_LEVEL || ''', ''description'')'
        );
    END IF;

    IF P_RSA_PUBLIC_KEY_2 IS NOT NULL THEN
        v_sql := 'CREATE USER ' || P_ACCOUNT_NAME ||
                 ' TYPE = SERVICE' ||
                 ' RSA_PUBLIC_KEY = ''' || P_RSA_PUBLIC_KEY || '''' ||
                 ' RSA_PUBLIC_KEY_2 = ''' || P_RSA_PUBLIC_KEY_2 || '''' ||
                 ' DEFAULT_ROLE = ''' || v_service_role || '''' ||
                 ' DEFAULT_WAREHOUSE = ''' || P_DEFAULT_WAREHOUSE || '''' ||
                 ' COMMENT = ''' || P_COMMENT || '''';
    ELSE
        v_sql := 'CREATE USER ' || P_ACCOUNT_NAME ||
                 ' TYPE = SERVICE' ||
                 ' RSA_PUBLIC_KEY = ''' || P_RSA_PUBLIC_KEY || '''' ||
                 ' DEFAULT_ROLE = ''' || v_service_role || '''' ||
                 ' DEFAULT_WAREHOUSE = ''' || P_DEFAULT_WAREHOUSE || '''' ||
                 ' COMMENT = ''' || P_COMMENT || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'CREATE_SERVICE_ACCOUNT',
        'account', P_ACCOUNT_NAME,
        'status', 'SUCCESS'
    ));
    
    v_sql := 'GRANT ROLE ' || v_service_role || ' TO USER ' || P_ACCOUNT_NAME;
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'GRANT_SERVICE_ROLE',
        'role', v_service_role,
        'status', 'SUCCESS'
    ));
    
    v_sql := 'GRANT USAGE ON WAREHOUSE ' || P_DEFAULT_WAREHOUSE || ' TO ROLE ' || v_service_role;
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'GRANT_WAREHOUSE_USAGE',
            'warehouse', P_DEFAULT_WAREHOUSE,
            'status', 'SUCCESS'
        ));
    EXCEPTION
        WHEN OTHER THEN
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'action', 'GRANT_WAREHOUSE_USAGE',
                'warehouse', P_DEFAULT_WAREHOUSE,
                'status', 'ALREADY_GRANTED_OR_ERROR',
                'note', SQLERRM
            ));
    END;

    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'account_name', P_ACCOUNT_NAME,
        'account_type', 'SERVICE',
        'environment', P_ENVIRONMENT,
        'domain', P_DOMAIN,
        'capability_level', P_CAPABILITY_LEVEL,
        'service_role', v_service_role,
        'default_warehouse', P_DEFAULT_WAREHOUSE,
        'authentication', 'RSA_KEY_PAIR',
        'has_backup_key', (P_RSA_PUBLIC_KEY_2 IS NOT NULL),
        'actions', v_actions,
        'connection_info', OBJECT_CONSTRUCT(
            'authenticator', 'SNOWFLAKE_JWT',
            'account', CURRENT_ACCOUNT(),
            'user', P_ACCOUNT_NAME,
            'role', v_service_role,
            'warehouse', P_DEFAULT_WAREHOUSE
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'account_name', P_ACCOUNT_NAME,
            'actions_attempted', v_actions
        );
END;
$$;
