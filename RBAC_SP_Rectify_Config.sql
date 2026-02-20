/*******************************************************************************
 * RBAC STORED PROCEDURE: Rectify RBAC Configuration
 * 
 * Purpose: Automatically fix RBAC configuration drift and misalignments
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
 *     - RBAC_SP_Monitor_Config.sql must be deployed first
 * 
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Rectify RBAC Configuration
 * 
 * Purpose: Analyzes current RBAC configuration and corrects any deviations
 *          from the standard configuration for a given schema
 * 
 * NOTE: This procedure fixes database role configuration but does NOT
 *       automatically link database roles to access roles. Use
 *       RBAC_LINK_SCHEMA_TO_ACCESS_ROLE for access role linkage.
 * 
 * Parameters:
 *   P_ENVIRONMENT     - Environment code: DEV, TST, UAT, PPE, PRD
 *   P_DATABASE_NAME   - Name of the database (without environment suffix)
 *   P_SCHEMA_NAME     - Name of the schema to rectify
 *   P_DRY_RUN         - If TRUE, only reports what would be changed (default: TRUE)
 * 
 * Returns: VARIANT containing actions taken or proposed
 * 
 * Execution Role: SRF_<ENV>_DBADMIN (must have MANAGE GRANTS on schema)
 * 
 * Usage Examples:
 *   -- Preview changes (dry run)
 *   CALL RBAC_RECTIFY_CONFIG('DEV', 'HR', 'EMPLOYEES', TRUE);
 *   
 *   -- Apply changes
 *   CALL RBAC_RECTIFY_CONFIG('PRD', 'SALES', 'ORDERS', FALSE);
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_RECTIFY_CONFIG(
    P_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR,
    P_DRY_RUN BOOLEAN DEFAULT TRUE
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
    v_read_db_role VARCHAR;
    v_write_db_role VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
    v_errors ARRAY := ARRAY_CONSTRUCT();
    v_action_count INTEGER := 0;
    v_sql VARCHAR;
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
    v_read_db_role := 'SRD_' || v_full_db_name || '_' || P_SCHEMA_NAME || '_READ';
    v_write_db_role := 'SRD_' || v_full_db_name || '_' || P_SCHEMA_NAME || '_WRITE';
    v_is_dev := (P_ENVIRONMENT = 'DEV');
    v_object_owner_role := IFF(v_is_dev, v_developer_role, v_devops_role);
    
    -- Verify database and schema exist
    LET v_schema_exists BOOLEAN := (
        SELECT COUNT(*) > 0
        FROM INFORMATION_SCHEMA.SCHEMATA
        WHERE CATALOG_NAME = :v_full_db_name AND SCHEMA_NAME = :P_SCHEMA_NAME
    );
    
    IF (NOT v_schema_exists) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Schema does not exist',
            'database', v_full_db_name,
            'schema', P_SCHEMA_NAME
        );
    END IF;
    
    EXECUTE IMMEDIATE 'USE DATABASE ' || v_full_db_name;
    
    -- =========================================================================
    -- RECTIFICATION 1: Enable Managed Access on Schema
    -- =========================================================================
    LET v_is_managed BOOLEAN := (
        SELECT IS_MANAGED_ACCESS = 'YES'
        FROM INFORMATION_SCHEMA.SCHEMATA
        WHERE CATALOG_NAME = :v_full_db_name AND SCHEMA_NAME = :P_SCHEMA_NAME
    );
    
    IF (NOT v_is_managed) THEN
        v_sql := 'ALTER SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' ENABLE MANAGED ACCESS';
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'ENABLE_MANAGED_ACCESS',
            'sql', v_sql,
            'status', IFF(P_DRY_RUN, 'PENDING', 'EXECUTING')
        ));
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
                v_action_count := v_action_count + 1;
                v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                    'action', 'ENABLE_MANAGED_ACCESS',
                    'sql', v_sql,
                    'status', 'SUCCESS'
                ));
            EXCEPTION
                WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT(
                        'action', 'ENABLE_MANAGED_ACCESS',
                        'sql', v_sql,
                        'error', SQLERRM
                    ));
            END;
        END IF;
    END IF;
    
    -- =========================================================================
    -- RECTIFICATION 2: Create Missing Database Roles
    -- =========================================================================
    -- Check and create READ role
    LET v_read_role_exists BOOLEAN := (
        SELECT COUNT(*) > 0
        FROM INFORMATION_SCHEMA.DATABASE_ROLES
        WHERE NAME = :v_read_db_role
    );
    
    IF (NOT v_read_role_exists) THEN
        v_sql := 'CREATE DATABASE ROLE ' || v_read_db_role || 
                 ' COMMENT = ''Database role: READ access on ' || v_full_db_name || '.' || P_SCHEMA_NAME || '''';
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'CREATE_READ_DATABASE_ROLE',
            'sql', v_sql,
            'status', IFF(P_DRY_RUN, 'PENDING', 'EXECUTING')
        ));
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
                v_action_count := v_action_count + 1;
                v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                    'action', 'CREATE_READ_DATABASE_ROLE',
                    'sql', v_sql,
                    'status', 'SUCCESS'
                ));
            EXCEPTION
                WHEN OTHER THEN
                    v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT(
                        'action', 'CREATE_READ_DATABASE_ROLE',
                        'sql', v_sql,
                        'error', SQLERRM
                    ));
            END;
        END IF;
    END IF;
    
    -- Check and create WRITE role (DEV only)
    IF (v_is_dev) THEN
        LET v_write_role_exists BOOLEAN := (
            SELECT COUNT(*) > 0
            FROM INFORMATION_SCHEMA.DATABASE_ROLES
            WHERE NAME = :v_write_db_role
        );
        
        IF (NOT v_write_role_exists) THEN
            v_sql := 'CREATE DATABASE ROLE ' || v_write_db_role ||
                     ' COMMENT = ''Database role: WRITE access on ' || v_full_db_name || '.' || P_SCHEMA_NAME || '''';
            v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                'action', 'CREATE_WRITE_DATABASE_ROLE',
                'sql', v_sql,
                'status', IFF(P_DRY_RUN, 'PENDING', 'EXECUTING')
            ));
            
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                    v_action_count := v_action_count + 1;
                    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                        'action', 'CREATE_WRITE_DATABASE_ROLE',
                        'sql', v_sql,
                        'status', 'SUCCESS'
                    ));
                EXCEPTION
                    WHEN OTHER THEN
                        v_errors := ARRAY_APPEND(v_errors, OBJECT_CONSTRUCT(
                            'action', 'CREATE_WRITE_DATABASE_ROLE',
                            'sql', v_sql,
                            'error', SQLERRM
                        ));
                END;
            END IF;
        END IF;
    END IF;
    
    -- =========================================================================
    -- RECTIFICATION 3: Grant Privileges to Database Roles
    -- =========================================================================
    -- READ privileges
    LET v_read_privileges ARRAY := ARRAY_CONSTRUCT(
        'GRANT USAGE ON SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON ALL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON FUTURE TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON ALL VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON FUTURE VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON ALL MATERIALIZED VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON FUTURE MATERIALIZED VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON ALL DYNAMIC TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON FUTURE DYNAMIC TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT USAGE ON ALL FUNCTIONS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT USAGE ON FUTURE FUNCTIONS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT READ ON ALL STAGES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT READ ON FUTURE STAGES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT USAGE ON ALL FILE FORMATS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT USAGE ON FUTURE FILE FORMATS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON ALL STREAMS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role,
        'GRANT SELECT ON FUTURE STREAMS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_read_privileges) - 1 DO
        v_sql := v_read_privileges[i];
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    NULL; -- Ignore if already granted
            END;
        END IF;
    END FOR;
    
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'GRANT_READ_PRIVILEGES',
        'statements', ARRAY_SIZE(v_read_privileges),
        'status', IFF(P_DRY_RUN, 'PENDING', 'SUCCESS')
    ));
    
    -- WRITE privileges (DEV only)
    IF (v_is_dev) THEN
        LET v_write_privileges ARRAY := ARRAY_CONSTRUCT(
            'GRANT USAGE ON SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role,
            'GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role,
            'GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON FUTURE TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role,
            'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role,
            'GRANT SELECT, INSERT, UPDATE, DELETE ON FUTURE VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role,
            'GRANT READ, WRITE ON ALL STAGES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role,
            'GRANT READ, WRITE ON FUTURE STAGES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role
        );
        
        FOR i IN 0 TO ARRAY_SIZE(v_write_privileges) - 1 DO
            v_sql := v_write_privileges[i];
            IF (NOT P_DRY_RUN) THEN
                BEGIN
                    EXECUTE IMMEDIATE v_sql;
                EXCEPTION
                    WHEN OTHER THEN
                        NULL; -- Ignore if already granted
                END;
            END IF;
        END FOR;
        
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'GRANT_WRITE_PRIVILEGES',
            'statements', ARRAY_SIZE(v_write_privileges),
            'status', IFF(P_DRY_RUN, 'PENDING', 'SUCCESS')
        ));
    END IF;
    
    -- =========================================================================
    -- RECTIFICATION 4: Database Roles Ready for Access Role Linking
    -- NOTE: Database roles are NOT linked to functional roles directly.
    -- They should be linked to Access Roles (SRA_*) using 
    -- RBAC_LINK_SCHEMA_TO_ACCESS_ROLE procedure.
    -- =========================================================================
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'DATABASE_ROLES_READY',
        'read_role', v_read_db_role,
        'write_role', IFF(v_is_dev, v_write_db_role, 'N/A'),
        'note', 'Link to Access Roles using RBAC_LINK_SCHEMA_TO_ACCESS_ROLE',
        'status', 'INFO'
    ));
    
    -- =========================================================================
    -- RECTIFICATION 5: Fix Object Ownership
    -- =========================================================================
    LET v_object_types ARRAY := ARRAY_CONSTRUCT(
        'TABLES', 'VIEWS', 'MATERIALIZED VIEWS', 'DYNAMIC TABLES', 'EXTERNAL TABLES',
        'FUNCTIONS', 'PROCEDURES', 'SEQUENCES', 'STAGES', 'FILE FORMATS',
        'STREAMS', 'TASKS', 'PIPES'
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_object_types) - 1 DO
        LET v_obj_type VARCHAR := v_object_types[i];
        v_sql := 'GRANT OWNERSHIP ON ALL ' || v_obj_type || ' IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME ||
                 ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    NULL; -- Object type may not have any objects
            END;
        END IF;
    END FOR;
    
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'TRANSFER_EXISTING_OWNERSHIP',
        'target_role', v_object_owner_role,
        'status', IFF(P_DRY_RUN, 'PENDING', 'SUCCESS')
    ));
    
    -- =========================================================================
    -- RECTIFICATION 6: Configure Future Ownership
    -- =========================================================================
    LET v_future_types ARRAY := ARRAY_CONSTRUCT(
        'TABLES', 'VIEWS', 'MATERIALIZED VIEWS', 'DYNAMIC TABLES', 'EXTERNAL TABLES',
        'FUNCTIONS', 'PROCEDURES', 'SEQUENCES', 'STAGES', 'FILE FORMATS',
        'STREAMS', 'TASKS', 'PIPES'
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_future_types) - 1 DO
        LET v_future_type VARCHAR := v_future_types[i];
        v_sql := 'GRANT OWNERSHIP ON FUTURE ' || v_future_type || ' IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME ||
                 ' TO ROLE ' || v_object_owner_role;
        
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    NULL; -- May already be configured
            END;
        END IF;
    END FOR;
    
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'CONFIGURE_FUTURE_OWNERSHIP',
        'target_role', v_object_owner_role,
        'status', IFF(P_DRY_RUN, 'PENDING', 'SUCCESS')
    ));
    
    -- =========================================================================
    -- RECTIFICATION 7: Grant CREATE Privileges
    -- =========================================================================
    LET v_create_role VARCHAR := IFF(v_is_dev, v_developer_role, v_devops_role);
    LET v_create_privileges ARRAY := ARRAY_CONSTRUCT(
        'GRANT CREATE TABLE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE VIEW ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE MATERIALIZED VIEW ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE DYNAMIC TABLE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE FUNCTION ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE PROCEDURE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE SEQUENCE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE STAGE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE FILE FORMAT ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE STREAM ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE TASK ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role,
        'GRANT CREATE PIPE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_create_role
    );
    
    FOR i IN 0 TO ARRAY_SIZE(v_create_privileges) - 1 DO
        v_sql := v_create_privileges[i];
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN
                    NULL;
            END;
        END IF;
    END FOR;
    
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
        'action', 'GRANT_CREATE_PRIVILEGES',
        'target_role', v_create_role,
        'statements', ARRAY_SIZE(v_create_privileges),
        'status', IFF(P_DRY_RUN, 'PENDING', 'SUCCESS')
    ));
    
    -- =========================================================================
    -- RECTIFICATION 8: Non-DEV specific - Grant USAGE to SRS_DEVOPS
    -- =========================================================================
    IF (NOT v_is_dev) THEN
        v_sql := 'GRANT USAGE ON DATABASE ' || v_full_db_name || ' TO ROLE ' || v_devops_role;
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN NULL;
            END;
        END IF;
        
        v_sql := 'GRANT USAGE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                EXECUTE IMMEDIATE v_sql;
            EXCEPTION
                WHEN OTHER THEN NULL;
            END;
        END IF;
        
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'GRANT_USAGE_TO_DEVOPS',
            'target_role', v_devops_role,
            'status', IFF(P_DRY_RUN, 'PENDING', 'SUCCESS')
        ));
    END IF;
    
    -- =========================================================================
    -- Return Results
    -- =========================================================================
    RETURN OBJECT_CONSTRUCT(
        'status', IFF(ARRAY_SIZE(v_errors) = 0, 'SUCCESS', 'PARTIAL_SUCCESS'),
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'APPLIED'),
        'environment', P_ENVIRONMENT,
        'database', v_full_db_name,
        'schema', P_SCHEMA_NAME,
        'is_dev_environment', v_is_dev,
        'object_owner', v_object_owner_role,
        'create_role', IFF(v_is_dev, v_developer_role, v_devops_role),
        'database_roles', OBJECT_CONSTRUCT(
            'read', v_read_db_role,
            'write', IFF(v_is_dev, v_write_db_role, 'N/A')
        ),
        'actions', v_actions,
        'errors', v_errors,
        'timestamp', CURRENT_TIMESTAMP()
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'environment', P_ENVIRONMENT,
            'database', v_full_db_name,
            'schema', P_SCHEMA_NAME,
            'actions_attempted', v_actions
        );
END;
$$;

-- Grant execute to DBADMIN roles
GRANT USAGE ON PROCEDURE RBAC_RECTIFY_CONFIG(VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRF_DEV_DBADMIN;
GRANT USAGE ON PROCEDURE RBAC_RECTIFY_CONFIG(VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRF_TST_DBADMIN;
GRANT USAGE ON PROCEDURE RBAC_RECTIFY_CONFIG(VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRF_UAT_DBADMIN;
GRANT USAGE ON PROCEDURE RBAC_RECTIFY_CONFIG(VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRF_PPE_DBADMIN;
GRANT USAGE ON PROCEDURE RBAC_RECTIFY_CONFIG(VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRF_PRD_DBADMIN;
