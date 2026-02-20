/*******************************************************************************
 * RBAC STORED PROCEDURE: Dynamic Schema Creation
 * 
 * Purpose: Creates database (if not existing), schema, database roles, and
 *          configures all RBAC privileges according to the standard configuration
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     PROCEDURE
 *   Object Name:     ADMIN.RBAC.RBAC_CREATE_SCHEMA
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the procedure)
 *   Execution Role:  SRF_<ENV>_DBADMIN (caller must have this role)
 * 
 *   Dependencies:    
 *     - ADMIN database must exist
 *     - ADMIN.RBAC schema must exist
 *     - SRF_*_DBADMIN, SRF_*_DEVELOPER, SRF_*_END_USER roles must exist
 *     - SRS_DEVOPS role must exist
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * PARAMETERS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   P_ENVIRONMENT     - Environment code: DEV, TST, UAT, PPE, PRD
 *   P_DATABASE_NAME   - Name of the database (without environment suffix)
 *   P_SCHEMA_NAME     - Name of the schema to create
 *   P_SCHEMA_COMMENT  - Description/comment for the schema
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * NOTE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   This procedure creates database roles (SRD_*) but does NOT link them
 *   to functional roles. Database roles should be linked to Access Roles
 *   (SRA_*) using RBAC_LINK_SCHEMA_TO_ACCESS_ROLE procedure.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * USAGE EXAMPLES
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   USE ROLE SRF_DEV_DBADMIN;
 *   CALL ADMIN.RBAC.RBAC_CREATE_SCHEMA('DEV', 'HR', 'EMPLOYEES', 'Employee data');
 *   
 *   USE ROLE SRF_PRD_DBADMIN;
 *   CALL ADMIN.RBAC.RBAC_CREATE_SCHEMA('PRD', 'SALES', 'ORDERS', 'Sales order data');
 * 
 *   -- Post-Execution: Link to an access role
 *   USE ROLE SRS_SECURITY_ADMIN;
 *   CALL ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE('DEV', 'HR', 'HR', 'EMPLOYEES', 'WRITE');
 * 
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- =============================================================================
-- PROCEDURE: ADMIN.RBAC.RBAC_CREATE_SCHEMA
-- =============================================================================

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_SCHEMA(
    P_ENVIRONMENT VARCHAR,
    P_DATABASE_NAME VARCHAR,
    P_SCHEMA_NAME VARCHAR,
    P_SCHEMA_COMMENT VARCHAR DEFAULT 'Schema created via RBAC automation'
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
    v_security_admin_role VARCHAR := 'SRS_SECURITY_ADMIN';
    v_read_db_role VARCHAR;
    v_write_db_role VARCHAR;
    v_is_dev BOOLEAN;
    v_object_owner_role VARCHAR;
    v_result VARIANT;
    v_steps ARRAY := ARRAY_CONSTRUCT();
    v_sql VARCHAR;
BEGIN
    -- Validate environment
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid environment. Must be one of: DEV, TST, UAT, PPE, PRD',
            'environment_provided', P_ENVIRONMENT
        );
    END IF;
    
    -- Derive role and object names
    v_full_db_name := P_DATABASE_NAME || '_' || P_ENVIRONMENT;
    v_dbadmin_role := 'SRF_' || P_ENVIRONMENT || '_DBADMIN';
    v_developer_role := 'SRF_' || P_ENVIRONMENT || '_DEVELOPER';
    v_end_user_role := 'SRF_' || P_ENVIRONMENT || '_END_USER';
    v_read_db_role := 'SRD_' || v_full_db_name || '_' || P_SCHEMA_NAME || '_READ';
    v_write_db_role := 'SRD_' || v_full_db_name || '_' || P_SCHEMA_NAME || '_WRITE';
    v_is_dev := (P_ENVIRONMENT = 'DEV');
    
    -- Determine object owner based on environment
    IF (v_is_dev) THEN
        v_object_owner_role := v_developer_role;
    ELSE
        v_object_owner_role := v_devops_role;
    END IF;
    
    -- =========================================================================
    -- STEP 1: Create Database (if not exists)
    -- =========================================================================
    v_sql := 'CREATE DATABASE IF NOT EXISTS ' || v_full_db_name || 
             ' COMMENT = ''Database for ' || P_ENVIRONMENT || ' environment''';
    EXECUTE IMMEDIATE v_sql;
    v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Create Database', 'sql', v_sql, 'status', 'SUCCESS'));
    
    -- =========================================================================
    -- STEP 2: Create Schema with Managed Access
    -- =========================================================================
    v_sql := 'CREATE SCHEMA IF NOT EXISTS ' || v_full_db_name || '.' || P_SCHEMA_NAME ||
             ' WITH MANAGED ACCESS COMMENT = ''' || P_SCHEMA_COMMENT || '''';
    EXECUTE IMMEDIATE v_sql;
    v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Create Schema', 'sql', v_sql, 'status', 'SUCCESS'));
    
    -- =========================================================================
    -- STEP 3: Create Database Roles
    -- =========================================================================
    EXECUTE IMMEDIATE 'USE DATABASE ' || v_full_db_name;
    
    v_sql := 'CREATE DATABASE ROLE IF NOT EXISTS ' || v_read_db_role ||
             ' COMMENT = ''Database role: READ access on ' || v_full_db_name || '.' || P_SCHEMA_NAME || '''';
    EXECUTE IMMEDIATE v_sql;
    v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Create READ Database Role', 'sql', v_sql, 'status', 'SUCCESS'));
    
    IF (v_is_dev) THEN
        v_sql := 'CREATE DATABASE ROLE IF NOT EXISTS ' || v_write_db_role ||
                 ' COMMENT = ''Database role: WRITE access on ' || v_full_db_name || '.' || P_SCHEMA_NAME || '''';
        EXECUTE IMMEDIATE v_sql;
        v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Create WRITE Database Role', 'sql', v_sql, 'status', 'SUCCESS'));
    END IF;
    
    -- =========================================================================
    -- STEP 4: Grant READ Privileges to READ Database Role
    -- =========================================================================
    EXECUTE IMMEDIATE 'GRANT USAGE ON SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON ALL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON ALL VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON ALL MATERIALIZED VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE MATERIALIZED VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON ALL DYNAMIC TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE DYNAMIC TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON ALL EXTERNAL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE EXTERNAL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON ALL STREAMS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE STREAMS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT USAGE ON ALL FUNCTIONS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT USAGE ON FUTURE FUNCTIONS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT USAGE ON ALL SEQUENCES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT USAGE ON FUTURE SEQUENCES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT USAGE ON ALL FILE FORMATS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT USAGE ON FUTURE FILE FORMATS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT READ ON ALL STAGES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    EXECUTE IMMEDIATE 'GRANT READ ON FUTURE STAGES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_read_db_role;
    
    v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Grant READ Privileges', 'status', 'SUCCESS'));
    
    -- =========================================================================
    -- STEP 5: Grant WRITE Privileges (DEV only)
    -- =========================================================================
    IF (v_is_dev) THEN
        EXECUTE IMMEDIATE 'GRANT USAGE ON SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON FUTURE TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT REFERENCES ON ALL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT REFERENCES ON FUTURE TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT, INSERT, UPDATE, DELETE ON FUTURE VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT ON ALL MATERIALIZED VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE MATERIALIZED VIEWS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT ON ALL DYNAMIC TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE DYNAMIC TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT ON ALL EXTERNAL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE EXTERNAL TABLES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT ON ALL STREAMS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT SELECT ON FUTURE STREAMS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON ALL FUNCTIONS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON FUTURE FUNCTIONS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON ALL PROCEDURES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON ALL SEQUENCES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON FUTURE SEQUENCES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON ALL FILE FORMATS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON FUTURE FILE FORMATS IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT READ, WRITE ON ALL STAGES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        EXECUTE IMMEDIATE 'GRANT READ, WRITE ON FUTURE STAGES IN SCHEMA ' || P_SCHEMA_NAME || ' TO DATABASE ROLE ' || v_write_db_role;
        
        v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Grant WRITE Privileges', 'status', 'SUCCESS'));
    END IF;
    
    -- =========================================================================
    -- STEP 6: Database roles created - ready for Access Role linking
    -- =========================================================================
    v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT(
        'step', 'Database Roles Ready',
        'note', 'Link to Access Roles using ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE',
        'read_role', v_read_db_role,
        'write_role', IFF(v_is_dev, v_write_db_role, 'N/A'),
        'status', 'SUCCESS'
    ));
    
    -- =========================================================================
    -- STEP 7: Object Ownership Transfer
    -- =========================================================================
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL TABLES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL VIEWS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL MATERIALIZED VIEWS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL DYNAMIC TABLES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL EXTERNAL TABLES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL FUNCTIONS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL PROCEDURES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL SEQUENCES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL STAGES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL FILE FORMATS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL STREAMS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL TASKS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON ALL PIPES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role || ' COPY CURRENT GRANTS';
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE TABLES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE VIEWS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE MATERIALIZED VIEWS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE DYNAMIC TABLES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE EXTERNAL TABLES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE FUNCTIONS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE PROCEDURES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE SEQUENCES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE STAGES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE FILE FORMATS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE STREAMS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE TASKS IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    EXECUTE IMMEDIATE 'GRANT OWNERSHIP ON FUTURE PIPES IN SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_object_owner_role;
    
    v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Object Ownership Transfer', 'owner_role', v_object_owner_role, 'status', 'SUCCESS'));
    
    -- =========================================================================
    -- STEP 8: Grant CREATE privileges (DEV: DEVELOPER, Non-DEV: SRS_DEVOPS)
    -- =========================================================================
    IF (v_is_dev) THEN
        EXECUTE IMMEDIATE 'GRANT CREATE TABLE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE VIEW ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE MATERIALIZED VIEW ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE DYNAMIC TABLE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE EXTERNAL TABLE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE FUNCTION ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE PROCEDURE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE SEQUENCE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE STAGE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE FILE FORMAT ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE STREAM ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE TASK ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE PIPE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        EXECUTE IMMEDIATE 'GRANT CREATE TAG ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_developer_role;
        
        v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Grant CREATE to DEVELOPER', 'status', 'SUCCESS'));
    ELSE
        EXECUTE IMMEDIATE 'GRANT USAGE ON DATABASE ' || v_full_db_name || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT USAGE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE TABLE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE VIEW ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE MATERIALIZED VIEW ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE DYNAMIC TABLE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE EXTERNAL TABLE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE FUNCTION ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE PROCEDURE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE SEQUENCE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE STAGE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE FILE FORMAT ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE STREAM ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE TASK ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE PIPE ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        EXECUTE IMMEDIATE 'GRANT CREATE TAG ON SCHEMA ' || v_full_db_name || '.' || P_SCHEMA_NAME || ' TO ROLE ' || v_devops_role;
        
        v_steps := ARRAY_APPEND(v_steps, OBJECT_CONSTRUCT('step', 'Grant CREATE to SRS_DEVOPS', 'status', 'SUCCESS'));
    END IF;
    
    -- =========================================================================
    -- Return Success Result
    -- =========================================================================
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'environment', P_ENVIRONMENT,
        'database', v_full_db_name,
        'schema', P_SCHEMA_NAME,
        'database_roles', OBJECT_CONSTRUCT(
            'read', v_read_db_role,
            'write', IFF(v_is_dev, v_write_db_role, 'N/A - Non-DEV environment')
        ),
        'object_owner', v_object_owner_role,
        'schema_owner', v_dbadmin_role,
        'is_managed_access', TRUE,
        'next_step', 'Link database roles to access role using ADMIN.RBAC.RBAC_LINK_SCHEMA_TO_ACCESS_ROLE',
        'steps', v_steps
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
            'steps_completed', v_steps
        );
END;
$$;

-- =============================================================================
-- GRANTS: Procedure Execution Permissions
-- =============================================================================

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_SCHEMA(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_DEV_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_SCHEMA(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_TST_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_SCHEMA(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_UAT_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_SCHEMA(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_PPE_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_SCHEMA(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRF_PRD_DBADMIN;

-- =============================================================================
-- VERIFICATION
-- =============================================================================
-- After deployment, verify the procedure exists:
--   SHOW PROCEDURES LIKE 'RBAC_CREATE_SCHEMA' IN SCHEMA ADMIN.RBAC;
--   DESCRIBE PROCEDURE ADMIN.RBAC.RBAC_CREATE_SCHEMA(VARCHAR, VARCHAR, VARCHAR, VARCHAR);
-- =============================================================================
