/*******************************************************************************
 * RBAC STORED PROCEDURE: Backup Management
 * 
 * Purpose: Implement and manage Snowflake backup operations including:
 *          - Point-in-time backups (zero-copy clones)
 *          - Backup policies and scheduling
 *          - Retention management and auto-cleanup
 *          - Restore operations
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          BACKUP
 *   Object Type:     TABLES (5), PROCEDURES (~15)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRF_*_DBADMIN, SRS_SECURITY_ADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and BACKUP schema must exist
 *     - Time Travel must be enabled on source objects
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * BACKUP STRATEGY:
 * ─────────────────────────────────────────────────────────────────────────────
 *   Snowflake backups leverage zero-copy cloning for instant, storage-efficient
 *   point-in-time snapshots. Combined with Time Travel, this provides:
 *   • Instant backup creation (no data movement)
 *   • Storage-efficient (only changed data consumes space)
 *   • Fast restore (swap or clone operations)
 *   • Granular recovery (database, schema, or table level)
 * 
 * DEPLOYMENT: ADMIN.BACKUP schema
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA BACKUP;

-- #############################################################################
-- SECTION 1: BACKUP TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.BACKUP.BACKUP_POLICIES (
    POLICY_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_NAME VARCHAR(255) NOT NULL UNIQUE,
    SOURCE_DATABASE VARCHAR(255) NOT NULL,
    SOURCE_SCHEMA VARCHAR(255),
    SOURCE_TABLE VARCHAR(255),
    BACKUP_TYPE VARCHAR(20) NOT NULL DEFAULT 'DATABASE',
    BACKUP_FREQUENCY VARCHAR(20) NOT NULL,
    RETENTION_DAYS INTEGER NOT NULL DEFAULT 30,
    BACKUP_PREFIX VARCHAR(50) DEFAULT 'BKP',
    TARGET_DATABASE VARCHAR(255),
    INCLUDE_PATTERN VARCHAR(500),
    EXCLUDE_PATTERN VARCHAR(500),
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    TASK_NAME VARCHAR(255),
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(255),
    UPDATED_AT TIMESTAMP_NTZ,
    LAST_BACKUP_AT TIMESTAMP_NTZ,
    NEXT_BACKUP_AT TIMESTAMP_NTZ,
    METADATA VARIANT
);

CREATE TABLE IF NOT EXISTS ADMIN.BACKUP.BACKUP_CATALOG (
    BACKUP_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_ID VARCHAR(36),
    BACKUP_NAME VARCHAR(255) NOT NULL,
    BACKUP_TYPE VARCHAR(20) NOT NULL,
    BACKUP_TAG VARCHAR(50),
    SOURCE_DATABASE VARCHAR(255) NOT NULL,
    SOURCE_SCHEMA VARCHAR(255),
    SOURCE_TABLE VARCHAR(255),
    TARGET_DATABASE VARCHAR(255) NOT NULL,
    TARGET_SCHEMA VARCHAR(255),
    TARGET_TABLE VARCHAR(255),
    BACKUP_TIMESTAMP TIMESTAMP_NTZ NOT NULL,
    TIME_TRAVEL_POINT TIMESTAMP_NTZ,
    SIZE_BYTES NUMBER,
    ROW_COUNT NUMBER,
    STATUS VARCHAR(20) DEFAULT 'ACTIVE',
    EXPIRES_AT TIMESTAMP_NTZ,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    RESTORED_COUNT INTEGER DEFAULT 0,
    LAST_RESTORED_AT TIMESTAMP_NTZ,
    METADATA VARIANT,
    FOREIGN KEY (POLICY_ID) REFERENCES BACKUP_POLICIES(POLICY_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.BACKUP.BACKUP_JOBS (
    JOB_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_ID VARCHAR(36) NOT NULL,
    JOB_TYPE VARCHAR(20) NOT NULL,
    STATUS VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    STARTED_AT TIMESTAMP_NTZ,
    COMPLETED_AT TIMESTAMP_NTZ,
    DURATION_SECONDS INTEGER,
    BACKUP_ID VARCHAR(36),
    SOURCE_OBJECT VARCHAR(500),
    TARGET_OBJECT VARCHAR(500),
    ROWS_PROCESSED NUMBER,
    BYTES_PROCESSED NUMBER,
    ERROR_MESSAGE TEXT,
    EXECUTED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    METADATA VARIANT,
    FOREIGN KEY (POLICY_ID) REFERENCES BACKUP_POLICIES(POLICY_ID),
    FOREIGN KEY (BACKUP_ID) REFERENCES BACKUP_CATALOG(BACKUP_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.BACKUP.BACKUP_RESTORE_HISTORY (
    RESTORE_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    BACKUP_ID VARCHAR(36) NOT NULL,
    RESTORE_TYPE VARCHAR(20) NOT NULL,
    SOURCE_BACKUP VARCHAR(500) NOT NULL,
    TARGET_OBJECT VARCHAR(500) NOT NULL,
    RESTORE_METHOD VARCHAR(20),
    STATUS VARCHAR(20) NOT NULL,
    STARTED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    COMPLETED_AT TIMESTAMP_NTZ,
    DURATION_SECONDS INTEGER,
    ROWS_RESTORED NUMBER,
    RESTORED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    RESTORE_REASON TEXT,
    ERROR_MESSAGE TEXT,
    FOREIGN KEY (BACKUP_ID) REFERENCES BACKUP_CATALOG(BACKUP_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.BACKUP.BACKUP_AUDIT_LOG (
    AUDIT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    ACTION VARCHAR(50) NOT NULL,
    OBJECT_TYPE VARCHAR(50),
    OBJECT_NAME VARCHAR(500),
    POLICY_ID VARCHAR(36),
    BACKUP_ID VARCHAR(36),
    PERFORMED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    PERFORMED_BY_ROLE VARCHAR(255) DEFAULT CURRENT_ROLE(),
    STATUS VARCHAR(20),
    DETAILS VARIANT,
    ERROR_MESSAGE TEXT
);

-- #############################################################################
-- SECTION 2: BACKUP CREATION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Backup
 * 
 * Purpose: Creates a point-in-time backup using zero-copy cloning
 * 
 * Backup Types:
 *   - DATABASE: Full database backup
 *   - SCHEMA: Single schema backup
 *   - TABLE: Individual table backup
 * 
 * Backup Tags:
 *   - ADHOC: Manual one-time backup
 *   - DAILY: Daily scheduled backup
 *   - WEEKLY: Weekly scheduled backup
 *   - MONTHLY: Monthly scheduled backup
 *   - YEARLY: Annual archive backup
 *   - PRE_RELEASE: Before deployment backup
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_CREATE_BACKUP(
    P_SOURCE_DATABASE VARCHAR,
    P_SOURCE_SCHEMA VARCHAR DEFAULT NULL,
    P_SOURCE_TABLE VARCHAR DEFAULT NULL,
    P_BACKUP_TAG VARCHAR DEFAULT 'ADHOC',
    P_TARGET_DATABASE VARCHAR DEFAULT NULL,
    P_TIME_TRAVEL_POINT TIMESTAMP_NTZ DEFAULT NULL,
    P_RETENTION_DAYS INTEGER DEFAULT 30,
    P_POLICY_ID VARCHAR DEFAULT NULL,
    P_DESCRIPTION TEXT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_backup_id VARCHAR;
    v_backup_name VARCHAR;
    v_backup_type VARCHAR;
    v_target_db VARCHAR;
    v_target_schema VARCHAR;
    v_target_table VARCHAR;
    v_sql VARCHAR;
    v_timestamp VARCHAR;
    v_expires_at TIMESTAMP_NTZ;
    v_source_object VARCHAR;
    v_target_object VARCHAR;
BEGIN
    v_backup_id := UUID_STRING();
    v_timestamp := TO_VARCHAR(CURRENT_TIMESTAMP(), 'YYYYMMDD_HH24MISS');
    v_expires_at := DATEADD(DAY, P_RETENTION_DAYS, CURRENT_TIMESTAMP());
    
    -- Determine backup type and naming
    IF (P_SOURCE_TABLE IS NOT NULL) THEN
        v_backup_type := 'TABLE';
        v_backup_name := 'BKP_' || P_SOURCE_DATABASE || '_' || P_SOURCE_SCHEMA || '_' || P_SOURCE_TABLE || '_' || v_timestamp;
        v_source_object := P_SOURCE_DATABASE || '.' || P_SOURCE_SCHEMA || '.' || P_SOURCE_TABLE;
        v_target_db := COALESCE(P_TARGET_DATABASE, P_SOURCE_DATABASE);
        v_target_schema := P_SOURCE_SCHEMA || '_BACKUP';
        v_target_table := P_SOURCE_TABLE || '_' || v_timestamp;
        v_target_object := v_target_db || '.' || v_target_schema || '.' || v_target_table;
        
        -- Ensure backup schema exists
        v_sql := 'CREATE SCHEMA IF NOT EXISTS ' || v_target_db || '.' || v_target_schema;
        EXECUTE IMMEDIATE v_sql;
        
        -- Create table clone
        IF (P_TIME_TRAVEL_POINT IS NOT NULL) THEN
            v_sql := 'CREATE TABLE ' || v_target_object || ' CLONE ' || v_source_object || ' AT (TIMESTAMP => TO_TIMESTAMP_NTZ(''' || TO_VARCHAR(P_TIME_TRAVEL_POINT) || '''))';
        ELSE
            v_sql := 'CREATE TABLE ' || v_target_object || ' CLONE ' || v_source_object;
        END IF;
        
    ELSEIF (P_SOURCE_SCHEMA IS NOT NULL) THEN
        v_backup_type := 'SCHEMA';
        v_backup_name := 'BKP_' || P_SOURCE_DATABASE || '_' || P_SOURCE_SCHEMA || '_' || v_timestamp;
        v_source_object := P_SOURCE_DATABASE || '.' || P_SOURCE_SCHEMA;
        v_target_db := COALESCE(P_TARGET_DATABASE, P_SOURCE_DATABASE);
        v_target_schema := P_SOURCE_SCHEMA || '_BKP_' || v_timestamp;
        v_target_object := v_target_db || '.' || v_target_schema;
        
        -- Create schema clone
        IF (P_TIME_TRAVEL_POINT IS NOT NULL) THEN
            v_sql := 'CREATE SCHEMA ' || v_target_object || ' CLONE ' || v_source_object || ' AT (TIMESTAMP => TO_TIMESTAMP_NTZ(''' || TO_VARCHAR(P_TIME_TRAVEL_POINT) || '''))';
        ELSE
            v_sql := 'CREATE SCHEMA ' || v_target_object || ' CLONE ' || v_source_object;
        END IF;
        
    ELSE
        v_backup_type := 'DATABASE';
        v_backup_name := 'BKP_' || P_SOURCE_DATABASE || '_' || v_timestamp;
        v_source_object := P_SOURCE_DATABASE;
        v_target_db := COALESCE(P_TARGET_DATABASE, P_SOURCE_DATABASE || '_BKP_' || v_timestamp);
        v_target_object := v_target_db;
        
        -- Create database clone
        IF (P_TIME_TRAVEL_POINT IS NOT NULL) THEN
            v_sql := 'CREATE DATABASE ' || v_target_db || ' CLONE ' || P_SOURCE_DATABASE || ' AT (TIMESTAMP => TO_TIMESTAMP_NTZ(''' || TO_VARCHAR(P_TIME_TRAVEL_POINT) || '''))';
        ELSE
            v_sql := 'CREATE DATABASE ' || v_target_db || ' CLONE ' || P_SOURCE_DATABASE;
        END IF;
    END IF;
    
    -- Execute backup
    EXECUTE IMMEDIATE v_sql;
    
    -- Add comment to backup
    IF (v_backup_type = 'DATABASE') THEN
        EXECUTE IMMEDIATE 'ALTER DATABASE ' || v_target_db || ' SET COMMENT = ''Backup: ' || v_backup_name || ' | Source: ' || v_source_object || ' | Created: ' || TO_VARCHAR(CURRENT_TIMESTAMP()) || ' | Expires: ' || TO_VARCHAR(v_expires_at) || ' | Tag: ' || P_BACKUP_TAG || '''';
    ELSEIF (v_backup_type = 'SCHEMA') THEN
        EXECUTE IMMEDIATE 'ALTER SCHEMA ' || v_target_object || ' SET COMMENT = ''Backup: ' || v_backup_name || ' | Source: ' || v_source_object || ' | Created: ' || TO_VARCHAR(CURRENT_TIMESTAMP()) || ' | Expires: ' || TO_VARCHAR(v_expires_at) || ' | Tag: ' || P_BACKUP_TAG || '''';
    END IF;
    
    -- Register in catalog
    INSERT INTO BACKUP_CATALOG (
        BACKUP_ID, POLICY_ID, BACKUP_NAME, BACKUP_TYPE, BACKUP_TAG,
        SOURCE_DATABASE, SOURCE_SCHEMA, SOURCE_TABLE,
        TARGET_DATABASE, TARGET_SCHEMA, TARGET_TABLE,
        BACKUP_TIMESTAMP, TIME_TRAVEL_POINT, EXPIRES_AT, STATUS, METADATA
    ) VALUES (
        v_backup_id, P_POLICY_ID, v_backup_name, v_backup_type, P_BACKUP_TAG,
        P_SOURCE_DATABASE, P_SOURCE_SCHEMA, P_SOURCE_TABLE,
        v_target_db, v_target_schema, v_target_table,
        CURRENT_TIMESTAMP(), P_TIME_TRAVEL_POINT, v_expires_at, 'ACTIVE',
        OBJECT_CONSTRUCT('description', P_DESCRIPTION, 'retention_days', P_RETENTION_DAYS)
    );
    
    -- Audit log
    INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, BACKUP_ID, STATUS, DETAILS)
    VALUES ('CREATE_BACKUP', v_backup_type, v_source_object, v_backup_id, 'SUCCESS',
            OBJECT_CONSTRUCT('backup_name', v_backup_name, 'target', v_target_object, 'tag', P_BACKUP_TAG));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'backup_id', v_backup_id,
        'backup_name', v_backup_name,
        'backup_type', v_backup_type,
        'source', v_source_object,
        'target', v_target_object,
        'tag', P_BACKUP_TAG,
        'expires_at', v_expires_at,
        'message', 'Backup created successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, ERROR_MESSAGE)
        VALUES ('CREATE_BACKUP', v_backup_type, v_source_object, 'FAILED', SQLERRM);
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Quick Backup (Simplified)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_QUICK_BACKUP(
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR DEFAULT NULL,
    P_TABLE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_result VARIANT;
BEGIN
    CALL ADMIN.BACKUP.RBAC_CREATE_BACKUP(P_DATABASE, P_SCHEMA, P_TABLE, 'ADHOC', NULL, NULL, 7, NULL, 'Quick backup') INTO v_result;
    RETURN v_result;
END;
$$;

-- #############################################################################
-- SECTION 3: BACKUP POLICIES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Backup Policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_CREATE_BACKUP_POLICY(
    P_POLICY_NAME VARCHAR,
    P_SOURCE_DATABASE VARCHAR,
    P_SOURCE_SCHEMA VARCHAR DEFAULT NULL,
    P_SOURCE_TABLE VARCHAR DEFAULT NULL,
    P_FREQUENCY VARCHAR DEFAULT 'DAILY',
    P_RETENTION_DAYS INTEGER DEFAULT 30,
    P_TARGET_DATABASE VARCHAR DEFAULT NULL,
    P_IS_ACTIVE BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_policy_id VARCHAR;
    v_backup_type VARCHAR;
BEGIN
    v_policy_id := UUID_STRING();
    
    -- Determine backup type
    IF (P_SOURCE_TABLE IS NOT NULL) THEN
        v_backup_type := 'TABLE';
    ELSEIF (P_SOURCE_SCHEMA IS NOT NULL) THEN
        v_backup_type := 'SCHEMA';
    ELSE
        v_backup_type := 'DATABASE';
    END IF;
    
    -- Validate frequency
    IF (P_FREQUENCY NOT IN ('HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY')) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid frequency. Use: HOURLY, DAILY, WEEKLY, MONTHLY, YEARLY');
    END IF;
    
    -- Create policy
    INSERT INTO BACKUP_POLICIES (
        POLICY_ID, POLICY_NAME, SOURCE_DATABASE, SOURCE_SCHEMA, SOURCE_TABLE,
        BACKUP_TYPE, BACKUP_FREQUENCY, RETENTION_DAYS, TARGET_DATABASE, IS_ACTIVE
    ) VALUES (
        v_policy_id, P_POLICY_NAME, P_SOURCE_DATABASE, P_SOURCE_SCHEMA, P_SOURCE_TABLE,
        v_backup_type, P_FREQUENCY, P_RETENTION_DAYS, P_TARGET_DATABASE, P_IS_ACTIVE
    );
    
    -- Audit log
    INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, POLICY_ID, STATUS, DETAILS)
    VALUES ('CREATE_POLICY', 'BACKUP_POLICY', P_POLICY_NAME, v_policy_id, 'SUCCESS',
            OBJECT_CONSTRUCT('frequency', P_FREQUENCY, 'retention_days', P_RETENTION_DAYS));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_id', v_policy_id,
        'policy_name', P_POLICY_NAME,
        'backup_type', v_backup_type,
        'frequency', P_FREQUENCY,
        'retention_days', P_RETENTION_DAYS,
        'message', 'Backup policy created. Use RBAC_SETUP_BACKUP_SCHEDULE to activate.'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Backup Schedule (Creates Snowflake Task)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_SETUP_BACKUP_SCHEDULE(
    P_POLICY_NAME VARCHAR,
    P_WAREHOUSE VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_policy VARIANT;
    v_task_name VARCHAR;
    v_schedule VARCHAR;
    v_sql VARCHAR;
    v_backup_tag VARCHAR;
BEGIN
    -- Get policy details
    SELECT OBJECT_CONSTRUCT(
        'policy_id', POLICY_ID,
        'source_database', SOURCE_DATABASE,
        'source_schema', SOURCE_SCHEMA,
        'source_table', SOURCE_TABLE,
        'frequency', BACKUP_FREQUENCY,
        'retention_days', RETENTION_DAYS,
        'target_database', TARGET_DATABASE
    ) INTO v_policy
    FROM BACKUP_POLICIES
    WHERE POLICY_NAME = P_POLICY_NAME;
    
    IF (v_policy IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Policy not found: ' || P_POLICY_NAME);
    END IF;
    
    v_task_name := 'BACKUP_TASK_' || UPPER(REPLACE(P_POLICY_NAME, ' ', '_'));
    
    -- Determine schedule and tag based on frequency
    CASE TO_VARCHAR(v_policy:frequency)
        WHEN 'HOURLY' THEN
            v_schedule := 'USING CRON 0 * * * * UTC';
            v_backup_tag := 'HOURLY';
        WHEN 'DAILY' THEN
            v_schedule := 'USING CRON 0 2 * * * UTC';
            v_backup_tag := 'DAILY';
        WHEN 'WEEKLY' THEN
            v_schedule := 'USING CRON 0 3 * * 0 UTC';
            v_backup_tag := 'WEEKLY';
        WHEN 'MONTHLY' THEN
            v_schedule := 'USING CRON 0 4 1 * * UTC';
            v_backup_tag := 'MONTHLY';
        WHEN 'YEARLY' THEN
            v_schedule := 'USING CRON 0 5 1 1 * UTC';
            v_backup_tag := 'YEARLY';
    END CASE;
    
    -- Create the task
    v_sql := 'CREATE OR REPLACE TASK ADMIN.BACKUP.' || v_task_name || '
        WAREHOUSE = ' || P_WAREHOUSE || '
        SCHEDULE = ''' || v_schedule || '''
        AS
        CALL ADMIN.BACKUP.RBAC_CREATE_BACKUP(
            ''' || TO_VARCHAR(v_policy:source_database) || ''',
            ' || IFF(v_policy:source_schema IS NOT NULL, '''' || TO_VARCHAR(v_policy:source_schema) || '''', 'NULL') || ',
            ' || IFF(v_policy:source_table IS NOT NULL, '''' || TO_VARCHAR(v_policy:source_table) || '''', 'NULL') || ',
            ''' || v_backup_tag || ''',
            ' || IFF(v_policy:target_database IS NOT NULL, '''' || TO_VARCHAR(v_policy:target_database) || '''', 'NULL') || ',
            NULL,
            ' || TO_VARCHAR(v_policy:retention_days) || ',
            ''' || TO_VARCHAR(v_policy:policy_id) || ''',
            ''Scheduled backup''
        )';
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Resume the task
    EXECUTE IMMEDIATE 'ALTER TASK ADMIN.BACKUP.' || v_task_name || ' RESUME';
    
    -- Update policy with task name
    UPDATE BACKUP_POLICIES
    SET TASK_NAME = v_task_name,
        UPDATED_AT = CURRENT_TIMESTAMP(),
        UPDATED_BY = CURRENT_USER()
    WHERE POLICY_NAME = P_POLICY_NAME;
    
    -- Audit log
    INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, POLICY_ID, STATUS, DETAILS)
    VALUES ('CREATE_SCHEDULE', 'TASK', v_task_name, v_policy:policy_id::VARCHAR, 'SUCCESS',
            OBJECT_CONSTRUCT('schedule', v_schedule, 'warehouse', P_WAREHOUSE));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'task_name', v_task_name,
        'schedule', v_schedule,
        'warehouse', P_WAREHOUSE,
        'message', 'Backup schedule created and activated'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Pause/Resume Backup Schedule
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_TOGGLE_BACKUP_SCHEDULE(
    P_POLICY_NAME VARCHAR,
    P_ACTION VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_task_name VARCHAR;
BEGIN
    SELECT TASK_NAME INTO v_task_name
    FROM BACKUP_POLICIES
    WHERE POLICY_NAME = P_POLICY_NAME;
    
    IF (v_task_name IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'No schedule found for policy: ' || P_POLICY_NAME);
    END IF;
    
    IF (UPPER(P_ACTION) = 'PAUSE') THEN
        EXECUTE IMMEDIATE 'ALTER TASK ADMIN.BACKUP.' || v_task_name || ' SUSPEND';
        UPDATE BACKUP_POLICIES SET IS_ACTIVE = FALSE WHERE POLICY_NAME = P_POLICY_NAME;
    ELSEIF (UPPER(P_ACTION) = 'RESUME') THEN
        EXECUTE IMMEDIATE 'ALTER TASK ADMIN.BACKUP.' || v_task_name || ' RESUME';
        UPDATE BACKUP_POLICIES SET IS_ACTIVE = TRUE WHERE POLICY_NAME = P_POLICY_NAME;
    ELSE
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid action. Use: PAUSE or RESUME');
    END IF;
    
    INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS)
    VALUES (UPPER(P_ACTION) || '_SCHEDULE', 'TASK', v_task_name, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'task_name', v_task_name,
        'action', UPPER(P_ACTION),
        'message', 'Backup schedule ' || LOWER(P_ACTION) || 'd'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 4: RESTORE OPERATIONS
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Restore from Backup
 * 
 * Restore Methods:
 *   - CLONE: Create new object from backup (non-destructive)
 *   - SWAP: Replace current object with backup (atomic swap)
 *   - OVERWRITE: Drop and recreate from backup
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_RESTORE_FROM_BACKUP(
    P_BACKUP_ID VARCHAR,
    P_RESTORE_METHOD VARCHAR DEFAULT 'CLONE',
    P_TARGET_NAME VARCHAR DEFAULT NULL,
    P_RESTORE_REASON TEXT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_backup VARIANT;
    v_restore_id VARCHAR;
    v_sql VARCHAR;
    v_target VARCHAR;
    v_source VARCHAR;
    v_start_time TIMESTAMP_NTZ;
BEGIN
    v_restore_id := UUID_STRING();
    v_start_time := CURRENT_TIMESTAMP();
    
    -- Get backup details
    SELECT OBJECT_CONSTRUCT(
        'backup_id', BACKUP_ID,
        'backup_type', BACKUP_TYPE,
        'target_database', TARGET_DATABASE,
        'target_schema', TARGET_SCHEMA,
        'target_table', TARGET_TABLE,
        'source_database', SOURCE_DATABASE,
        'source_schema', SOURCE_SCHEMA,
        'source_table', SOURCE_TABLE
    ) INTO v_backup
    FROM BACKUP_CATALOG
    WHERE BACKUP_ID = P_BACKUP_ID AND STATUS = 'ACTIVE';
    
    IF (v_backup IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Backup not found or inactive: ' || P_BACKUP_ID);
    END IF;
    
    -- Build source path (the backup)
    CASE v_backup:backup_type
        WHEN 'DATABASE' THEN
            v_source := v_backup:target_database;
            v_target := COALESCE(P_TARGET_NAME, v_backup:source_database || '_RESTORED');
        WHEN 'SCHEMA' THEN
            v_source := v_backup:target_database || '.' || v_backup:target_schema;
            v_target := COALESCE(P_TARGET_NAME, v_backup:source_database || '.' || v_backup:source_schema || '_RESTORED');
        WHEN 'TABLE' THEN
            v_source := v_backup:target_database || '.' || v_backup:target_schema || '.' || v_backup:target_table;
            v_target := COALESCE(P_TARGET_NAME, v_backup:source_database || '.' || v_backup:source_schema || '.' || v_backup:source_table || '_RESTORED');
    END CASE;
    
    -- Record restore start
    INSERT INTO BACKUP_RESTORE_HISTORY (
        RESTORE_ID, BACKUP_ID, RESTORE_TYPE, SOURCE_BACKUP, TARGET_OBJECT,
        RESTORE_METHOD, STATUS, RESTORE_REASON
    ) VALUES (
        v_restore_id, P_BACKUP_ID, v_backup:backup_type, v_source, v_target,
        P_RESTORE_METHOD, 'IN_PROGRESS', P_RESTORE_REASON
    );
    
    -- Perform restore based on method
    CASE UPPER(P_RESTORE_METHOD)
        WHEN 'CLONE' THEN
            -- Create new object from backup
            CASE v_backup:backup_type
                WHEN 'DATABASE' THEN
                    v_sql := 'CREATE DATABASE ' || v_target || ' CLONE ' || v_source;
                WHEN 'SCHEMA' THEN
                    v_sql := 'CREATE SCHEMA ' || v_target || ' CLONE ' || v_source;
                WHEN 'TABLE' THEN
                    v_sql := 'CREATE TABLE ' || v_target || ' CLONE ' || v_source;
            END CASE;
            
        WHEN 'SWAP' THEN
            -- Atomic swap (only for tables and schemas in same database)
            IF (v_backup:backup_type = 'TABLE') THEN
                LET v_original VARCHAR := v_backup:source_database || '.' || v_backup:source_schema || '.' || v_backup:source_table;
                v_sql := 'ALTER TABLE ' || v_original || ' SWAP WITH ' || v_source;
                v_target := v_original;
            ELSE
                RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'SWAP method only supported for TABLE backups');
            END IF;
            
        WHEN 'OVERWRITE' THEN
            -- Drop existing and clone from backup
            CASE v_backup:backup_type
                WHEN 'DATABASE' THEN
                    LET v_orig_db VARCHAR := v_backup:source_database;
                    EXECUTE IMMEDIATE 'DROP DATABASE IF EXISTS ' || v_orig_db;
                    v_sql := 'CREATE DATABASE ' || v_orig_db || ' CLONE ' || v_source;
                    v_target := v_orig_db;
                WHEN 'SCHEMA' THEN
                    LET v_orig_schema VARCHAR := v_backup:source_database || '.' || v_backup:source_schema;
                    EXECUTE IMMEDIATE 'DROP SCHEMA IF EXISTS ' || v_orig_schema;
                    v_sql := 'CREATE SCHEMA ' || v_orig_schema || ' CLONE ' || v_source;
                    v_target := v_orig_schema;
                WHEN 'TABLE' THEN
                    LET v_orig_table VARCHAR := v_backup:source_database || '.' || v_backup:source_schema || '.' || v_backup:source_table;
                    EXECUTE IMMEDIATE 'DROP TABLE IF EXISTS ' || v_orig_table;
                    v_sql := 'CREATE TABLE ' || v_orig_table || ' CLONE ' || v_source;
                    v_target := v_orig_table;
            END CASE;
            
        ELSE
            RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid restore method. Use: CLONE, SWAP, or OVERWRITE');
    END CASE;
    
    -- Execute restore
    EXECUTE IMMEDIATE v_sql;
    
    -- Update restore history
    UPDATE BACKUP_RESTORE_HISTORY
    SET STATUS = 'SUCCESS',
        COMPLETED_AT = CURRENT_TIMESTAMP(),
        DURATION_SECONDS = DATEDIFF(SECOND, v_start_time, CURRENT_TIMESTAMP()),
        TARGET_OBJECT = v_target
    WHERE RESTORE_ID = v_restore_id;
    
    -- Update backup restored count
    UPDATE BACKUP_CATALOG
    SET RESTORED_COUNT = RESTORED_COUNT + 1,
        LAST_RESTORED_AT = CURRENT_TIMESTAMP()
    WHERE BACKUP_ID = P_BACKUP_ID;
    
    -- Audit log
    INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, BACKUP_ID, STATUS, DETAILS)
    VALUES ('RESTORE', TO_VARCHAR(v_backup:backup_type), v_target, P_BACKUP_ID, 'SUCCESS',
            OBJECT_CONSTRUCT('method', P_RESTORE_METHOD, 'source', v_source, 'reason', P_RESTORE_REASON));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'restore_id', v_restore_id,
        'backup_id', P_BACKUP_ID,
        'method', P_RESTORE_METHOD,
        'source', v_source,
        'target', v_target,
        'duration_seconds', DATEDIFF(SECOND, v_start_time, CURRENT_TIMESTAMP()),
        'message', 'Restore completed successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        UPDATE BACKUP_RESTORE_HISTORY
        SET STATUS = 'FAILED', ERROR_MESSAGE = SQLERRM, COMPLETED_AT = CURRENT_TIMESTAMP()
        WHERE RESTORE_ID = v_restore_id;
        
        INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, BACKUP_ID, STATUS, ERROR_MESSAGE)
        VALUES ('RESTORE', v_backup:backup_type, P_BACKUP_ID, 'FAILED', SQLERRM);
        
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Restore Using Time Travel
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_RESTORE_TIME_TRAVEL(
    P_DATABASE VARCHAR,
    P_SCHEMA VARCHAR,
    P_TABLE VARCHAR,
    P_RESTORE_POINT TIMESTAMP_NTZ,
    P_TARGET_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_source VARCHAR;
    v_target VARCHAR;
    v_sql VARCHAR;
BEGIN
    v_source := P_DATABASE || '.' || P_SCHEMA || '.' || P_TABLE;
    v_target := COALESCE(P_TARGET_NAME, v_source || '_TT_' || TO_VARCHAR(CURRENT_TIMESTAMP(), 'YYYYMMDD_HH24MISS'));
    
    v_sql := 'CREATE TABLE ' || v_target || ' CLONE ' || v_source || ' AT (TIMESTAMP => TO_TIMESTAMP_NTZ(''' || TO_VARCHAR(P_RESTORE_POINT) || '''))';
    
    EXECUTE IMMEDIATE v_sql;
    
    INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, DETAILS)
    VALUES ('TIME_TRAVEL_RESTORE', 'TABLE', v_source, 'SUCCESS',
            OBJECT_CONSTRUCT('restore_point', P_RESTORE_POINT, 'target', v_target));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'source', v_source,
        'target', v_target,
        'restore_point', P_RESTORE_POINT,
        'message', 'Time travel restore completed'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 5: RETENTION MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Cleanup Expired Backups
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_CLEANUP_EXPIRED_BACKUPS(
    P_DRY_RUN BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_deleted INTEGER := 0;
    v_failed INTEGER := 0;
    v_deleted_list VARIANT := ARRAY_CONSTRUCT();
    v_failed_list VARIANT := ARRAY_CONSTRUCT();
BEGIN
    FOR backup_rec IN (
        SELECT BACKUP_ID, BACKUP_NAME, BACKUP_TYPE, TARGET_DATABASE, TARGET_SCHEMA, TARGET_TABLE
        FROM BACKUP_CATALOG
        WHERE STATUS = 'ACTIVE' AND EXPIRES_AT < CURRENT_TIMESTAMP()
    ) LOOP
        IF (NOT P_DRY_RUN) THEN
            BEGIN
                -- Drop the backup object
                CASE backup_rec.BACKUP_TYPE
                    WHEN 'DATABASE' THEN
                        EXECUTE IMMEDIATE 'DROP DATABASE IF EXISTS ' || backup_rec.TARGET_DATABASE;
                    WHEN 'SCHEMA' THEN
                        EXECUTE IMMEDIATE 'DROP SCHEMA IF EXISTS ' || backup_rec.TARGET_DATABASE || '.' || backup_rec.TARGET_SCHEMA;
                    WHEN 'TABLE' THEN
                        EXECUTE IMMEDIATE 'DROP TABLE IF EXISTS ' || backup_rec.TARGET_DATABASE || '.' || backup_rec.TARGET_SCHEMA || '.' || backup_rec.TARGET_TABLE;
                END CASE;
                
                -- Mark as deleted in catalog
                UPDATE BACKUP_CATALOG SET STATUS = 'DELETED' WHERE BACKUP_ID = backup_rec.BACKUP_ID;
                
                v_deleted := v_deleted + 1;
                v_deleted_list := ARRAY_APPEND(v_deleted_list, backup_rec.BACKUP_NAME);
            EXCEPTION
                WHEN OTHER THEN
                    v_failed := v_failed + 1;
                    v_failed_list := ARRAY_APPEND(v_failed_list, OBJECT_CONSTRUCT('backup', backup_rec.BACKUP_NAME, 'error', SQLERRM));
            END;
        ELSE
            v_deleted := v_deleted + 1;
            v_deleted_list := ARRAY_APPEND(v_deleted_list, backup_rec.BACKUP_NAME);
        END IF;
    END LOOP;
    
    IF (NOT P_DRY_RUN) THEN
        INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, STATUS, DETAILS)
        VALUES ('CLEANUP_EXPIRED', 'BACKUP', 'SUCCESS',
                OBJECT_CONSTRUCT('deleted', v_deleted, 'failed', v_failed));
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'EXECUTED'),
        'backups_deleted', v_deleted,
        'backups_failed', v_failed,
        'deleted_list', v_deleted_list,
        'failed_list', v_failed_list,
        'message', IFF(P_DRY_RUN, 'Dry run complete. Set P_DRY_RUN=FALSE to execute.', 'Cleanup completed')
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Delete Specific Backup
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_DELETE_BACKUP(
    P_BACKUP_ID VARCHAR,
    P_REASON TEXT DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_backup VARIANT;
    v_target VARCHAR;
BEGIN
    SELECT OBJECT_CONSTRUCT(
        'backup_name', BACKUP_NAME,
        'backup_type', BACKUP_TYPE,
        'target_database', TARGET_DATABASE,
        'target_schema', TARGET_SCHEMA,
        'target_table', TARGET_TABLE
    ) INTO v_backup
    FROM BACKUP_CATALOG
    WHERE BACKUP_ID = P_BACKUP_ID AND STATUS = 'ACTIVE';
    
    IF (v_backup IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Backup not found or already deleted');
    END IF;
    
    -- Drop the backup object
    CASE v_backup:backup_type
        WHEN 'DATABASE' THEN
            v_target := v_backup:target_database;
            EXECUTE IMMEDIATE 'DROP DATABASE IF EXISTS ' || v_target;
        WHEN 'SCHEMA' THEN
            v_target := v_backup:target_database || '.' || v_backup:target_schema;
            EXECUTE IMMEDIATE 'DROP SCHEMA IF EXISTS ' || v_target;
        WHEN 'TABLE' THEN
            v_target := v_backup:target_database || '.' || v_backup:target_schema || '.' || v_backup:target_table;
            EXECUTE IMMEDIATE 'DROP TABLE IF EXISTS ' || v_target;
    END CASE;
    
    -- Mark as deleted
    UPDATE BACKUP_CATALOG SET STATUS = 'DELETED' WHERE BACKUP_ID = P_BACKUP_ID;
    
    -- Audit log
    INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, BACKUP_ID, STATUS, DETAILS)
    VALUES ('DELETE_BACKUP', v_backup:backup_type, v_target, P_BACKUP_ID, 'SUCCESS',
            OBJECT_CONSTRUCT('reason', P_REASON));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'backup_id', P_BACKUP_ID,
        'backup_name', v_backup:backup_name::VARCHAR,
        'deleted_object', v_target,
        'message', 'Backup deleted successfully'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 6: LISTING AND CATALOG
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Backups
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_LIST_BACKUPS(
    P_SOURCE_DATABASE VARCHAR DEFAULT NULL,
    P_BACKUP_TYPE VARCHAR DEFAULT NULL,
    P_BACKUP_TAG VARCHAR DEFAULT NULL,
    P_STATUS VARCHAR DEFAULT 'ACTIVE'
)
RETURNS TABLE (
    BACKUP_ID VARCHAR,
    BACKUP_NAME VARCHAR,
    BACKUP_TYPE VARCHAR,
    BACKUP_TAG VARCHAR,
    SOURCE_OBJECT VARCHAR,
    TARGET_OBJECT VARCHAR,
    BACKUP_TIMESTAMP TIMESTAMP_NTZ,
    EXPIRES_AT TIMESTAMP_NTZ,
    DAYS_UNTIL_EXPIRY INTEGER,
    RESTORED_COUNT INTEGER,
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
            BACKUP_ID,
            BACKUP_NAME,
            BACKUP_TYPE,
            BACKUP_TAG,
            SOURCE_DATABASE || COALESCE('.' || SOURCE_SCHEMA, '') || COALESCE('.' || SOURCE_TABLE, '') AS SOURCE_OBJECT,
            TARGET_DATABASE || COALESCE('.' || TARGET_SCHEMA, '') || COALESCE('.' || TARGET_TABLE, '') AS TARGET_OBJECT,
            BACKUP_TIMESTAMP,
            EXPIRES_AT,
            DATEDIFF(DAY, CURRENT_TIMESTAMP(), EXPIRES_AT) AS DAYS_UNTIL_EXPIRY,
            RESTORED_COUNT,
            STATUS
        FROM BACKUP_CATALOG
        WHERE (P_SOURCE_DATABASE IS NULL OR SOURCE_DATABASE = P_SOURCE_DATABASE)
          AND (P_BACKUP_TYPE IS NULL OR BACKUP_TYPE = P_BACKUP_TYPE)
          AND (P_BACKUP_TAG IS NULL OR BACKUP_TAG = P_BACKUP_TAG)
          AND (P_STATUS IS NULL OR STATUS = P_STATUS)
        ORDER BY BACKUP_TIMESTAMP DESC
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Backup Policies
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_LIST_BACKUP_POLICIES(
    P_IS_ACTIVE BOOLEAN DEFAULT NULL
)
RETURNS TABLE (
    POLICY_ID VARCHAR,
    POLICY_NAME VARCHAR,
    BACKUP_TYPE VARCHAR,
    SOURCE_OBJECT VARCHAR,
    FREQUENCY VARCHAR,
    RETENTION_DAYS INTEGER,
    IS_ACTIVE BOOLEAN,
    TASK_NAME VARCHAR,
    LAST_BACKUP_AT TIMESTAMP_NTZ
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
            POLICY_ID,
            POLICY_NAME,
            BACKUP_TYPE,
            SOURCE_DATABASE || COALESCE('.' || SOURCE_SCHEMA, '') || COALESCE('.' || SOURCE_TABLE, '') AS SOURCE_OBJECT,
            BACKUP_FREQUENCY AS FREQUENCY,
            RETENTION_DAYS,
            IS_ACTIVE,
            TASK_NAME,
            LAST_BACKUP_AT
        FROM BACKUP_POLICIES
        WHERE (P_IS_ACTIVE IS NULL OR IS_ACTIVE = P_IS_ACTIVE)
        ORDER BY POLICY_NAME
    );
    RETURN TABLE(res);
END;
$$;

-- #############################################################################
-- SECTION 7: SETUP RETENTION CLEANUP TASK
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Automatic Retention Cleanup
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.BACKUP.RBAC_SETUP_RETENTION_CLEANUP(
    P_WAREHOUSE VARCHAR,
    P_SCHEDULE VARCHAR DEFAULT 'DAILY'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_cron VARCHAR;
BEGIN
    CASE UPPER(P_SCHEDULE)
        WHEN 'HOURLY' THEN v_cron := 'USING CRON 30 * * * * UTC';
        WHEN 'DAILY' THEN v_cron := 'USING CRON 0 1 * * * UTC';
        WHEN 'WEEKLY' THEN v_cron := 'USING CRON 0 1 * * 0 UTC';
        ELSE RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid schedule. Use: HOURLY, DAILY, WEEKLY');
    END CASE;
    
    EXECUTE IMMEDIATE '
        CREATE OR REPLACE TASK ADMIN.BACKUP.BACKUP_RETENTION_CLEANUP_TASK
        WAREHOUSE = ' || P_WAREHOUSE || '
        SCHEDULE = ''' || v_cron || '''
        AS
        CALL ADMIN.BACKUP.RBAC_CLEANUP_EXPIRED_BACKUPS(FALSE)';
    
    EXECUTE IMMEDIATE 'ALTER TASK ADMIN.BACKUP.BACKUP_RETENTION_CLEANUP_TASK RESUME';
    
    INSERT INTO BACKUP_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, DETAILS)
    VALUES ('SETUP_RETENTION_CLEANUP', 'TASK', 'BACKUP_RETENTION_CLEANUP_TASK', 'SUCCESS',
            OBJECT_CONSTRUCT('schedule', P_SCHEDULE, 'warehouse', P_WAREHOUSE));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'task_name', 'BACKUP_RETENTION_CLEANUP_TASK',
        'schedule', P_SCHEDULE,
        'warehouse', P_WAREHOUSE,
        'message', 'Retention cleanup task created and activated'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 8: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_CREATE_BACKUP(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMP_NTZ, INTEGER, VARCHAR, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_QUICK_BACKUP(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_CREATE_BACKUP_POLICY(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_SETUP_BACKUP_SCHEDULE(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_TOGGLE_BACKUP_SCHEDULE(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_RESTORE_FROM_BACKUP(VARCHAR, VARCHAR, VARCHAR, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_RESTORE_TIME_TRAVEL(VARCHAR, VARCHAR, VARCHAR, TIMESTAMP_NTZ, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_CLEANUP_EXPIRED_BACKUPS(BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_DELETE_BACKUP(VARCHAR, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_LIST_BACKUPS(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_LIST_BACKUP_POLICIES(BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_SETUP_RETENTION_CLEANUP(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- DBAdmins can create and list backups
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_CREATE_BACKUP(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMP_NTZ, INTEGER, VARCHAR, TEXT) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_QUICK_BACKUP(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_LIST_BACKUPS(VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_LIST_BACKUP_POLICIES(BOOLEAN) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.BACKUP.RBAC_RESTORE_FROM_BACKUP(VARCHAR, VARCHAR, VARCHAR, TEXT) TO ROLE SRS_SYSTEM_ADMIN;
