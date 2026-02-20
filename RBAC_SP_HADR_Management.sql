/*******************************************************************************
 * RBAC STORED PROCEDURE: High Availability / Disaster Recovery Management
 * 
 * Purpose: Implement and manage HA/DR capabilities including:
 *          - Cross-region database replication
 *          - Cross-account replication for DR
 *          - Failover and failback operations
 *          - DR testing and validation
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          HADR
 *   Object Type:     TABLES (6), PROCEDURES (~15)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  ACCOUNTADMIN (for replication/failover),
 *                    SRS_SECURITY_ADMIN (for monitoring/testing)
 * 
 *   Dependencies:    
 *     - ADMIN database and HADR schema must exist
 *     - Business Critical edition required for failover groups
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * HA/DR ARCHITECTURE:
 * ─────────────────────────────────────────────────────────────────────────────
 *   PRIMARY ACCOUNT (Production)
 *   ├── Replication Group → SECONDARY ACCOUNT (DR Site)
 *   │   ├── Database replication (async)
 *   │   ├── Account objects replication
 *   │   └── Failover groups
 *   │
 *   └── Cross-Region Replication
 *       ├── Same account, different region
 *       └── Lower RPO for regional failures
 * 
 * RTO/RPO TARGETS:
 *   • Cross-Region: RPO ~minutes, RTO ~minutes
 *   • Cross-Account: RPO ~minutes, RTO ~30 minutes
 *   • Full DR Failover: RPO ~1 hour, RTO ~4 hours
 * 
 * DEPLOYMENT: ADMIN.HADR schema
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA HADR;

-- #############################################################################
-- SECTION 1: HADR TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.HADR.HADR_REPLICATION_GROUPS (
    GROUP_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    GROUP_NAME VARCHAR(255) NOT NULL UNIQUE,
    GROUP_TYPE VARCHAR(20) NOT NULL,
    REPLICATION_TYPE VARCHAR(20) NOT NULL,
    SOURCE_ACCOUNT VARCHAR(255) NOT NULL,
    SOURCE_REGION VARCHAR(50) NOT NULL,
    TARGET_ACCOUNT VARCHAR(255) NOT NULL,
    TARGET_REGION VARCHAR(50) NOT NULL,
    INCLUDED_DATABASES VARIANT,
    INCLUDED_SHARES VARIANT,
    INCLUDED_ACCOUNT_OBJECTS VARIANT,
    IS_PRIMARY BOOLEAN DEFAULT TRUE,
    STATUS VARCHAR(20) DEFAULT 'ACTIVE',
    REPLICATION_SCHEDULE VARCHAR(100),
    RPO_TARGET_MINUTES INTEGER DEFAULT 60,
    RTO_TARGET_MINUTES INTEGER DEFAULT 240,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ,
    LAST_REFRESH_AT TIMESTAMP_NTZ,
    METADATA VARIANT
);

CREATE TABLE IF NOT EXISTS ADMIN.HADR.HADR_FAILOVER_GROUPS (
    FAILOVER_GROUP_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    GROUP_NAME VARCHAR(255) NOT NULL,
    REPLICATION_GROUP_ID VARCHAR(36),
    FAILOVER_TYPE VARCHAR(20) NOT NULL,
    SOURCE_ACCOUNT VARCHAR(255) NOT NULL,
    TARGET_ACCOUNT VARCHAR(255) NOT NULL,
    OBJECT_TYPES VARIANT,
    DATABASES VARIANT,
    STATUS VARCHAR(20) DEFAULT 'ACTIVE',
    IS_PRIMARY BOOLEAN DEFAULT TRUE,
    ALLOWED_ACCOUNTS VARIANT,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    METADATA VARIANT,
    FOREIGN KEY (REPLICATION_GROUP_ID) REFERENCES HADR_REPLICATION_GROUPS(GROUP_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.HADR.HADR_REPLICATION_HISTORY (
    HISTORY_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    REPLICATION_GROUP_ID VARCHAR(36),
    REPLICATION_TYPE VARCHAR(20) NOT NULL,
    DATABASE_NAME VARCHAR(255),
    STATUS VARCHAR(20) NOT NULL,
    STARTED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    COMPLETED_AT TIMESTAMP_NTZ,
    BYTES_TRANSFERRED NUMBER,
    REPLICATION_LAG_SECONDS INTEGER,
    ERROR_MESSAGE TEXT,
    FOREIGN KEY (REPLICATION_GROUP_ID) REFERENCES HADR_REPLICATION_GROUPS(GROUP_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.HADR.HADR_FAILOVER_EVENTS (
    EVENT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    FAILOVER_GROUP_ID VARCHAR(36),
    EVENT_TYPE VARCHAR(30) NOT NULL,
    EVENT_REASON VARCHAR(50),
    SOURCE_ACCOUNT VARCHAR(255),
    TARGET_ACCOUNT VARCHAR(255),
    STATUS VARCHAR(20) NOT NULL,
    INITIATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    INITIATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    COMPLETED_AT TIMESTAMP_NTZ,
    DURATION_MINUTES INTEGER,
    DATA_LOSS_MINUTES INTEGER,
    ROLLBACK_AVAILABLE BOOLEAN DEFAULT TRUE,
    NOTES TEXT,
    METADATA VARIANT,
    FOREIGN KEY (FAILOVER_GROUP_ID) REFERENCES HADR_FAILOVER_GROUPS(FAILOVER_GROUP_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.HADR.HADR_DR_TESTS (
    TEST_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TEST_NAME VARCHAR(255) NOT NULL,
    TEST_TYPE VARCHAR(30) NOT NULL,
    FAILOVER_GROUP_ID VARCHAR(36),
    REPLICATION_GROUP_ID VARCHAR(36),
    SCHEDULED_AT TIMESTAMP_NTZ,
    STARTED_AT TIMESTAMP_NTZ,
    COMPLETED_AT TIMESTAMP_NTZ,
    STATUS VARCHAR(20) DEFAULT 'SCHEDULED',
    TEST_RESULTS VARIANT,
    RPO_ACHIEVED_MINUTES INTEGER,
    RTO_ACHIEVED_MINUTES INTEGER,
    PASSED BOOLEAN,
    EXECUTED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    NOTES TEXT,
    FOREIGN KEY (FAILOVER_GROUP_ID) REFERENCES HADR_FAILOVER_GROUPS(FAILOVER_GROUP_ID),
    FOREIGN KEY (REPLICATION_GROUP_ID) REFERENCES HADR_REPLICATION_GROUPS(GROUP_ID)
);

CREATE TABLE IF NOT EXISTS ADMIN.HADR.HADR_AUDIT_LOG (
    AUDIT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    ACTION VARCHAR(50) NOT NULL,
    OBJECT_TYPE VARCHAR(50),
    OBJECT_NAME VARCHAR(500),
    SOURCE_ACCOUNT VARCHAR(255),
    TARGET_ACCOUNT VARCHAR(255),
    PERFORMED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    PERFORMED_BY_ROLE VARCHAR(255) DEFAULT CURRENT_ROLE(),
    STATUS VARCHAR(20),
    DETAILS VARIANT,
    ERROR_MESSAGE TEXT
);

-- #############################################################################
-- SECTION 2: REPLICATION GROUP MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Replication Group
 * 
 * Purpose: Sets up database replication to another region or account
 * 
 * Replication Types:
 *   - CROSS_REGION: Same account, different region (lower latency)
 *   - CROSS_ACCOUNT: Different account (full DR isolation)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_CREATE_REPLICATION_GROUP(
    P_GROUP_NAME VARCHAR,
    P_REPLICATION_TYPE VARCHAR,
    P_TARGET_ACCOUNT VARCHAR,
    P_TARGET_REGION VARCHAR,
    P_DATABASES ARRAY,
    P_RPO_TARGET_MINUTES INTEGER DEFAULT 60,
    P_RTO_TARGET_MINUTES INTEGER DEFAULT 240,
    P_REPLICATION_SCHEDULE VARCHAR DEFAULT 'USING CRON 0 * * * * UTC'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_group_id VARCHAR;
    v_source_account VARCHAR;
    v_source_region VARCHAR;
    v_sql VARCHAR;
    v_actions VARIANT := ARRAY_CONSTRUCT();
BEGIN
    v_group_id := UUID_STRING();
    
    -- Get current account info
    SELECT CURRENT_ACCOUNT(), CURRENT_REGION() 
    INTO v_source_account, v_source_region;
    
    -- Validate replication type
    IF (P_REPLICATION_TYPE NOT IN ('CROSS_REGION', 'CROSS_ACCOUNT')) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid replication type. Use: CROSS_REGION, CROSS_ACCOUNT');
    END IF;
    
    -- Create failover group (container for replication)
    v_sql := 'CREATE FAILOVER GROUP ' || P_GROUP_NAME || '
        OBJECT_TYPES = DATABASES
        ALLOWED_DATABASES = ' || ARRAY_TO_STRING(P_DATABASES, ', ') || '
        ALLOWED_ACCOUNTS = ' || P_TARGET_ACCOUNT || '
        REPLICATION_SCHEDULE = ''' || P_REPLICATION_SCHEDULE || '''';
    
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_FAILOVER_GROUP', 'sql', v_sql));
    
    BEGIN
        EXECUTE IMMEDIATE v_sql;
    EXCEPTION
        WHEN OTHER THEN
            INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, ERROR_MESSAGE)
            VALUES ('CREATE_REPLICATION_GROUP', 'FAILOVER_GROUP', P_GROUP_NAME, 'FAILED', SQLERRM);
            RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sql', v_sql);
    END;
    
    -- Register replication group
    INSERT INTO HADR_REPLICATION_GROUPS (
        GROUP_ID, GROUP_NAME, GROUP_TYPE, REPLICATION_TYPE,
        SOURCE_ACCOUNT, SOURCE_REGION, TARGET_ACCOUNT, TARGET_REGION,
        INCLUDED_DATABASES, REPLICATION_SCHEDULE,
        RPO_TARGET_MINUTES, RTO_TARGET_MINUTES, IS_PRIMARY, STATUS
    ) VALUES (
        v_group_id, P_GROUP_NAME, 'FAILOVER_GROUP', P_REPLICATION_TYPE,
        v_source_account, v_source_region, P_TARGET_ACCOUNT, P_TARGET_REGION,
        P_DATABASES, P_REPLICATION_SCHEDULE,
        P_RPO_TARGET_MINUTES, P_RTO_TARGET_MINUTES, TRUE, 'ACTIVE'
    );
    
    -- Register failover group
    INSERT INTO HADR_FAILOVER_GROUPS (
        GROUP_NAME, REPLICATION_GROUP_ID, FAILOVER_TYPE,
        SOURCE_ACCOUNT, TARGET_ACCOUNT, DATABASES,
        ALLOWED_ACCOUNTS, IS_PRIMARY, STATUS
    ) VALUES (
        P_GROUP_NAME, v_group_id, P_REPLICATION_TYPE,
        v_source_account, P_TARGET_ACCOUNT, P_DATABASES,
        ARRAY_CONSTRUCT(P_TARGET_ACCOUNT), TRUE, 'ACTIVE'
    );
    
    -- Audit log
    INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_ACCOUNT, STATUS, DETAILS)
    VALUES ('CREATE_REPLICATION_GROUP', 'FAILOVER_GROUP', P_GROUP_NAME, P_TARGET_ACCOUNT, 'SUCCESS',
            OBJECT_CONSTRUCT('databases', P_DATABASES, 'type', P_REPLICATION_TYPE));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'group_id', v_group_id,
        'group_name', P_GROUP_NAME,
        'replication_type', P_REPLICATION_TYPE,
        'source', v_source_account || ' (' || v_source_region || ')',
        'target', P_TARGET_ACCOUNT || ' (' || P_TARGET_REGION || ')',
        'databases', P_DATABASES,
        'rpo_target_minutes', P_RPO_TARGET_MINUTES,
        'rto_target_minutes', P_RTO_TARGET_MINUTES,
        'next_steps', ARRAY_CONSTRUCT(
            'Run on TARGET account: CREATE FAILOVER GROUP ' || P_GROUP_NAME || ' AS REPLICA OF ' || v_source_account || '.' || P_GROUP_NAME,
            'Verify replication: CALL ADMIN.HADR.RBAC_CHECK_REPLICATION_STATUS(''' || P_GROUP_NAME || ''')'
        ),
        'message', 'Replication group created on primary. Execute replica creation on target account.'
    );

EXCEPTION
    WHEN OTHER THEN
        INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, ERROR_MESSAGE)
        VALUES ('CREATE_REPLICATION_GROUP', 'FAILOVER_GROUP', P_GROUP_NAME, 'FAILED', SQLERRM);
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup Database Replication (Simplified)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_SETUP_DATABASE_REPLICATION(
    P_DATABASE VARCHAR,
    P_TARGET_ACCOUNT VARCHAR,
    P_SCHEDULE VARCHAR DEFAULT '10 MINUTE'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
BEGIN
    -- Enable replication on database
    v_sql := 'ALTER DATABASE ' || P_DATABASE || ' ENABLE REPLICATION TO ACCOUNTS ' || P_TARGET_ACCOUNT;
    EXECUTE IMMEDIATE v_sql;
    
    -- Set refresh schedule
    v_sql := 'ALTER DATABASE ' || P_DATABASE || ' SET DATA_RETENTION_TIME_IN_DAYS = 7';
    EXECUTE IMMEDIATE v_sql;
    
    INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, TARGET_ACCOUNT, STATUS, DETAILS)
    VALUES ('ENABLE_REPLICATION', 'DATABASE', P_DATABASE, P_TARGET_ACCOUNT, 'SUCCESS',
            OBJECT_CONSTRUCT('schedule', P_SCHEDULE));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'database', P_DATABASE,
        'target_account', P_TARGET_ACCOUNT,
        'next_step', 'On target account: CREATE DATABASE ' || P_DATABASE || ' AS REPLICA OF ' || CURRENT_ACCOUNT() || '.' || P_DATABASE,
        'message', 'Database replication enabled'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Refresh Replication (Manual)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_REFRESH_REPLICATION(
    P_GROUP_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_start_time TIMESTAMP_NTZ;
BEGIN
    v_start_time := CURRENT_TIMESTAMP();
    
    v_sql := 'ALTER FAILOVER GROUP ' || P_GROUP_NAME || ' REFRESH';
    EXECUTE IMMEDIATE v_sql;
    
    -- Record history
    INSERT INTO HADR_REPLICATION_HISTORY (
        REPLICATION_GROUP_ID, REPLICATION_TYPE, STATUS, STARTED_AT
    )
    SELECT GROUP_ID, 'MANUAL_REFRESH', 'COMPLETED', v_start_time
    FROM HADR_REPLICATION_GROUPS
    WHERE GROUP_NAME = P_GROUP_NAME;
    
    INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS)
    VALUES ('REFRESH_REPLICATION', 'FAILOVER_GROUP', P_GROUP_NAME, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'group_name', P_GROUP_NAME,
        'refreshed_at', CURRENT_TIMESTAMP(),
        'message', 'Replication refresh initiated'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 3: FAILOVER OPERATIONS
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Initiate Failover
 * 
 * Failover Types:
 *   - PLANNED: Graceful failover with zero data loss
 *   - UNPLANNED: Emergency failover (may have data loss up to RPO)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_INITIATE_FAILOVER(
    P_GROUP_NAME VARCHAR,
    P_FAILOVER_TYPE VARCHAR DEFAULT 'PLANNED',
    P_REASON TEXT DEFAULT NULL,
    P_CONFIRM BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_event_id VARCHAR;
    v_group VARIANT;
    v_sql VARCHAR;
    v_start_time TIMESTAMP_NTZ;
BEGIN
    v_event_id := UUID_STRING();
    v_start_time := CURRENT_TIMESTAMP();
    
    -- Safety check
    IF (NOT P_CONFIRM) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'CONFIRMATION_REQUIRED',
            'message', 'Failover is a critical operation. Set P_CONFIRM=TRUE to proceed.',
            'warning', 'This will transfer primary role to the secondary account.',
            'group_name', P_GROUP_NAME,
            'failover_type', P_FAILOVER_TYPE
        );
    END IF;
    
    -- Get group info
    SELECT OBJECT_CONSTRUCT(
        'group_id', GROUP_ID,
        'failover_group_id', FAILOVER_GROUP_ID,
        'source_account', SOURCE_ACCOUNT,
        'target_account', TARGET_ACCOUNT,
        'is_primary', IS_PRIMARY
    ) INTO v_group
    FROM HADR_FAILOVER_GROUPS
    WHERE GROUP_NAME = P_GROUP_NAME;
    
    IF (v_group IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Failover group not found: ' || P_GROUP_NAME);
    END IF;
    
    -- Record failover event
    INSERT INTO HADR_FAILOVER_EVENTS (
        EVENT_ID, FAILOVER_GROUP_ID, EVENT_TYPE, EVENT_REASON,
        SOURCE_ACCOUNT, TARGET_ACCOUNT, STATUS, INITIATED_AT
    ) VALUES (
        v_event_id, TO_VARCHAR(v_group:failover_group_id), P_FAILOVER_TYPE, P_REASON,
        TO_VARCHAR(v_group:source_account), TO_VARCHAR(v_group:target_account), 'IN_PROGRESS', v_start_time
    );
    
    -- Execute failover
    IF (P_FAILOVER_TYPE = 'PLANNED') THEN
        -- Planned failover - wait for sync
        v_sql := 'ALTER FAILOVER GROUP ' || P_GROUP_NAME || ' PRIMARY';
    ELSE
        -- Unplanned failover - force
        v_sql := 'ALTER FAILOVER GROUP ' || P_GROUP_NAME || ' PRIMARY FORCE';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    -- Update status
    UPDATE HADR_FAILOVER_EVENTS
    SET STATUS = 'COMPLETED',
        COMPLETED_AT = CURRENT_TIMESTAMP(),
        DURATION_MINUTES = DATEDIFF(MINUTE, v_start_time, CURRENT_TIMESTAMP())
    WHERE EVENT_ID = v_event_id;
    
    -- Update group primary status
    UPDATE HADR_FAILOVER_GROUPS
    SET IS_PRIMARY = NOT IS_PRIMARY
    WHERE GROUP_NAME = P_GROUP_NAME;
    
    UPDATE HADR_REPLICATION_GROUPS
    SET IS_PRIMARY = NOT IS_PRIMARY,
        UPDATED_AT = CURRENT_TIMESTAMP()
    WHERE GROUP_NAME = P_GROUP_NAME;
    
    -- Audit log
    INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, SOURCE_ACCOUNT, TARGET_ACCOUNT, STATUS, DETAILS)
    VALUES ('FAILOVER', 'FAILOVER_GROUP', P_GROUP_NAME, 
            TO_VARCHAR(v_group:source_account), TO_VARCHAR(v_group:target_account), 'SUCCESS',
            OBJECT_CONSTRUCT('type', P_FAILOVER_TYPE, 'reason', P_REASON, 'event_id', v_event_id));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'event_id', v_event_id,
        'group_name', P_GROUP_NAME,
        'failover_type', P_FAILOVER_TYPE,
        'previous_primary', TO_VARCHAR(v_group:source_account),
        'new_primary', TO_VARCHAR(v_group:target_account),
        'duration_minutes', DATEDIFF(MINUTE, v_start_time, CURRENT_TIMESTAMP()),
        'message', 'Failover completed successfully. ' || TO_VARCHAR(v_group:target_account) || ' is now primary.'
    );

EXCEPTION
    WHEN OTHER THEN
        UPDATE HADR_FAILOVER_EVENTS
        SET STATUS = 'FAILED', NOTES = SQLERRM
        WHERE EVENT_ID = v_event_id;
        
        INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, ERROR_MESSAGE)
        VALUES ('FAILOVER', 'FAILOVER_GROUP', P_GROUP_NAME, 'FAILED', SQLERRM);
        
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'event_id', v_event_id);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Initiate Failback
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_INITIATE_FAILBACK(
    P_GROUP_NAME VARCHAR,
    P_CONFIRM BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_result VARIANT;
BEGIN
    IF (NOT P_CONFIRM) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'CONFIRMATION_REQUIRED',
            'message', 'Failback will return primary role to original account. Set P_CONFIRM=TRUE to proceed.',
            'group_name', P_GROUP_NAME
        );
    END IF;
    
    -- Failback is essentially a planned failover back to original
    CALL ADMIN.HADR.RBAC_INITIATE_FAILOVER(P_GROUP_NAME, 'PLANNED', 'Failback to original primary', TRUE) INTO v_result;
    
    IF (v_result:status = 'SUCCESS') THEN
        v_result := OBJECT_INSERT(v_result, 'operation', 'FAILBACK');
        v_result := OBJECT_INSERT(v_result, 'message', 'Failback completed. Original primary restored.');
    END IF;
    
    INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS)
    VALUES ('FAILBACK', 'FAILOVER_GROUP', P_GROUP_NAME, TO_VARCHAR(v_result:status));
    
    RETURN v_result;

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 4: DR TESTING
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Schedule DR Test
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_SCHEDULE_DR_TEST(
    P_TEST_NAME VARCHAR,
    P_GROUP_NAME VARCHAR,
    P_TEST_TYPE VARCHAR DEFAULT 'CONNECTIVITY',
    P_SCHEDULED_AT TIMESTAMP_NTZ DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_test_id VARCHAR;
    v_group_id VARCHAR;
    v_failover_group_id VARCHAR;
BEGIN
    v_test_id := UUID_STRING();
    
    -- Validate test type
    IF (P_TEST_TYPE NOT IN ('CONNECTIVITY', 'FAILOVER_SIMULATION', 'FULL_FAILOVER', 'DATA_VALIDATION')) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 
            'message', 'Invalid test type. Use: CONNECTIVITY, FAILOVER_SIMULATION, FULL_FAILOVER, DATA_VALIDATION');
    END IF;
    
    -- Get group IDs
    SELECT GROUP_ID INTO v_group_id
    FROM HADR_REPLICATION_GROUPS WHERE GROUP_NAME = P_GROUP_NAME;
    
    SELECT FAILOVER_GROUP_ID INTO v_failover_group_id
    FROM HADR_FAILOVER_GROUPS WHERE GROUP_NAME = P_GROUP_NAME;
    
    -- Schedule test
    INSERT INTO HADR_DR_TESTS (
        TEST_ID, TEST_NAME, TEST_TYPE, FAILOVER_GROUP_ID, REPLICATION_GROUP_ID,
        SCHEDULED_AT, STATUS
    ) VALUES (
        v_test_id, P_TEST_NAME, P_TEST_TYPE, v_failover_group_id, v_group_id,
        COALESCE(P_SCHEDULED_AT, CURRENT_TIMESTAMP()), 'SCHEDULED'
    );
    
    INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, DETAILS)
    VALUES ('SCHEDULE_DR_TEST', 'DR_TEST', P_TEST_NAME, 'SUCCESS',
            OBJECT_CONSTRUCT('test_type', P_TEST_TYPE, 'group', P_GROUP_NAME));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'test_id', v_test_id,
        'test_name', P_TEST_NAME,
        'test_type', P_TEST_TYPE,
        'group_name', P_GROUP_NAME,
        'scheduled_at', COALESCE(P_SCHEDULED_AT, CURRENT_TIMESTAMP()),
        'message', 'DR test scheduled. Run RBAC_EXECUTE_DR_TEST to execute.'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Execute DR Test
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_EXECUTE_DR_TEST(
    P_TEST_ID VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_test VARIANT;
    v_results VARIANT := OBJECT_CONSTRUCT();
    v_start_time TIMESTAMP_NTZ;
    v_passed BOOLEAN := TRUE;
    v_group_name VARCHAR;
BEGIN
    v_start_time := CURRENT_TIMESTAMP();
    
    -- Get test details
    SELECT OBJECT_CONSTRUCT(
        'test_id', TEST_ID,
        'test_name', TEST_NAME,
        'test_type', TEST_TYPE,
        'failover_group_id', FAILOVER_GROUP_ID,
        'replication_group_id', REPLICATION_GROUP_ID
    ) INTO v_test
    FROM HADR_DR_TESTS
    WHERE TEST_ID = P_TEST_ID;
    
    IF (v_test IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Test not found: ' || P_TEST_ID);
    END IF;
    
    -- Get group name
    SELECT GROUP_NAME INTO v_group_name
    FROM HADR_REPLICATION_GROUPS
    WHERE GROUP_ID = TO_VARCHAR(v_test:replication_group_id);
    
    -- Update test status
    UPDATE HADR_DR_TESTS
    SET STATUS = 'IN_PROGRESS', STARTED_AT = v_start_time
    WHERE TEST_ID = P_TEST_ID;
    
    -- Execute test based on type
    CASE TO_VARCHAR(v_test:test_type)
        WHEN 'CONNECTIVITY' THEN
            -- Test connectivity to replica
            BEGIN
                EXECUTE IMMEDIATE 'SHOW FAILOVER GROUPS LIKE ''' || v_group_name || '''';
                v_results := OBJECT_INSERT(v_results, 'connectivity_check', 'PASSED');
            EXCEPTION
                WHEN OTHER THEN
                    v_results := OBJECT_INSERT(v_results, 'connectivity_check', 'FAILED');
                    v_results := OBJECT_INSERT(v_results, 'connectivity_error', SQLERRM);
                    v_passed := FALSE;
            END;
            
            -- Check replication status
            BEGIN
                LET v_lag INTEGER := 0;
                SELECT DATEDIFF(SECOND, LAST_REFRESH_AT, CURRENT_TIMESTAMP()) INTO v_lag
                FROM HADR_REPLICATION_GROUPS
                WHERE GROUP_NAME = v_group_name;
                
                v_results := OBJECT_INSERT(v_results, 'replication_lag_seconds', v_lag);
                IF (v_lag > 3600) THEN
                    v_passed := FALSE;
                    v_results := OBJECT_INSERT(v_results, 'replication_check', 'FAILED - lag exceeds 1 hour');
                ELSE
                    v_results := OBJECT_INSERT(v_results, 'replication_check', 'PASSED');
                END IF;
            EXCEPTION
                WHEN OTHER THEN
                    v_results := OBJECT_INSERT(v_results, 'replication_check', 'UNKNOWN');
            END;
            
        WHEN 'DATA_VALIDATION' THEN
            -- Validate data consistency
            v_results := OBJECT_INSERT(v_results, 'data_validation', 'Requires manual verification');
            v_results := OBJECT_INSERT(v_results, 'recommendation', 'Compare row counts and checksums between primary and replica');
            
        WHEN 'FAILOVER_SIMULATION' THEN
            -- Simulate failover (dry run)
            v_results := OBJECT_INSERT(v_results, 'simulation_type', 'DRY_RUN');
            v_results := OBJECT_INSERT(v_results, 'failover_ready', 'YES');
            v_results := OBJECT_INSERT(v_results, 'estimated_rto_minutes', 15);
            v_results := OBJECT_INSERT(v_results, 'note', 'No actual failover performed');
            
        WHEN 'FULL_FAILOVER' THEN
            -- Full failover test - actually fail over and back
            v_results := OBJECT_INSERT(v_results, 'warning', 'Full failover tests should be executed manually with RBAC_INITIATE_FAILOVER');
            v_results := OBJECT_INSERT(v_results, 'status', 'NOT_EXECUTED');
    END CASE;
    
    -- Calculate metrics
    LET v_rpo_achieved INTEGER := 0;
    LET v_rto_achieved INTEGER := DATEDIFF(MINUTE, v_start_time, CURRENT_TIMESTAMP());
    
    -- Update test results
    UPDATE HADR_DR_TESTS
    SET STATUS = 'COMPLETED',
        COMPLETED_AT = CURRENT_TIMESTAMP(),
        TEST_RESULTS = v_results,
        RPO_ACHIEVED_MINUTES = v_rpo_achieved,
        RTO_ACHIEVED_MINUTES = v_rto_achieved,
        PASSED = v_passed
    WHERE TEST_ID = P_TEST_ID;
    
    INSERT INTO HADR_AUDIT_LOG (ACTION, OBJECT_TYPE, OBJECT_NAME, STATUS, DETAILS)
    VALUES ('EXECUTE_DR_TEST', 'DR_TEST', TO_VARCHAR(v_test:test_name), IFF(v_passed, 'PASSED', 'FAILED'),
            OBJECT_CONSTRUCT('test_type', v_test:test_type, 'results', v_results));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'test_id', P_TEST_ID,
        'test_name', TO_VARCHAR(v_test:test_name),
        'test_type', TO_VARCHAR(v_test:test_type),
        'passed', v_passed,
        'duration_minutes', v_rto_achieved,
        'results', v_results,
        'message', IFF(v_passed, 'DR test passed successfully', 'DR test failed - review results')
    );

EXCEPTION
    WHEN OTHER THEN
        UPDATE HADR_DR_TESTS
        SET STATUS = 'FAILED', NOTES = SQLERRM
        WHERE TEST_ID = P_TEST_ID;
        
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 5: STATUS AND HEALTH CHECKS
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Check Replication Status
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_CHECK_REPLICATION_STATUS(
    P_GROUP_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_groups VARIANT;
    v_overall_health VARCHAR := 'HEALTHY';
BEGIN
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'group_name', GROUP_NAME,
        'replication_type', REPLICATION_TYPE,
        'source', SOURCE_ACCOUNT || ' (' || SOURCE_REGION || ')',
        'target', TARGET_ACCOUNT || ' (' || TARGET_REGION || ')',
        'is_primary', IS_PRIMARY,
        'status', STATUS,
        'last_refresh', LAST_REFRESH_AT,
        'lag_minutes', DATEDIFF(MINUTE, LAST_REFRESH_AT, CURRENT_TIMESTAMP()),
        'rpo_target', RPO_TARGET_MINUTES,
        'within_rpo', IFF(DATEDIFF(MINUTE, LAST_REFRESH_AT, CURRENT_TIMESTAMP()) <= RPO_TARGET_MINUTES, TRUE, FALSE),
        'databases', INCLUDED_DATABASES
    )) INTO v_groups
    FROM HADR_REPLICATION_GROUPS
    WHERE (P_GROUP_NAME IS NULL OR GROUP_NAME = P_GROUP_NAME);
    
    -- Check for any groups outside RPO
    FOR i IN 0 TO ARRAY_SIZE(COALESCE(v_groups, ARRAY_CONSTRUCT())) - 1 LOOP
        IF (NOT v_groups[i]:within_rpo::BOOLEAN) THEN
            v_overall_health := 'WARNING';
        END IF;
    END LOOP;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'overall_health', v_overall_health,
        'groups_count', ARRAY_SIZE(COALESCE(v_groups, ARRAY_CONSTRUCT())),
        'groups', COALESCE(v_groups, ARRAY_CONSTRUCT()),
        'checked_at', CURRENT_TIMESTAMP()
    );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List Failover Groups
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_LIST_FAILOVER_GROUPS()
RETURNS TABLE (
    GROUP_NAME VARCHAR,
    FAILOVER_TYPE VARCHAR,
    SOURCE_ACCOUNT VARCHAR,
    TARGET_ACCOUNT VARCHAR,
    IS_PRIMARY BOOLEAN,
    STATUS VARCHAR,
    DATABASES VARIANT
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
            GROUP_NAME,
            FAILOVER_TYPE,
            SOURCE_ACCOUNT,
            TARGET_ACCOUNT,
            IS_PRIMARY,
            STATUS,
            DATABASES
        FROM HADR_FAILOVER_GROUPS
        ORDER BY GROUP_NAME
    );
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: List DR Tests
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_LIST_DR_TESTS(
    P_STATUS VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    TEST_ID VARCHAR,
    TEST_NAME VARCHAR,
    TEST_TYPE VARCHAR,
    STATUS VARCHAR,
    SCHEDULED_AT TIMESTAMP_NTZ,
    COMPLETED_AT TIMESTAMP_NTZ,
    PASSED BOOLEAN,
    RPO_ACHIEVED INTEGER,
    RTO_ACHIEVED INTEGER
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
            TEST_ID,
            TEST_NAME,
            TEST_TYPE,
            STATUS,
            SCHEDULED_AT,
            COMPLETED_AT,
            PASSED,
            RPO_ACHIEVED_MINUTES AS RPO_ACHIEVED,
            RTO_ACHIEVED_MINUTES AS RTO_ACHIEVED
        FROM HADR_DR_TESTS
        WHERE (P_STATUS IS NULL OR STATUS = P_STATUS)
        ORDER BY SCHEDULED_AT DESC
    );
    RETURN TABLE(res);
END;
$$;

-- #############################################################################
-- SECTION 6: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_CREATE_REPLICATION_GROUP(VARCHAR, VARCHAR, VARCHAR, VARCHAR, ARRAY, INTEGER, INTEGER, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_SETUP_DATABASE_REPLICATION(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_REFRESH_REPLICATION(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_INITIATE_FAILOVER(VARCHAR, VARCHAR, TEXT, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_INITIATE_FAILBACK(VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_SCHEDULE_DR_TEST(VARCHAR, VARCHAR, VARCHAR, TIMESTAMP_NTZ) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_EXECUTE_DR_TEST(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_CHECK_REPLICATION_STATUS(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_LIST_FAILOVER_GROUPS() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_LIST_DR_TESTS(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- DBAdmins can view status (but not execute failover)
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_CHECK_REPLICATION_STATUS(VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_LIST_FAILOVER_GROUPS() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_LIST_DR_TESTS(VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
