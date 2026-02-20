/*******************************************************************************
 * RBAC STORED PROCEDURE: Security Policy Management
 * 
 * Purpose: Comprehensive management of Snowflake security policies including:
 *          - Network Policies (IP allow/block lists)
 *          - Password Policies (complexity, rotation, history)
 *          - Session Policies (timeout, idle time)
 *          - Authentication Policies (MFA, allowed methods)
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          SECURITY
 *   Object Type:     TABLES (5), PROCEDURES (~20)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN, ACCOUNTADMIN (for policy creation)
 * 
 *   Dependencies:    
 *     - ADMIN database and SECURITY schema must exist
 *     - Enterprise edition required for some policy types
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * POLICY TYPES SUPPORTED
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   NETWORK POLICIES
 *   ─────────────────────────────────────────────────────────────────────────────
 *   Control network access to Snowflake account
 *   - ALLOWED_IP_LIST: IPs that CAN connect
 *   - BLOCKED_IP_LIST: IPs that CANNOT connect (takes precedence)
 *   - Can be assigned to: Account, User, or Security Integration
 * 
 *   PASSWORD POLICIES
 *   ─────────────────────────────────────────────────────────────────────────────
 *   Control password requirements for users
 *   - MIN_LENGTH, MAX_LENGTH
 *   - MIN_UPPER_CASE_CHARS, MIN_LOWER_CASE_CHARS
 *   - MIN_NUMERIC_CHARS, MIN_SPECIAL_CHARS
 *   - MAX_AGE_DAYS, MAX_RETRIES, LOCKOUT_TIME_MINS
 *   - PASSWORD_HISTORY (prevent reuse)
 * 
 *   SESSION POLICIES
 *   ─────────────────────────────────────────────────────────────────────────────
 *   Control session behavior
 *   - SESSION_IDLE_TIMEOUT_MINS
 *   - SESSION_UI_IDLE_TIMEOUT_MINS
 * 
 *   AUTHENTICATION POLICIES
 *   ─────────────────────────────────────────────────────────────────────────────
 *   Control authentication methods
 *   - AUTHENTICATION_METHODS (PASSWORD, SAML, OAUTH, KEYPAIR)
 *   - MFA_AUTHENTICATION_METHODS
 *   - CLIENT_TYPES (SNOWFLAKE_UI, DRIVERS, SNOWSQL)
 *   - SECURITY_INTEGRATIONS
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * POLICY HIERARCHY
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │                         POLICY APPLICATION LEVELS                       │
 *   ├─────────────────────────────────────────────────────────────────────────┤
 *   │                                                                         │
 *   │   ACCOUNT LEVEL (Default for all users)                                │
 *   │       │                                                                 │
 *   │       ├── Network Policy ──► Applied to all connections                │
 *   │       ├── Password Policy ──► Default for all users                    │
 *   │       ├── Session Policy ──► Default session timeouts                  │
 *   │       └── Authentication Policy ──► Default auth methods               │
 *   │                                                                         │
 *   │   USER LEVEL (Override account defaults)                               │
 *   │       │                                                                 │
 *   │       ├── Network Policy ──► User-specific IP restrictions             │
 *   │       ├── Password Policy ──► User-specific password rules             │
 *   │       ├── Session Policy ──► User-specific timeouts                    │
 *   │       └── Authentication Policy ──► User-specific auth methods         │
 *   │                                                                         │
 *   │   SECURITY INTEGRATION LEVEL (For SSO/OAuth)                           │
 *   │       │                                                                 │
 *   │       └── Network Policy ──► Integration-specific IP restrictions      │
 *   │                                                                         │
 *   └─────────────────────────────────────────────────────────────────────────┘
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * STANDARD POLICY TEMPLATES
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   RESTRICTIVE (Production/Sensitive)
 *   ─────────────────────────────────────────────────────────────────────────────
 *   - Network: Specific corporate IPs only
 *   - Password: 14+ chars, complexity, 90-day rotation
 *   - Session: 30 min idle timeout
 *   - Auth: MFA required, limited methods
 * 
 *   STANDARD (General Business)
 *   ─────────────────────────────────────────────────────────────────────────────
 *   - Network: Corporate ranges + VPN
 *   - Password: 12+ chars, complexity, 180-day rotation
 *   - Session: 60 min idle timeout
 *   - Auth: MFA encouraged, standard methods
 * 
 *   RELAXED (Development/Testing)
 *   ─────────────────────────────────────────────────────────────────────────────
 *   - Network: Broader IP ranges
 *   - Password: 8+ chars, basic complexity
 *   - Session: 120 min idle timeout
 *   - Auth: Multiple methods allowed
 * 
 *   SERVICE ACCOUNT
 *   ─────────────────────────────────────────────────────────────────────────────
 *   - Network: Specific service IPs only
 *   - Password: N/A (key-pair auth)
 *   - Session: No idle timeout
 *   - Auth: Key-pair only, no interactive
 * 
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA SECURITY;

-- #############################################################################
-- SECTION 1: POLICY TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.SECURITY.POLICY_REGISTRY (
    POLICY_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_TYPE VARCHAR(50) NOT NULL,
    POLICY_NAME VARCHAR(255) NOT NULL,
    POLICY_TEMPLATE VARCHAR(50),
    DESCRIPTION VARCHAR(1000),
    CONFIGURATION VARIANT,
    APPLIED_TO_ACCOUNT BOOLEAN DEFAULT FALSE,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_BY VARCHAR(255),
    UPDATED_AT TIMESTAMP_NTZ,
    STATUS VARCHAR(20) DEFAULT 'ACTIVE',
    CONSTRAINT UQ_POLICY_TYPE_NAME UNIQUE (POLICY_TYPE, POLICY_NAME)
);

CREATE TABLE IF NOT EXISTS ADMIN.SECURITY.POLICY_ASSIGNMENTS (
    ASSIGNMENT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_TYPE VARCHAR(50) NOT NULL,
    POLICY_NAME VARCHAR(255) NOT NULL,
    ASSIGNMENT_LEVEL VARCHAR(50) NOT NULL,
    ASSIGNED_TO VARCHAR(255) NOT NULL,
    ASSIGNED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    ASSIGNED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PREVIOUS_POLICY VARCHAR(255),
    STATUS VARCHAR(20) DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS ADMIN.SECURITY.POLICY_TEMPLATES (
    TEMPLATE_NAME VARCHAR(50) PRIMARY KEY,
    POLICY_TYPE VARCHAR(50) NOT NULL,
    DESCRIPTION VARCHAR(500),
    CONFIGURATION VARIANT NOT NULL,
    IS_DEFAULT BOOLEAN DEFAULT FALSE,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS ADMIN.SECURITY.POLICY_AUDIT_LOG (
    AUDIT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    AUDIT_TIMESTAMP TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    POLICY_TYPE VARCHAR(50) NOT NULL,
    POLICY_NAME VARCHAR(255) NOT NULL,
    ACTION VARCHAR(50) NOT NULL,
    ACTION_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    TARGET_TYPE VARCHAR(50),
    TARGET_NAME VARCHAR(255),
    OLD_VALUE VARIANT,
    NEW_VALUE VARIANT,
    RESULT VARCHAR(20),
    ERROR_MESSAGE VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS ADMIN.SECURITY.POLICY_EXCEPTIONS (
    EXCEPTION_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    POLICY_TYPE VARCHAR(50) NOT NULL,
    POLICY_NAME VARCHAR(255) NOT NULL,
    EXCEPTION_TARGET VARCHAR(255) NOT NULL,
    EXCEPTION_REASON VARCHAR(1000) NOT NULL,
    APPROVED_BY VARCHAR(255),
    APPROVED_AT TIMESTAMP_NTZ,
    EXPIRES_AT TIMESTAMP_NTZ,
    STATUS VARCHAR(20) DEFAULT 'PENDING',
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- #############################################################################
-- SECTION 2: NETWORK POLICY MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Create Network Policy
 * 
 * Purpose: Creates a new network policy with specified IP allow/block lists
 * 
 * Parameters:
 *   P_POLICY_NAME       - Unique name for the network policy
 *   P_ALLOWED_IP_LIST   - Array of allowed IP addresses/CIDR ranges
 *   P_BLOCKED_IP_LIST   - Array of blocked IP addresses/CIDR ranges (optional)
 *   P_COMMENT           - Description of the policy
 *   P_TEMPLATE          - Template name (RESTRICTIVE, STANDARD, RELAXED, SERVICE)
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.SECURITY.POLICY_CREATE_NETWORK_POLICY(
    P_POLICY_NAME VARCHAR,
    P_ALLOWED_IP_LIST ARRAY,
    P_BLOCKED_IP_LIST ARRAY,
    P_COMMENT VARCHAR,
    P_TEMPLATE VARCHAR
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS OWNER
AS
$$
    var allowedStr = P_ALLOWED_IP_LIST.join(',');
    var blockedStr = '';
    
    if (P_BLOCKED_IP_LIST && P_BLOCKED_IP_LIST.length > 0) {
        blockedStr = P_BLOCKED_IP_LIST.join(',');
    }
    
    var sql = 'CREATE OR REPLACE NETWORK POLICY ' + P_POLICY_NAME + 
              ' ALLOWED_IP_LIST = (' + allowedStr + ')';
    
    if (blockedStr !== '') {
        sql += ' BLOCKED_IP_LIST = (' + blockedStr + ')';
    }
    
    if (P_COMMENT) {
        sql += ' COMMENT = \'' + P_COMMENT + '\'';
    }
    
    try {
        snowflake.createStatement({sqlText: sql}).execute();
        
        snowflake.createStatement({
            sqlText: `INSERT INTO ADMIN.SECURITY.POLICY_REGISTRY 
                (POLICY_TYPE, POLICY_NAME, POLICY_TEMPLATE, DESCRIPTION, CONFIGURATION)
            VALUES (?, ?, ?, ?, PARSE_JSON(?))`,
            binds: [
                'NETWORK',
                P_POLICY_NAME,
                P_TEMPLATE,
                P_COMMENT,
                JSON.stringify({
                    allowed_ip_list: P_ALLOWED_IP_LIST,
                    blocked_ip_list: P_BLOCKED_IP_LIST
                })
            ]
        }).execute();
        
        snowflake.createStatement({
            sqlText: `INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
                (POLICY_TYPE, POLICY_NAME, ACTION, NEW_VALUE, RESULT)
            VALUES (?, ?, ?, PARSE_JSON(?), ?)`,
            binds: [
                'NETWORK',
                P_POLICY_NAME,
                'CREATE',
                JSON.stringify({allowed_ip_list: P_ALLOWED_IP_LIST, blocked_ip_list: P_BLOCKED_IP_LIST}),
                'SUCCESS'
            ]
        }).execute();
        
        return {
            status: 'SUCCESS',
            policy_type: 'NETWORK',
            policy_name: P_POLICY_NAME,
            allowed_ips: P_ALLOWED_IP_LIST.length,
            blocked_ips: P_BLOCKED_IP_LIST ? P_BLOCKED_IP_LIST.length : 0
        };
    } catch(err) {
        snowflake.createStatement({
            sqlText: `INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
                (POLICY_TYPE, POLICY_NAME, ACTION, RESULT, ERROR_MESSAGE)
            VALUES (?, ?, ?, ?, ?)`,
            binds: ['NETWORK', P_POLICY_NAME, 'CREATE', 'FAILED', err.message]
        }).execute();
        
        return {status: 'ERROR', message: err.message};
    }
$$;

/*******************************************************************************
 * PROCEDURE: Modify Network Policy
 * 
 * Purpose: Adds or removes IP addresses from an existing network policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_MODIFY_NETWORK_POLICY(
    P_POLICY_NAME VARCHAR,
    P_ACTION VARCHAR,
    P_IP_LIST ARRAY,
    P_LIST_TYPE VARCHAR DEFAULT 'ALLOWED'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_result VARIANT;
    v_current_config VARIANT;
    v_current_list ARRAY;
    v_new_list ARRAY;
    v_sql VARCHAR;
BEGIN
    SELECT CONFIGURATION INTO v_current_config
    FROM ADMIN.SECURITY.POLICY_REGISTRY
    WHERE POLICY_TYPE = 'NETWORK' AND POLICY_NAME = P_POLICY_NAME;
    
    IF (P_LIST_TYPE = 'ALLOWED') THEN
        v_current_list := v_current_config:allowed_ip_list::ARRAY;
    ELSE
        v_current_list := v_current_config:blocked_ip_list::ARRAY;
    END IF;
    
    IF (P_ACTION = 'ADD') THEN
        v_new_list := ARRAY_CAT(COALESCE(v_current_list, ARRAY_CONSTRUCT()), P_IP_LIST);
    ELSEIF (P_ACTION = 'REMOVE') THEN
        v_new_list := ARRAY_CONSTRUCT();
        FOR i IN 0 TO ARRAY_SIZE(v_current_list) - 1 DO
            IF (NOT ARRAY_CONTAINS(v_current_list[i]::VARIANT, P_IP_LIST)) THEN
                v_new_list := ARRAY_APPEND(v_new_list, v_current_list[i]);
            END IF;
        END FOR;
    END IF;
    
    v_sql := 'ALTER NETWORK POLICY ' || P_POLICY_NAME || 
             ' SET ' || P_LIST_TYPE || '_IP_LIST = (' || ARRAY_TO_STRING(v_new_list, ',') || ')';
    
    EXECUTE IMMEDIATE v_sql;
    
    IF (P_LIST_TYPE = 'ALLOWED') THEN
        UPDATE ADMIN.SECURITY.POLICY_REGISTRY
        SET CONFIGURATION = OBJECT_INSERT(CONFIGURATION, 'allowed_ip_list', v_new_list, TRUE),
            UPDATED_BY = CURRENT_USER(),
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE POLICY_TYPE = 'NETWORK' AND POLICY_NAME = P_POLICY_NAME;
    ELSE
        UPDATE ADMIN.SECURITY.POLICY_REGISTRY
        SET CONFIGURATION = OBJECT_INSERT(CONFIGURATION, 'blocked_ip_list', v_new_list, TRUE),
            UPDATED_BY = CURRENT_USER(),
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE POLICY_TYPE = 'NETWORK' AND POLICY_NAME = P_POLICY_NAME;
    END IF;
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, OLD_VALUE, NEW_VALUE, RESULT)
    VALUES (
        'NETWORK',
        P_POLICY_NAME,
        P_ACTION || '_IP',
        OBJECT_CONSTRUCT('list_type', P_LIST_TYPE, 'ips', v_current_list),
        OBJECT_CONSTRUCT('list_type', P_LIST_TYPE, 'ips', v_new_list),
        'SUCCESS'
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'action', P_ACTION,
        'list_type', P_LIST_TYPE,
        'modified_ips', ARRAY_SIZE(P_IP_LIST),
        'total_ips', ARRAY_SIZE(v_new_list)
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * PROCEDURE: Assign Network Policy
 * 
 * Purpose: Assigns a network policy to account, user, or security integration
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_ASSIGN_NETWORK_POLICY(
    P_POLICY_NAME VARCHAR,
    P_ASSIGNMENT_LEVEL VARCHAR,
    P_TARGET_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_result VARIANT;
    v_sql VARCHAR;
    v_previous_policy VARCHAR;
BEGIN
    IF (P_ASSIGNMENT_LEVEL = 'ACCOUNT') THEN
        v_sql := 'ALTER ACCOUNT SET NETWORK_POLICY = ' || P_POLICY_NAME;
        
        UPDATE ADMIN.SECURITY.POLICY_REGISTRY
        SET APPLIED_TO_ACCOUNT = TRUE,
            UPDATED_BY = CURRENT_USER(),
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE POLICY_TYPE = 'NETWORK' AND POLICY_NAME = P_POLICY_NAME;
        
    ELSEIF (P_ASSIGNMENT_LEVEL = 'USER') THEN
        v_sql := 'ALTER USER ' || P_TARGET_NAME || ' SET NETWORK_POLICY = ' || P_POLICY_NAME;
        
    ELSEIF (P_ASSIGNMENT_LEVEL = 'INTEGRATION') THEN
        v_sql := 'ALTER SECURITY INTEGRATION ' || P_TARGET_NAME || ' SET NETWORK_POLICY = ' || P_POLICY_NAME;
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    INSERT INTO ADMIN.SECURITY.POLICY_ASSIGNMENTS 
        (POLICY_TYPE, POLICY_NAME, ASSIGNMENT_LEVEL, ASSIGNED_TO)
    VALUES ('NETWORK', P_POLICY_NAME, P_ASSIGNMENT_LEVEL, COALESCE(P_TARGET_NAME, 'ACCOUNT'));
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, TARGET_TYPE, TARGET_NAME, RESULT)
    VALUES ('NETWORK', P_POLICY_NAME, 'ASSIGN', P_ASSIGNMENT_LEVEL, COALESCE(P_TARGET_NAME, 'ACCOUNT'), 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_name', P_POLICY_NAME,
        'assignment_level', P_ASSIGNMENT_LEVEL,
        'target', COALESCE(P_TARGET_NAME, 'ACCOUNT')
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 3: PASSWORD POLICY MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Create Password Policy
 * 
 * Purpose: Creates a new password policy with specified requirements
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_CREATE_PASSWORD_POLICY(
    P_POLICY_NAME VARCHAR,
    P_MIN_LENGTH INTEGER DEFAULT 12,
    P_MAX_LENGTH INTEGER DEFAULT 256,
    P_MIN_UPPER_CASE INTEGER DEFAULT 1,
    P_MIN_LOWER_CASE INTEGER DEFAULT 1,
    P_MIN_NUMERIC INTEGER DEFAULT 1,
    P_MIN_SPECIAL INTEGER DEFAULT 1,
    P_MAX_AGE_DAYS INTEGER DEFAULT 90,
    P_MAX_RETRIES INTEGER DEFAULT 5,
    P_LOCKOUT_TIME_MINS INTEGER DEFAULT 15,
    P_PASSWORD_HISTORY INTEGER DEFAULT 5,
    P_COMMENT VARCHAR DEFAULT NULL,
    P_TEMPLATE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_result VARIANT;
    v_sql VARCHAR;
    v_config VARIANT;
BEGIN
    v_sql := 'CREATE OR REPLACE PASSWORD POLICY ' || P_POLICY_NAME ||
             ' PASSWORD_MIN_LENGTH = ' || P_MIN_LENGTH ||
             ' PASSWORD_MAX_LENGTH = ' || P_MAX_LENGTH ||
             ' PASSWORD_MIN_UPPER_CASE_CHARS = ' || P_MIN_UPPER_CASE ||
             ' PASSWORD_MIN_LOWER_CASE_CHARS = ' || P_MIN_LOWER_CASE ||
             ' PASSWORD_MIN_NUMERIC_CHARS = ' || P_MIN_NUMERIC ||
             ' PASSWORD_MIN_SPECIAL_CHARS = ' || P_MIN_SPECIAL ||
             ' PASSWORD_MAX_AGE_DAYS = ' || P_MAX_AGE_DAYS ||
             ' PASSWORD_MAX_RETRIES = ' || P_MAX_RETRIES ||
             ' PASSWORD_LOCKOUT_TIME_MINS = ' || P_LOCKOUT_TIME_MINS ||
             ' PASSWORD_HISTORY = ' || P_PASSWORD_HISTORY;
    
    IF (P_COMMENT IS NOT NULL) THEN
        v_sql := v_sql || ' COMMENT = ''' || P_COMMENT || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    v_config := OBJECT_CONSTRUCT(
        'min_length', P_MIN_LENGTH,
        'max_length', P_MAX_LENGTH,
        'min_upper_case', P_MIN_UPPER_CASE,
        'min_lower_case', P_MIN_LOWER_CASE,
        'min_numeric', P_MIN_NUMERIC,
        'min_special', P_MIN_SPECIAL,
        'max_age_days', P_MAX_AGE_DAYS,
        'max_retries', P_MAX_RETRIES,
        'lockout_time_mins', P_LOCKOUT_TIME_MINS,
        'password_history', P_PASSWORD_HISTORY
    );
    
    INSERT INTO ADMIN.SECURITY.POLICY_REGISTRY 
        (POLICY_TYPE, POLICY_NAME, POLICY_TEMPLATE, DESCRIPTION, CONFIGURATION)
    VALUES ('PASSWORD', P_POLICY_NAME, P_TEMPLATE, P_COMMENT, v_config);
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, NEW_VALUE, RESULT)
    VALUES ('PASSWORD', P_POLICY_NAME, 'CREATE', v_config, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_type', 'PASSWORD',
        'policy_name', P_POLICY_NAME,
        'configuration', v_config
    );
EXCEPTION
    WHEN OTHER THEN
        INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
            (POLICY_TYPE, POLICY_NAME, ACTION, RESULT, ERROR_MESSAGE)
        VALUES ('PASSWORD', P_POLICY_NAME, 'CREATE', 'FAILED', SQLERRM);
        
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * PROCEDURE: Assign Password Policy
 * 
 * Purpose: Assigns a password policy to account or user
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_ASSIGN_PASSWORD_POLICY(
    P_POLICY_NAME VARCHAR,
    P_ASSIGNMENT_LEVEL VARCHAR,
    P_TARGET_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_sql VARCHAR;
BEGIN
    IF (P_ASSIGNMENT_LEVEL = 'ACCOUNT') THEN
        v_sql := 'ALTER ACCOUNT SET PASSWORD POLICY ' || P_POLICY_NAME;
        
        UPDATE ADMIN.SECURITY.POLICY_REGISTRY
        SET APPLIED_TO_ACCOUNT = TRUE,
            UPDATED_BY = CURRENT_USER(),
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE POLICY_TYPE = 'PASSWORD' AND POLICY_NAME = P_POLICY_NAME;
        
    ELSEIF (P_ASSIGNMENT_LEVEL = 'USER') THEN
        v_sql := 'ALTER USER ' || P_TARGET_NAME || ' SET PASSWORD POLICY ' || P_POLICY_NAME;
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    INSERT INTO ADMIN.SECURITY.POLICY_ASSIGNMENTS 
        (POLICY_TYPE, POLICY_NAME, ASSIGNMENT_LEVEL, ASSIGNED_TO)
    VALUES ('PASSWORD', P_POLICY_NAME, P_ASSIGNMENT_LEVEL, COALESCE(P_TARGET_NAME, 'ACCOUNT'));
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, TARGET_TYPE, TARGET_NAME, RESULT)
    VALUES ('PASSWORD', P_POLICY_NAME, 'ASSIGN', P_ASSIGNMENT_LEVEL, COALESCE(P_TARGET_NAME, 'ACCOUNT'), 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_name', P_POLICY_NAME,
        'assignment_level', P_ASSIGNMENT_LEVEL,
        'target', COALESCE(P_TARGET_NAME, 'ACCOUNT')
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 4: SESSION POLICY MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Create Session Policy
 * 
 * Purpose: Creates a new session policy with specified timeout settings
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_CREATE_SESSION_POLICY(
    P_POLICY_NAME VARCHAR,
    P_SESSION_IDLE_TIMEOUT_MINS INTEGER DEFAULT 60,
    P_SESSION_UI_IDLE_TIMEOUT_MINS INTEGER DEFAULT 60,
    P_COMMENT VARCHAR DEFAULT NULL,
    P_TEMPLATE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_config VARIANT;
BEGIN
    v_sql := 'CREATE OR REPLACE SESSION POLICY ' || P_POLICY_NAME ||
             ' SESSION_IDLE_TIMEOUT_MINS = ' || P_SESSION_IDLE_TIMEOUT_MINS ||
             ' SESSION_UI_IDLE_TIMEOUT_MINS = ' || P_SESSION_UI_IDLE_TIMEOUT_MINS;
    
    IF (P_COMMENT IS NOT NULL) THEN
        v_sql := v_sql || ' COMMENT = ''' || P_COMMENT || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    v_config := OBJECT_CONSTRUCT(
        'session_idle_timeout_mins', P_SESSION_IDLE_TIMEOUT_MINS,
        'session_ui_idle_timeout_mins', P_SESSION_UI_IDLE_TIMEOUT_MINS
    );
    
    INSERT INTO ADMIN.SECURITY.POLICY_REGISTRY 
        (POLICY_TYPE, POLICY_NAME, POLICY_TEMPLATE, DESCRIPTION, CONFIGURATION)
    VALUES ('SESSION', P_POLICY_NAME, P_TEMPLATE, P_COMMENT, v_config);
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, NEW_VALUE, RESULT)
    VALUES ('SESSION', P_POLICY_NAME, 'CREATE', v_config, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_type', 'SESSION',
        'policy_name', P_POLICY_NAME,
        'configuration', v_config
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * PROCEDURE: Assign Session Policy
 * 
 * Purpose: Assigns a session policy to account or user
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_ASSIGN_SESSION_POLICY(
    P_POLICY_NAME VARCHAR,
    P_ASSIGNMENT_LEVEL VARCHAR,
    P_TARGET_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_sql VARCHAR;
BEGIN
    IF (P_ASSIGNMENT_LEVEL = 'ACCOUNT') THEN
        v_sql := 'ALTER ACCOUNT SET SESSION POLICY ' || P_POLICY_NAME;
        
        UPDATE ADMIN.SECURITY.POLICY_REGISTRY
        SET APPLIED_TO_ACCOUNT = TRUE,
            UPDATED_BY = CURRENT_USER(),
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE POLICY_TYPE = 'SESSION' AND POLICY_NAME = P_POLICY_NAME;
        
    ELSEIF (P_ASSIGNMENT_LEVEL = 'USER') THEN
        v_sql := 'ALTER USER ' || P_TARGET_NAME || ' SET SESSION POLICY ' || P_POLICY_NAME;
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    INSERT INTO ADMIN.SECURITY.POLICY_ASSIGNMENTS 
        (POLICY_TYPE, POLICY_NAME, ASSIGNMENT_LEVEL, ASSIGNED_TO)
    VALUES ('SESSION', P_POLICY_NAME, P_ASSIGNMENT_LEVEL, COALESCE(P_TARGET_NAME, 'ACCOUNT'));
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, TARGET_TYPE, TARGET_NAME, RESULT)
    VALUES ('SESSION', P_POLICY_NAME, 'ASSIGN', P_ASSIGNMENT_LEVEL, COALESCE(P_TARGET_NAME, 'ACCOUNT'), 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_name', P_POLICY_NAME,
        'assignment_level', P_ASSIGNMENT_LEVEL,
        'target', COALESCE(P_TARGET_NAME, 'ACCOUNT')
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 5: AUTHENTICATION POLICY MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Create Authentication Policy
 * 
 * Purpose: Creates a new authentication policy with specified methods
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_CREATE_AUTHENTICATION_POLICY(
    P_POLICY_NAME VARCHAR,
    P_AUTH_METHODS ARRAY DEFAULT ARRAY_CONSTRUCT('PASSWORD', 'SAML'),
    P_MFA_AUTH_METHODS ARRAY DEFAULT ARRAY_CONSTRUCT('TOTP'),
    P_CLIENT_TYPES ARRAY DEFAULT ARRAY_CONSTRUCT('SNOWFLAKE_UI', 'SNOWSQL', 'DRIVERS'),
    P_SECURITY_INTEGRATIONS ARRAY DEFAULT NULL,
    P_COMMENT VARCHAR DEFAULT NULL,
    P_TEMPLATE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_config VARIANT;
BEGIN
    v_sql := 'CREATE OR REPLACE AUTHENTICATION POLICY ' || P_POLICY_NAME ||
             ' AUTHENTICATION_METHODS = (' || ARRAY_TO_STRING(P_AUTH_METHODS, ',') || ')' ||
             ' MFA_AUTHENTICATION_METHODS = (' || ARRAY_TO_STRING(P_MFA_AUTH_METHODS, ',') || ')' ||
             ' CLIENT_TYPES = (' || ARRAY_TO_STRING(P_CLIENT_TYPES, ',') || ')';
    
    IF (P_SECURITY_INTEGRATIONS IS NOT NULL AND ARRAY_SIZE(P_SECURITY_INTEGRATIONS) > 0) THEN
        v_sql := v_sql || ' SECURITY_INTEGRATIONS = (' || ARRAY_TO_STRING(P_SECURITY_INTEGRATIONS, ',') || ')';
    END IF;
    
    IF (P_COMMENT IS NOT NULL) THEN
        v_sql := v_sql || ' COMMENT = ''' || P_COMMENT || '''';
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    v_config := OBJECT_CONSTRUCT(
        'authentication_methods', P_AUTH_METHODS,
        'mfa_authentication_methods', P_MFA_AUTH_METHODS,
        'client_types', P_CLIENT_TYPES,
        'security_integrations', P_SECURITY_INTEGRATIONS
    );
    
    INSERT INTO ADMIN.SECURITY.POLICY_REGISTRY 
        (POLICY_TYPE, POLICY_NAME, POLICY_TEMPLATE, DESCRIPTION, CONFIGURATION)
    VALUES ('AUTHENTICATION', P_POLICY_NAME, P_TEMPLATE, P_COMMENT, v_config);
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, NEW_VALUE, RESULT)
    VALUES ('AUTHENTICATION', P_POLICY_NAME, 'CREATE', v_config, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_type', 'AUTHENTICATION',
        'policy_name', P_POLICY_NAME,
        'configuration', v_config
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * PROCEDURE: Assign Authentication Policy
 * 
 * Purpose: Assigns an authentication policy to account or user
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_ASSIGN_AUTHENTICATION_POLICY(
    P_POLICY_NAME VARCHAR,
    P_ASSIGNMENT_LEVEL VARCHAR,
    P_TARGET_NAME VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_sql VARCHAR;
BEGIN
    IF (P_ASSIGNMENT_LEVEL = 'ACCOUNT') THEN
        v_sql := 'ALTER ACCOUNT SET AUTHENTICATION POLICY ' || P_POLICY_NAME;
        
        UPDATE ADMIN.SECURITY.POLICY_REGISTRY
        SET APPLIED_TO_ACCOUNT = TRUE,
            UPDATED_BY = CURRENT_USER(),
            UPDATED_AT = CURRENT_TIMESTAMP()
        WHERE POLICY_TYPE = 'AUTHENTICATION' AND POLICY_NAME = P_POLICY_NAME;
        
    ELSEIF (P_ASSIGNMENT_LEVEL = 'USER') THEN
        v_sql := 'ALTER USER ' || P_TARGET_NAME || ' SET AUTHENTICATION POLICY ' || P_POLICY_NAME;
    END IF;
    
    EXECUTE IMMEDIATE v_sql;
    
    INSERT INTO ADMIN.SECURITY.POLICY_ASSIGNMENTS 
        (POLICY_TYPE, POLICY_NAME, ASSIGNMENT_LEVEL, ASSIGNED_TO)
    VALUES ('AUTHENTICATION', P_POLICY_NAME, P_ASSIGNMENT_LEVEL, COALESCE(P_TARGET_NAME, 'ACCOUNT'));
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, TARGET_TYPE, TARGET_NAME, RESULT)
    VALUES ('AUTHENTICATION', P_POLICY_NAME, 'ASSIGN', P_ASSIGNMENT_LEVEL, COALESCE(P_TARGET_NAME, 'ACCOUNT'), 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'policy_name', P_POLICY_NAME,
        'assignment_level', P_ASSIGNMENT_LEVEL,
        'target', COALESCE(P_TARGET_NAME, 'ACCOUNT')
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 6: POLICY TEMPLATES
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Setup Standard Policy Templates
 * 
 * Purpose: Creates standard policy templates for common security profiles
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_SETUP_TEMPLATES()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_templates_created INTEGER := 0;
BEGIN
    MERGE INTO ADMIN.SECURITY.POLICY_TEMPLATES AS target
    USING (
        SELECT 'RESTRICTIVE' AS TEMPLATE_NAME, 'PASSWORD' AS POLICY_TYPE,
               'High security password policy for production' AS DESCRIPTION,
               PARSE_JSON('{"min_length":14,"max_length":256,"min_upper_case":2,"min_lower_case":2,"min_numeric":2,"min_special":2,"max_age_days":90,"max_retries":3,"lockout_time_mins":30,"password_history":12}') AS CONFIGURATION
        UNION ALL
        SELECT 'STANDARD', 'PASSWORD', 'Standard password policy for general use',
               PARSE_JSON('{"min_length":12,"max_length":256,"min_upper_case":1,"min_lower_case":1,"min_numeric":1,"min_special":1,"max_age_days":180,"max_retries":5,"lockout_time_mins":15,"password_history":5}')
        UNION ALL
        SELECT 'RELAXED', 'PASSWORD', 'Relaxed password policy for development',
               PARSE_JSON('{"min_length":8,"max_length":256,"min_upper_case":1,"min_lower_case":1,"min_numeric":1,"min_special":0,"max_age_days":365,"max_retries":10,"lockout_time_mins":5,"password_history":3}')
        UNION ALL
        SELECT 'RESTRICTIVE', 'SESSION', 'Short session timeout for sensitive environments',
               PARSE_JSON('{"session_idle_timeout_mins":30,"session_ui_idle_timeout_mins":30}')
        UNION ALL
        SELECT 'STANDARD', 'SESSION', 'Standard session timeout',
               PARSE_JSON('{"session_idle_timeout_mins":60,"session_ui_idle_timeout_mins":60}')
        UNION ALL
        SELECT 'RELAXED', 'SESSION', 'Extended session timeout for development',
               PARSE_JSON('{"session_idle_timeout_mins":240,"session_ui_idle_timeout_mins":120}')
        UNION ALL
        SELECT 'SERVICE_ACCOUNT', 'SESSION', 'No timeout for service accounts',
               PARSE_JSON('{"session_idle_timeout_mins":0,"session_ui_idle_timeout_mins":0}')
        UNION ALL
        SELECT 'RESTRICTIVE', 'AUTHENTICATION', 'MFA required, limited methods',
               PARSE_JSON('{"authentication_methods":["PASSWORD","SAML"],"mfa_authentication_methods":["TOTP"],"client_types":["SNOWFLAKE_UI","SNOWSQL"]}')
        UNION ALL
        SELECT 'STANDARD', 'AUTHENTICATION', 'Standard authentication with MFA encouraged',
               PARSE_JSON('{"authentication_methods":["PASSWORD","SAML","OAUTH"],"mfa_authentication_methods":["TOTP"],"client_types":["SNOWFLAKE_UI","SNOWSQL","DRIVERS"]}')
        UNION ALL
        SELECT 'SERVICE_ACCOUNT', 'AUTHENTICATION', 'Key-pair only for service accounts',
               PARSE_JSON('{"authentication_methods":["KEYPAIR"],"mfa_authentication_methods":[],"client_types":["DRIVERS","SNOWSQL"]}')
    ) AS source
    ON target.TEMPLATE_NAME = source.TEMPLATE_NAME AND target.POLICY_TYPE = source.POLICY_TYPE
    WHEN NOT MATCHED THEN
        INSERT (TEMPLATE_NAME, POLICY_TYPE, DESCRIPTION, CONFIGURATION)
        VALUES (source.TEMPLATE_NAME, source.POLICY_TYPE, source.DESCRIPTION, source.CONFIGURATION);
    
    SELECT COUNT(*) INTO v_templates_created FROM ADMIN.SECURITY.POLICY_TEMPLATES;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'templates_available', v_templates_created
    );
END;
$$;

/*******************************************************************************
 * PROCEDURE: Create Policy From Template
 * 
 * Purpose: Creates a policy based on a predefined template
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_CREATE_FROM_TEMPLATE(
    P_POLICY_NAME VARCHAR,
    P_POLICY_TYPE VARCHAR,
    P_TEMPLATE_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_config VARIANT;
    v_result VARIANT;
BEGIN
    SELECT CONFIGURATION INTO v_config
    FROM ADMIN.SECURITY.POLICY_TEMPLATES
    WHERE TEMPLATE_NAME = P_TEMPLATE_NAME AND POLICY_TYPE = P_POLICY_TYPE;
    
    IF (v_config IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Template not found: ' || P_TEMPLATE_NAME || ' for ' || P_POLICY_TYPE);
    END IF;
    
    IF (P_POLICY_TYPE = 'PASSWORD') THEN
        CALL ADMIN.SECURITY.POLICY_CREATE_PASSWORD_POLICY(
            P_POLICY_NAME,
            v_config:min_length::INTEGER,
            v_config:max_length::INTEGER,
            v_config:min_upper_case::INTEGER,
            v_config:min_lower_case::INTEGER,
            v_config:min_numeric::INTEGER,
            v_config:min_special::INTEGER,
            v_config:max_age_days::INTEGER,
            v_config:max_retries::INTEGER,
            v_config:lockout_time_mins::INTEGER,
            v_config:password_history::INTEGER,
            'Created from template: ' || P_TEMPLATE_NAME,
            P_TEMPLATE_NAME
        ) INTO v_result;
        
    ELSEIF (P_POLICY_TYPE = 'SESSION') THEN
        CALL ADMIN.SECURITY.POLICY_CREATE_SESSION_POLICY(
            P_POLICY_NAME,
            v_config:session_idle_timeout_mins::INTEGER,
            v_config:session_ui_idle_timeout_mins::INTEGER,
            'Created from template: ' || P_TEMPLATE_NAME,
            P_TEMPLATE_NAME
        ) INTO v_result;
        
    ELSEIF (P_POLICY_TYPE = 'AUTHENTICATION') THEN
        CALL ADMIN.SECURITY.POLICY_CREATE_AUTHENTICATION_POLICY(
            P_POLICY_NAME,
            v_config:authentication_methods::ARRAY,
            v_config:mfa_authentication_methods::ARRAY,
            v_config:client_types::ARRAY,
            NULL,
            'Created from template: ' || P_TEMPLATE_NAME,
            P_TEMPLATE_NAME
        ) INTO v_result;
    END IF;
    
    RETURN v_result;
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 7: POLICY LISTING AND REPORTING
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: List All Policies
 * 
 * Purpose: Lists all policies of a given type or all types
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_LIST_POLICIES(
    P_POLICY_TYPE VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    POLICY_TYPE VARCHAR,
    POLICY_NAME VARCHAR,
    TEMPLATE VARCHAR,
    APPLIED_TO_ACCOUNT BOOLEAN,
    CONFIGURATION VARIANT,
    STATUS VARCHAR,
    CREATED_AT TIMESTAMP_NTZ
)
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    IF (P_POLICY_TYPE IS NULL) THEN
        res := (SELECT POLICY_TYPE, POLICY_NAME, POLICY_TEMPLATE AS TEMPLATE,
                       APPLIED_TO_ACCOUNT, CONFIGURATION, STATUS, CREATED_AT
                FROM ADMIN.SECURITY.POLICY_REGISTRY
                WHERE STATUS = 'ACTIVE'
                ORDER BY POLICY_TYPE, POLICY_NAME);
    ELSE
        res := (SELECT POLICY_TYPE, POLICY_NAME, POLICY_TEMPLATE AS TEMPLATE,
                       APPLIED_TO_ACCOUNT, CONFIGURATION, STATUS, CREATED_AT
                FROM ADMIN.SECURITY.POLICY_REGISTRY
                WHERE POLICY_TYPE = P_POLICY_TYPE AND STATUS = 'ACTIVE'
                ORDER BY POLICY_NAME);
    END IF;
    
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * PROCEDURE: List Policy Assignments
 * 
 * Purpose: Lists all policy assignments
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_LIST_ASSIGNMENTS(
    P_POLICY_TYPE VARCHAR DEFAULT NULL,
    P_ASSIGNMENT_LEVEL VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    POLICY_TYPE VARCHAR,
    POLICY_NAME VARCHAR,
    ASSIGNMENT_LEVEL VARCHAR,
    ASSIGNED_TO VARCHAR,
    ASSIGNED_BY VARCHAR,
    ASSIGNED_AT TIMESTAMP_NTZ
)
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (SELECT POLICY_TYPE, POLICY_NAME, ASSIGNMENT_LEVEL, ASSIGNED_TO, ASSIGNED_BY, ASSIGNED_AT
            FROM ADMIN.SECURITY.POLICY_ASSIGNMENTS
            WHERE STATUS = 'ACTIVE'
              AND (P_POLICY_TYPE IS NULL OR POLICY_TYPE = P_POLICY_TYPE)
              AND (P_ASSIGNMENT_LEVEL IS NULL OR ASSIGNMENT_LEVEL = P_ASSIGNMENT_LEVEL)
            ORDER BY POLICY_TYPE, ASSIGNMENT_LEVEL, ASSIGNED_TO);
    
    RETURN TABLE(res);
END;
$$;

/*******************************************************************************
 * PROCEDURE: Policy Audit Report
 * 
 * Purpose: Generates audit report for policy changes
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_AUDIT_REPORT(
    P_DAYS_BACK INTEGER DEFAULT 30,
    P_POLICY_TYPE VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    AUDIT_TIMESTAMP TIMESTAMP_NTZ,
    POLICY_TYPE VARCHAR,
    POLICY_NAME VARCHAR,
    ACTION VARCHAR,
    ACTION_BY VARCHAR,
    TARGET_TYPE VARCHAR,
    TARGET_NAME VARCHAR,
    RESULT VARCHAR
)
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (SELECT AUDIT_TIMESTAMP, POLICY_TYPE, POLICY_NAME, ACTION, 
                   ACTION_BY, TARGET_TYPE, TARGET_NAME, RESULT
            FROM ADMIN.SECURITY.POLICY_AUDIT_LOG
            WHERE AUDIT_TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
              AND (P_POLICY_TYPE IS NULL OR POLICY_TYPE = P_POLICY_TYPE)
            ORDER BY AUDIT_TIMESTAMP DESC);
    
    RETURN TABLE(res);
END;
$$;

-- #############################################################################
-- SECTION 8: POLICY MONITORING DASHBOARD
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Policy Compliance Dashboard
 * 
 * Purpose: Overview of policy compliance across the account
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_COMPLIANCE_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_network_policies INTEGER;
    v_password_policies INTEGER;
    v_session_policies INTEGER;
    v_auth_policies INTEGER;
    v_account_network BOOLEAN := FALSE;
    v_account_password BOOLEAN := FALSE;
    v_account_session BOOLEAN := FALSE;
    v_account_auth BOOLEAN := FALSE;
    v_users_with_network INTEGER := 0;
    v_users_with_password INTEGER := 0;
    v_pending_exceptions INTEGER := 0;
    v_recent_changes INTEGER := 0;
BEGIN
    SELECT COUNT(*) INTO v_network_policies
    FROM ADMIN.SECURITY.POLICY_REGISTRY WHERE POLICY_TYPE = 'NETWORK' AND STATUS = 'ACTIVE';
    
    SELECT COUNT(*) INTO v_password_policies
    FROM ADMIN.SECURITY.POLICY_REGISTRY WHERE POLICY_TYPE = 'PASSWORD' AND STATUS = 'ACTIVE';
    
    SELECT COUNT(*) INTO v_session_policies
    FROM ADMIN.SECURITY.POLICY_REGISTRY WHERE POLICY_TYPE = 'SESSION' AND STATUS = 'ACTIVE';
    
    SELECT COUNT(*) INTO v_auth_policies
    FROM ADMIN.SECURITY.POLICY_REGISTRY WHERE POLICY_TYPE = 'AUTHENTICATION' AND STATUS = 'ACTIVE';
    
    SELECT COALESCE(MAX(APPLIED_TO_ACCOUNT), FALSE) INTO v_account_network
    FROM ADMIN.SECURITY.POLICY_REGISTRY WHERE POLICY_TYPE = 'NETWORK';
    
    SELECT COALESCE(MAX(APPLIED_TO_ACCOUNT), FALSE) INTO v_account_password
    FROM ADMIN.SECURITY.POLICY_REGISTRY WHERE POLICY_TYPE = 'PASSWORD';
    
    SELECT COALESCE(MAX(APPLIED_TO_ACCOUNT), FALSE) INTO v_account_session
    FROM ADMIN.SECURITY.POLICY_REGISTRY WHERE POLICY_TYPE = 'SESSION';
    
    SELECT COALESCE(MAX(APPLIED_TO_ACCOUNT), FALSE) INTO v_account_auth
    FROM ADMIN.SECURITY.POLICY_REGISTRY WHERE POLICY_TYPE = 'AUTHENTICATION';
    
    SELECT COUNT(DISTINCT ASSIGNED_TO) INTO v_users_with_network
    FROM ADMIN.SECURITY.POLICY_ASSIGNMENTS 
    WHERE POLICY_TYPE = 'NETWORK' AND ASSIGNMENT_LEVEL = 'USER' AND STATUS = 'ACTIVE';
    
    SELECT COUNT(DISTINCT ASSIGNED_TO) INTO v_users_with_password
    FROM ADMIN.SECURITY.POLICY_ASSIGNMENTS 
    WHERE POLICY_TYPE = 'PASSWORD' AND ASSIGNMENT_LEVEL = 'USER' AND STATUS = 'ACTIVE';
    
    SELECT COUNT(*) INTO v_pending_exceptions
    FROM ADMIN.SECURITY.POLICY_EXCEPTIONS WHERE STATUS = 'PENDING';
    
    SELECT COUNT(*) INTO v_recent_changes
    FROM ADMIN.SECURITY.POLICY_AUDIT_LOG 
    WHERE AUDIT_TIMESTAMP >= DATEADD(DAY, -7, CURRENT_TIMESTAMP());
    
    RETURN OBJECT_CONSTRUCT(
        'policy_counts', OBJECT_CONSTRUCT(
            'network_policies', v_network_policies,
            'password_policies', v_password_policies,
            'session_policies', v_session_policies,
            'authentication_policies', v_auth_policies
        ),
        'account_level_policies', OBJECT_CONSTRUCT(
            'network_policy_set', v_account_network,
            'password_policy_set', v_account_password,
            'session_policy_set', v_account_session,
            'authentication_policy_set', v_account_auth
        ),
        'user_level_assignments', OBJECT_CONSTRUCT(
            'users_with_network_policy', v_users_with_network,
            'users_with_password_policy', v_users_with_password
        ),
        'compliance_status', OBJECT_CONSTRUCT(
            'pending_exceptions', v_pending_exceptions,
            'recent_changes_7d', v_recent_changes
        ),
        'recommendations', ARRAY_CONSTRUCT(
            IFF(NOT v_account_network, 'WARNING: No account-level network policy set', NULL),
            IFF(NOT v_account_password, 'WARNING: No account-level password policy set', NULL),
            IFF(NOT v_account_session, 'INFO: No account-level session policy set', NULL),
            IFF(NOT v_account_auth, 'INFO: No account-level authentication policy set', NULL),
            IFF(v_pending_exceptions > 0, 'ACTION: ' || v_pending_exceptions || ' policy exceptions pending review', NULL)
        )
    );
END;
$$;

/*******************************************************************************
 * PROCEDURE: Policy Monitoring Dashboard (Master)
 * 
 * Purpose: Combined dashboard for all policy monitoring
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_MONITORING_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_compliance VARIANT;
    v_recent_audit ARRAY;
    v_policy_summary ARRAY;
BEGIN
    CALL ADMIN.SECURITY.POLICY_COMPLIANCE_DASHBOARD() INTO v_compliance;
    
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'timestamp', AUDIT_TIMESTAMP,
        'policy_type', POLICY_TYPE,
        'policy_name', POLICY_NAME,
        'action', ACTION,
        'result', RESULT
    )) INTO v_recent_audit
    FROM (
        SELECT * FROM ADMIN.SECURITY.POLICY_AUDIT_LOG
        WHERE AUDIT_TIMESTAMP >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())
        ORDER BY AUDIT_TIMESTAMP DESC
        LIMIT 20
    );
    
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'policy_type', POLICY_TYPE,
        'policy_name', POLICY_NAME,
        'template', POLICY_TEMPLATE,
        'applied_to_account', APPLIED_TO_ACCOUNT
    )) INTO v_policy_summary
    FROM ADMIN.SECURITY.POLICY_REGISTRY
    WHERE STATUS = 'ACTIVE';
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard_generated', CURRENT_TIMESTAMP(),
        'compliance_overview', v_compliance,
        'active_policies', v_policy_summary,
        'recent_audit_events', v_recent_audit
    );
END;
$$;

-- #############################################################################
-- SECTION 9: POLICY EXCEPTION MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Create Policy Exception
 * 
 * Purpose: Creates an exception request for a policy
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_CREATE_EXCEPTION(
    P_POLICY_TYPE VARCHAR,
    P_POLICY_NAME VARCHAR,
    P_EXCEPTION_TARGET VARCHAR,
    P_EXCEPTION_REASON VARCHAR,
    P_EXPIRY_DAYS INTEGER DEFAULT 90
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
BEGIN
    INSERT INTO ADMIN.SECURITY.POLICY_EXCEPTIONS 
        (POLICY_TYPE, POLICY_NAME, EXCEPTION_TARGET, EXCEPTION_REASON, EXPIRES_AT)
    VALUES (
        P_POLICY_TYPE,
        P_POLICY_NAME,
        P_EXCEPTION_TARGET,
        P_EXCEPTION_REASON,
        DATEADD(DAY, P_EXPIRY_DAYS, CURRENT_TIMESTAMP())
    );
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, TARGET_TYPE, TARGET_NAME, RESULT)
    VALUES (P_POLICY_TYPE, P_POLICY_NAME, 'EXCEPTION_REQUEST', 'EXCEPTION', P_EXCEPTION_TARGET, 'PENDING');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'message', 'Exception request created and pending approval',
        'policy_type', P_POLICY_TYPE,
        'policy_name', P_POLICY_NAME,
        'target', P_EXCEPTION_TARGET,
        'expires_at', DATEADD(DAY, P_EXPIRY_DAYS, CURRENT_TIMESTAMP())
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * PROCEDURE: Approve Policy Exception
 * 
 * Purpose: Approves a pending policy exception
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_APPROVE_EXCEPTION(
    P_EXCEPTION_ID VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_policy_type VARCHAR;
    v_policy_name VARCHAR;
    v_target VARCHAR;
BEGIN
    SELECT POLICY_TYPE, POLICY_NAME, EXCEPTION_TARGET 
    INTO v_policy_type, v_policy_name, v_target
    FROM ADMIN.SECURITY.POLICY_EXCEPTIONS
    WHERE EXCEPTION_ID = P_EXCEPTION_ID AND STATUS = 'PENDING';
    
    UPDATE ADMIN.SECURITY.POLICY_EXCEPTIONS
    SET STATUS = 'APPROVED',
        APPROVED_BY = CURRENT_USER(),
        APPROVED_AT = CURRENT_TIMESTAMP()
    WHERE EXCEPTION_ID = P_EXCEPTION_ID;
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, TARGET_TYPE, TARGET_NAME, RESULT)
    VALUES (v_policy_type, v_policy_name, 'EXCEPTION_APPROVED', 'EXCEPTION', v_target, 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'message', 'Exception approved',
        'exception_id', P_EXCEPTION_ID,
        'approved_by', CURRENT_USER()
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 10: POLICY DELETION
-- #############################################################################

/*******************************************************************************
 * PROCEDURE: Drop Policy
 * 
 * Purpose: Safely drops a policy and cleans up tracking records
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.POLICY_DROP_POLICY(
    P_POLICY_TYPE VARCHAR,
    P_POLICY_NAME VARCHAR,
    P_FORCE BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_assignments INTEGER;
    v_sql VARCHAR;
BEGIN
    SELECT COUNT(*) INTO v_assignments
    FROM ADMIN.SECURITY.POLICY_ASSIGNMENTS
    WHERE POLICY_TYPE = P_POLICY_TYPE 
      AND POLICY_NAME = P_POLICY_NAME 
      AND STATUS = 'ACTIVE';
    
    IF (v_assignments > 0 AND NOT P_FORCE) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Policy has ' || v_assignments || ' active assignments. Use P_FORCE=TRUE to drop anyway.',
            'active_assignments', v_assignments
        );
    END IF;
    
    v_sql := 'DROP ' || P_POLICY_TYPE || ' POLICY IF EXISTS ' || P_POLICY_NAME;
    EXECUTE IMMEDIATE v_sql;
    
    UPDATE ADMIN.SECURITY.POLICY_REGISTRY
    SET STATUS = 'DROPPED',
        UPDATED_BY = CURRENT_USER(),
        UPDATED_AT = CURRENT_TIMESTAMP()
    WHERE POLICY_TYPE = P_POLICY_TYPE AND POLICY_NAME = P_POLICY_NAME;
    
    UPDATE ADMIN.SECURITY.POLICY_ASSIGNMENTS
    SET STATUS = 'INACTIVE'
    WHERE POLICY_TYPE = P_POLICY_TYPE AND POLICY_NAME = P_POLICY_NAME;
    
    INSERT INTO ADMIN.SECURITY.POLICY_AUDIT_LOG 
        (POLICY_TYPE, POLICY_NAME, ACTION, RESULT)
    VALUES (P_POLICY_TYPE, P_POLICY_NAME, 'DROP', 'SUCCESS');
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'message', 'Policy dropped successfully',
        'policy_type', P_POLICY_TYPE,
        'policy_name', P_POLICY_NAME
    );
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 11: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_CREATE_NETWORK_POLICY(VARCHAR, ARRAY, ARRAY, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_MODIFY_NETWORK_POLICY(VARCHAR, VARCHAR, ARRAY, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_ASSIGN_NETWORK_POLICY(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_CREATE_PASSWORD_POLICY(VARCHAR, INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, INTEGER, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_ASSIGN_PASSWORD_POLICY(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_CREATE_SESSION_POLICY(VARCHAR, INTEGER, INTEGER, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_ASSIGN_SESSION_POLICY(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_CREATE_AUTHENTICATION_POLICY(VARCHAR, ARRAY, ARRAY, ARRAY, ARRAY, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_ASSIGN_AUTHENTICATION_POLICY(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_SETUP_TEMPLATES() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_CREATE_FROM_TEMPLATE(VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_LIST_POLICIES(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_LIST_ASSIGNMENTS(VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_AUDIT_REPORT(INTEGER, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_COMPLIANCE_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_MONITORING_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_CREATE_EXCEPTION(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_APPROVE_EXCEPTION(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.POLICY_DROP_POLICY(VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;

GRANT SELECT ON TABLE ADMIN.SECURITY.POLICY_REGISTRY TO ROLE SRS_SECURITY_ADMIN;
GRANT SELECT ON TABLE ADMIN.SECURITY.POLICY_ASSIGNMENTS TO ROLE SRS_SECURITY_ADMIN;
GRANT SELECT ON TABLE ADMIN.SECURITY.POLICY_TEMPLATES TO ROLE SRS_SECURITY_ADMIN;
GRANT SELECT ON TABLE ADMIN.SECURITY.POLICY_AUDIT_LOG TO ROLE SRS_SECURITY_ADMIN;
GRANT SELECT ON TABLE ADMIN.SECURITY.POLICY_EXCEPTIONS TO ROLE SRS_SECURITY_ADMIN;

-- =============================================================================
-- END OF POLICY MANAGEMENT PROCEDURES
-- =============================================================================
