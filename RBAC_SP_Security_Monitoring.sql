/*******************************************************************************
 * RBAC STORED PROCEDURE: Security Monitoring Dashboard
 * 
 * Purpose: Real-time monitoring of RBAC security posture, role assignments,
 *          exceptions, misalignments, and security anomalies
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          SECURITY
 *   Object Type:     TABLES (3), PROCEDURES (~10)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN (caller must have this role)
 * 
 *   Dependencies:    
 *     - ADMIN database and SECURITY schema must exist
 *     - SNOWFLAKE.ACCOUNT_USAGE access required
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DASHBOARD COMPONENTS
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Role Assignment Overview   - Current role distribution and hierarchy
 *   • Access Anomalies           - Unusual access patterns and deviations
 *   • Configuration Misalignment - RBAC config vs actual state
 *   • Privilege Escalation       - Detection of unusual privilege grants
 *   • User Activity Analysis     - Login patterns and access behavior
 *   • Exception Tracking         - Temporary access and exceptions
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA SECURITY;

-- #############################################################################
-- SECTION 1: SECURITY TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.SECURITY.RBAC_SECURITY_EXCEPTIONS (
    EXCEPTION_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    EXCEPTION_TYPE VARCHAR(50) NOT NULL,
    USER_NAME VARCHAR(255),
    ROLE_NAME VARCHAR(255),
    ENVIRONMENT VARCHAR(10),
    REASON TEXT NOT NULL,
    APPROVED_BY VARCHAR(255) NOT NULL,
    APPROVED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    EXPIRES_AT TIMESTAMP_NTZ,
    STATUS VARCHAR(20) DEFAULT 'ACTIVE',
    TICKET_NUMBER VARCHAR(50),
    METADATA VARIANT
);

CREATE TABLE IF NOT EXISTS ADMIN.SECURITY.RBAC_SECURITY_ALERTS (
    ALERT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    ALERT_TYPE VARCHAR(50) NOT NULL,
    SEVERITY VARCHAR(20) NOT NULL,
    TITLE VARCHAR(500) NOT NULL,
    DESCRIPTION TEXT,
    AFFECTED_USER VARCHAR(255),
    AFFECTED_ROLE VARCHAR(255),
    DETECTED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    STATUS VARCHAR(20) DEFAULT 'OPEN',
    ACKNOWLEDGED_BY VARCHAR(255),
    ACKNOWLEDGED_AT TIMESTAMP_NTZ,
    RESOLVED_BY VARCHAR(255),
    RESOLVED_AT TIMESTAMP_NTZ,
    RESOLUTION_NOTES TEXT,
    METADATA VARIANT
);

CREATE TABLE IF NOT EXISTS ADMIN.SECURITY.RBAC_CONFIG_SNAPSHOTS (
    SNAPSHOT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    SNAPSHOT_TYPE VARCHAR(50) NOT NULL,
    ENVIRONMENT VARCHAR(10),
    SNAPSHOT_DATA VARIANT NOT NULL,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER()
);

-- #############################################################################
-- SECTION 2: ROLE ASSIGNMENT DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Role Assignment Dashboard
 * 
 * Purpose: Overview of all role assignments across the organization
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.RBAC_ROLE_ASSIGNMENT_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_total_users INTEGER;
    v_total_roles INTEGER;
    v_total_grants INTEGER;
    v_by_role_type VARIANT;
    v_by_environment VARIANT;
    v_system_roles ARRAY;
    v_functional_roles ARRAY;
    v_access_roles ARRAY;
    v_recent_grants ARRAY;
    v_users_without_roles ARRAY;
    v_roles_without_users ARRAY;
BEGIN
    -- Total counts
    SELECT COUNT(DISTINCT GRANTEE_NAME) INTO v_total_users
    FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
    WHERE DELETED_ON IS NULL AND ROLE LIKE 'SR%';
    
    SELECT COUNT(*) INTO v_total_roles
    FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
    WHERE DELETED_ON IS NULL AND NAME LIKE 'SR%';
    
    SELECT COUNT(*) INTO v_total_grants
    FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
    WHERE DELETED_ON IS NULL AND ROLE LIKE 'SR%';
    
    -- By role type (SRS, SRF, SRA, SRW, SRD)
    SELECT OBJECT_AGG(ROLE_TYPE, OBJECT_CONSTRUCT(
        'count', CNT,
        'users', USR_CNT
    )) INTO v_by_role_type
    FROM (
        SELECT 
            CASE 
                WHEN r.NAME LIKE 'SRS_%' THEN 'SRS_SYSTEM'
                WHEN r.NAME LIKE 'SRF_%' THEN 'SRF_FUNCTIONAL'
                WHEN r.NAME LIKE 'SRA_%' THEN 'SRA_ACCESS'
                WHEN r.NAME LIKE 'SRW_%' THEN 'SRW_WRAPPER'
                WHEN r.NAME LIKE 'SRD_%' THEN 'SRD_DATABASE'
                ELSE 'OTHER'
            END AS ROLE_TYPE,
            COUNT(DISTINCT r.NAME) AS CNT,
            COUNT(DISTINCT g.GRANTEE_NAME) AS USR_CNT
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES r
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g 
            ON r.NAME = g.ROLE AND g.DELETED_ON IS NULL
        WHERE r.DELETED_ON IS NULL AND r.NAME LIKE 'SR%'
        GROUP BY ROLE_TYPE
    );
    
    -- By environment
    SELECT OBJECT_AGG(ENV, OBJECT_CONSTRUCT(
        'roles', ROLE_CNT,
        'users', USR_CNT
    )) INTO v_by_environment
    FROM (
        SELECT 
            CASE 
                WHEN NAME LIKE '%_DEV%' OR NAME LIKE '%DEV_%' THEN 'DEV'
                WHEN NAME LIKE '%_TST%' OR NAME LIKE '%TST_%' THEN 'TST'
                WHEN NAME LIKE '%_UAT%' OR NAME LIKE '%UAT_%' THEN 'UAT'
                WHEN NAME LIKE '%_PPE%' OR NAME LIKE '%PPE_%' THEN 'PPE'
                WHEN NAME LIKE '%_PRD%' OR NAME LIKE '%PRD_%' THEN 'PRD'
                ELSE 'GLOBAL'
            END AS ENV,
            COUNT(DISTINCT r.NAME) AS ROLE_CNT,
            COUNT(DISTINCT g.GRANTEE_NAME) AS USR_CNT
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES r
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g 
            ON r.NAME = g.ROLE AND g.DELETED_ON IS NULL
        WHERE r.DELETED_ON IS NULL AND r.NAME LIKE 'SR%'
        GROUP BY ENV
    );
    
    -- System roles with user counts
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'role', NAME,
        'user_count', USR_CNT,
        'created', CREATED_ON
    )) INTO v_system_roles
    FROM (
        SELECT r.NAME, r.CREATED_ON, COUNT(DISTINCT g.GRANTEE_NAME) AS USR_CNT
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES r
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g 
            ON r.NAME = g.ROLE AND g.DELETED_ON IS NULL
        WHERE r.DELETED_ON IS NULL AND r.NAME LIKE 'SRS_%'
        GROUP BY r.NAME, r.CREATED_ON
        ORDER BY r.NAME
    );
    
    -- Recent grants (last 7 days)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', GRANTEE_NAME,
        'role', ROLE,
        'granted_by', GRANTED_BY,
        'granted_on', CREATED_ON
    )) INTO v_recent_grants
    FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
    WHERE DELETED_ON IS NULL 
      AND ROLE LIKE 'SR%'
      AND CREATED_ON >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())
    ORDER BY CREATED_ON DESC
    LIMIT 25;
    
    -- Roles without users (potential cleanup)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'role', NAME,
        'created', CREATED_ON,
        'age_days', DATEDIFF(DAY, CREATED_ON, CURRENT_TIMESTAMP())
    )) INTO v_roles_without_users
    FROM (
        SELECT r.NAME, r.CREATED_ON
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES r
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g 
            ON r.NAME = g.ROLE AND g.DELETED_ON IS NULL
        WHERE r.DELETED_ON IS NULL 
          AND r.NAME LIKE 'SR%'
          AND g.ROLE IS NULL
        ORDER BY r.CREATED_ON
        LIMIT 20
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'ROLE_ASSIGNMENT',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_users_with_rbac_roles', v_total_users,
            'total_rbac_roles', v_total_roles,
            'total_role_grants', v_total_grants,
            'avg_roles_per_user', ROUND(v_total_grants * 1.0 / NULLIF(v_total_users, 0), 1)
        ),
        'by_role_type', COALESCE(v_by_role_type, OBJECT_CONSTRUCT()),
        'by_environment', COALESCE(v_by_environment, OBJECT_CONSTRUCT()),
        'system_roles', COALESCE(v_system_roles, ARRAY_CONSTRUCT()),
        'recent_grants', COALESCE(v_recent_grants, ARRAY_CONSTRUCT()),
        'roles_without_users', COALESCE(v_roles_without_users, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 3: ACCESS ANOMALY DETECTION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Access Anomaly Dashboard
 * 
 * Purpose: Detect unusual access patterns and potential security issues
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.RBAC_ACCESS_ANOMALY_DASHBOARD(
    P_DAYS_BACK INTEGER DEFAULT 7
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_unusual_hours ARRAY;
    v_failed_logins ARRAY;
    v_role_switches ARRAY;
    v_high_privilege_usage ARRAY;
    v_new_access_patterns ARRAY;
    v_inactive_users_active ARRAY;
    v_anomaly_count INTEGER := 0;
BEGIN
    -- Access outside business hours (before 6 AM or after 10 PM)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', USER_NAME,
        'timestamp', START_TIME,
        'hour', HOUR(START_TIME),
        'query_type', QUERY_TYPE,
        'role', ROLE_NAME
    )) INTO v_unusual_hours
    FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE START_TIME >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
      AND (HOUR(START_TIME) < 6 OR HOUR(START_TIME) >= 22)
      AND ROLE_NAME LIKE 'SR%'
    ORDER BY START_TIME DESC
    LIMIT 50;
    
    -- Failed login attempts
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', USER_NAME,
        'timestamp', EVENT_TIMESTAMP,
        'error_code', ERROR_CODE,
        'error_message', ERROR_MESSAGE,
        'client_ip', CLIENT_IP
    )) INTO v_failed_logins
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE EVENT_TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
      AND IS_SUCCESS = 'NO'
    ORDER BY EVENT_TIMESTAMP DESC
    LIMIT 50;
    
    -- Frequent role switches (potential privilege hopping)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', USER_NAME,
        'role_switch_count', SWITCH_CNT,
        'unique_roles', UNIQUE_ROLES
    )) INTO v_role_switches
    FROM (
        SELECT 
            USER_NAME,
            COUNT(*) AS SWITCH_CNT,
            COUNT(DISTINCT ROLE_NAME) AS UNIQUE_ROLES
        FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
        WHERE START_TIME >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
          AND QUERY_TEXT ILIKE '%USE ROLE%'
        GROUP BY USER_NAME
        HAVING COUNT(*) > 20
        ORDER BY SWITCH_CNT DESC
        LIMIT 20
    );
    
    -- High privilege role usage (SRS roles by non-admin users)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', USER_NAME,
        'role', ROLE_NAME,
        'query_count', QRY_CNT,
        'last_used', LAST_USED
    )) INTO v_high_privilege_usage
    FROM (
        SELECT 
            USER_NAME,
            ROLE_NAME,
            COUNT(*) AS QRY_CNT,
            MAX(START_TIME) AS LAST_USED
        FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
        WHERE START_TIME >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
          AND ROLE_NAME LIKE 'SRS_%'
          AND USER_NAME NOT IN ('SYSTEM', 'SNOWFLAKE')
        GROUP BY USER_NAME, ROLE_NAME
        ORDER BY QRY_CNT DESC
        LIMIT 25
    );
    
    -- Calculate anomaly count
    v_anomaly_count := COALESCE(ARRAY_SIZE(v_unusual_hours), 0) +
                       COALESCE(ARRAY_SIZE(v_failed_logins), 0) +
                       COALESCE(ARRAY_SIZE(v_role_switches), 0);
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'ACCESS_ANOMALY',
        'generated_at', CURRENT_TIMESTAMP(),
        'period_days', P_DAYS_BACK,
        'summary', OBJECT_CONSTRUCT(
            'total_anomalies_detected', v_anomaly_count,
            'unusual_hour_access', ARRAY_SIZE(COALESCE(v_unusual_hours, ARRAY_CONSTRUCT())),
            'failed_logins', ARRAY_SIZE(COALESCE(v_failed_logins, ARRAY_CONSTRUCT())),
            'frequent_role_switchers', ARRAY_SIZE(COALESCE(v_role_switches, ARRAY_CONSTRUCT())),
            'high_privilege_users', ARRAY_SIZE(COALESCE(v_high_privilege_usage, ARRAY_CONSTRUCT()))
        ),
        'risk_level', CASE 
            WHEN v_anomaly_count > 100 THEN 'HIGH'
            WHEN v_anomaly_count > 50 THEN 'MEDIUM'
            WHEN v_anomaly_count > 10 THEN 'LOW'
            ELSE 'MINIMAL'
        END,
        'unusual_hours_access', COALESCE(v_unusual_hours, ARRAY_CONSTRUCT()),
        'failed_logins', COALESCE(v_failed_logins, ARRAY_CONSTRUCT()),
        'frequent_role_switches', COALESCE(v_role_switches, ARRAY_CONSTRUCT()),
        'high_privilege_usage', COALESCE(v_high_privilege_usage, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 4: CONFIGURATION MISALIGNMENT DETECTION
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Config Misalignment Dashboard
 * 
 * Purpose: Detect discrepancies between expected RBAC config and actual state
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.RBAC_CONFIG_MISALIGNMENT_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_missing_hierarchy ARRAY;
    v_orphan_roles ARRAY;
    v_direct_grants ARRAY;
    v_missing_db_roles ARRAY;
    v_schema_misalignments ARRAY;
    v_total_issues INTEGER := 0;
BEGIN
    -- Roles missing expected hierarchy (SRF should grant to SRA, etc.)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'role', r.NAME,
        'expected_parent', 'SRS_SYSTEM_ADMIN or hierarchy',
        'issue', 'Role not in expected hierarchy'
    )) INTO v_missing_hierarchy
    FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES r
    LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES g
        ON r.NAME = g.GRANTEE_NAME AND g.DELETED_ON IS NULL
    WHERE r.DELETED_ON IS NULL
      AND r.NAME LIKE 'SRF_%'
      AND g.NAME IS NULL
    LIMIT 20;
    
    -- Orphan roles (SR* roles not granted to anyone)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'role', r.NAME,
        'created', r.CREATED_ON,
        'age_days', DATEDIFF(DAY, r.CREATED_ON, CURRENT_TIMESTAMP()),
        'issue', 'Role has no grants'
    )) INTO v_orphan_roles
    FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES r
    LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS gu
        ON r.NAME = gu.ROLE AND gu.DELETED_ON IS NULL
    LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES gr
        ON r.NAME = gr.NAME AND gr.DELETED_ON IS NULL
    WHERE r.DELETED_ON IS NULL
      AND r.NAME LIKE 'SR%'
      AND gu.ROLE IS NULL
      AND gr.NAME IS NULL
      AND r.CREATED_ON < DATEADD(DAY, -7, CURRENT_TIMESTAMP())
    ORDER BY r.CREATED_ON
    LIMIT 30;
    
    -- Direct grants bypassing RBAC (users with direct schema/table grants)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', GRANTEE_NAME,
        'privilege', PRIVILEGE,
        'object_type', GRANTED_ON,
        'object_name', NAME,
        'issue', 'Direct grant bypasses RBAC'
    )) INTO v_direct_grants
    FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
    WHERE DELETED_ON IS NULL
      AND GRANTED_ON IN ('SCHEMA', 'TABLE', 'VIEW', 'DATABASE')
      AND GRANTEE_NAME NOT LIKE 'SR%'
    ORDER BY CREATED_ON DESC
    LIMIT 30;
    
    -- Calculate total issues
    v_total_issues := COALESCE(ARRAY_SIZE(v_missing_hierarchy), 0) +
                      COALESCE(ARRAY_SIZE(v_orphan_roles), 0) +
                      COALESCE(ARRAY_SIZE(v_direct_grants), 0);
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'CONFIG_MISALIGNMENT',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_misalignments', v_total_issues,
            'hierarchy_issues', ARRAY_SIZE(COALESCE(v_missing_hierarchy, ARRAY_CONSTRUCT())),
            'orphan_roles', ARRAY_SIZE(COALESCE(v_orphan_roles, ARRAY_CONSTRUCT())),
            'direct_grants', ARRAY_SIZE(COALESCE(v_direct_grants, ARRAY_CONSTRUCT()))
        ),
        'health_status', CASE 
            WHEN v_total_issues > 50 THEN 'CRITICAL'
            WHEN v_total_issues > 20 THEN 'WARNING'
            WHEN v_total_issues > 5 THEN 'ATTENTION'
            ELSE 'HEALTHY'
        END,
        'missing_hierarchy', COALESCE(v_missing_hierarchy, ARRAY_CONSTRUCT()),
        'orphan_roles', COALESCE(v_orphan_roles, ARRAY_CONSTRUCT()),
        'direct_grants_bypassing_rbac', COALESCE(v_direct_grants, ARRAY_CONSTRUCT()),
        'recommendations', ARRAY_CONSTRUCT(
            OBJECT_CONSTRUCT(
                'issue', 'Direct grants bypassing RBAC',
                'action', 'Revoke direct grants and assign through proper RBAC roles'
            ),
            OBJECT_CONSTRUCT(
                'issue', 'Orphan roles',
                'action', 'Review and clean up unused roles'
            )
        )
    );
END;
$$;

-- #############################################################################
-- SECTION 5: EXCEPTION MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Security Exception
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.RBAC_CREATE_SECURITY_EXCEPTION(
    P_EXCEPTION_TYPE VARCHAR,
    P_REASON TEXT,
    P_USER_NAME VARCHAR DEFAULT NULL,
    P_ROLE_NAME VARCHAR DEFAULT NULL,
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_EXPIRES_IN_DAYS INTEGER DEFAULT 30,
    P_TICKET_NUMBER VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_exception_id VARCHAR;
    v_expires_at TIMESTAMP_NTZ;
BEGIN
    v_exception_id := UUID_STRING();
    v_expires_at := DATEADD(DAY, P_EXPIRES_IN_DAYS, CURRENT_TIMESTAMP());
    
    INSERT INTO RBAC_SECURITY_EXCEPTIONS (
        EXCEPTION_ID, EXCEPTION_TYPE, USER_NAME, ROLE_NAME,
        ENVIRONMENT, REASON, APPROVED_BY, EXPIRES_AT, TICKET_NUMBER
    ) VALUES (
        v_exception_id, P_EXCEPTION_TYPE, P_USER_NAME, P_ROLE_NAME,
        P_ENVIRONMENT, P_REASON, CURRENT_USER(), v_expires_at, P_TICKET_NUMBER
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'exception_id', v_exception_id,
        'exception_type', P_EXCEPTION_TYPE,
        'expires_at', v_expires_at,
        'message', 'Security exception created'
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Security Exceptions Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.RBAC_SECURITY_EXCEPTIONS_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_active_exceptions ARRAY;
    v_expiring_soon ARRAY;
    v_by_type VARIANT;
    v_total_active INTEGER;
BEGIN
    -- Active exceptions
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'exception_id', EXCEPTION_ID,
        'type', EXCEPTION_TYPE,
        'user', USER_NAME,
        'role', ROLE_NAME,
        'environment', ENVIRONMENT,
        'reason', REASON,
        'approved_by', APPROVED_BY,
        'expires_at', EXPIRES_AT,
        'days_remaining', DATEDIFF(DAY, CURRENT_TIMESTAMP(), EXPIRES_AT),
        'ticket', TICKET_NUMBER
    )) INTO v_active_exceptions
    FROM RBAC_SECURITY_EXCEPTIONS
    WHERE STATUS = 'ACTIVE'
      AND (EXPIRES_AT IS NULL OR EXPIRES_AT > CURRENT_TIMESTAMP())
    ORDER BY EXPIRES_AT ASC;
    
    v_total_active := ARRAY_SIZE(COALESCE(v_active_exceptions, ARRAY_CONSTRUCT()));
    
    -- Expiring within 7 days
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'exception_id', EXCEPTION_ID,
        'type', EXCEPTION_TYPE,
        'user', USER_NAME,
        'expires_at', EXPIRES_AT,
        'days_remaining', DATEDIFF(DAY, CURRENT_TIMESTAMP(), EXPIRES_AT)
    )) INTO v_expiring_soon
    FROM RBAC_SECURITY_EXCEPTIONS
    WHERE STATUS = 'ACTIVE'
      AND EXPIRES_AT IS NOT NULL
      AND EXPIRES_AT <= DATEADD(DAY, 7, CURRENT_TIMESTAMP())
      AND EXPIRES_AT > CURRENT_TIMESTAMP()
    ORDER BY EXPIRES_AT ASC;
    
    -- By type
    SELECT OBJECT_AGG(EXCEPTION_TYPE, CNT) INTO v_by_type
    FROM (
        SELECT EXCEPTION_TYPE, COUNT(*) AS CNT
        FROM RBAC_SECURITY_EXCEPTIONS
        WHERE STATUS = 'ACTIVE'
        GROUP BY EXCEPTION_TYPE
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'SECURITY_EXCEPTIONS',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_active', v_total_active,
            'expiring_7_days', ARRAY_SIZE(COALESCE(v_expiring_soon, ARRAY_CONSTRUCT()))
        ),
        'by_type', COALESCE(v_by_type, OBJECT_CONSTRUCT()),
        'active_exceptions', COALESCE(v_active_exceptions, ARRAY_CONSTRUCT()),
        'expiring_soon', COALESCE(v_expiring_soon, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 6: SECURITY ALERTS
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Security Alert
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.RBAC_CREATE_SECURITY_ALERT(
    P_ALERT_TYPE VARCHAR,
    P_SEVERITY VARCHAR,
    P_TITLE VARCHAR,
    P_DESCRIPTION TEXT DEFAULT NULL,
    P_AFFECTED_USER VARCHAR DEFAULT NULL,
    P_AFFECTED_ROLE VARCHAR DEFAULT NULL,
    P_METADATA VARIANT DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_alert_id VARCHAR;
BEGIN
    v_alert_id := UUID_STRING();
    
    INSERT INTO RBAC_SECURITY_ALERTS (
        ALERT_ID, ALERT_TYPE, SEVERITY, TITLE, DESCRIPTION,
        AFFECTED_USER, AFFECTED_ROLE, METADATA
    ) VALUES (
        v_alert_id, P_ALERT_TYPE, P_SEVERITY, P_TITLE, P_DESCRIPTION,
        P_AFFECTED_USER, P_AFFECTED_ROLE, P_METADATA
    );
    
    RETURN v_alert_id;
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Security Alerts Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.SECURITY.RBAC_SECURITY_ALERTS_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_open_alerts ARRAY;
    v_by_severity VARIANT;
    v_by_type VARIANT;
    v_recent_resolved ARRAY;
    v_total_open INTEGER;
BEGIN
    -- Open alerts
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'alert_id', ALERT_ID,
        'type', ALERT_TYPE,
        'severity', SEVERITY,
        'title', TITLE,
        'description', DESCRIPTION,
        'affected_user', AFFECTED_USER,
        'affected_role', AFFECTED_ROLE,
        'detected_at', DETECTED_AT,
        'age_hours', DATEDIFF(HOUR, DETECTED_AT, CURRENT_TIMESTAMP())
    )) INTO v_open_alerts
    FROM RBAC_SECURITY_ALERTS
    WHERE STATUS = 'OPEN'
    ORDER BY 
        CASE SEVERITY WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
        DETECTED_AT DESC;
    
    v_total_open := ARRAY_SIZE(COALESCE(v_open_alerts, ARRAY_CONSTRUCT()));
    
    -- By severity
    SELECT OBJECT_AGG(SEVERITY, CNT) INTO v_by_severity
    FROM (
        SELECT SEVERITY, COUNT(*) AS CNT
        FROM RBAC_SECURITY_ALERTS
        WHERE STATUS = 'OPEN'
        GROUP BY SEVERITY
    );
    
    -- By type
    SELECT OBJECT_AGG(ALERT_TYPE, CNT) INTO v_by_type
    FROM (
        SELECT ALERT_TYPE, COUNT(*) AS CNT
        FROM RBAC_SECURITY_ALERTS
        WHERE STATUS = 'OPEN'
        GROUP BY ALERT_TYPE
    );
    
    -- Recently resolved
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'alert_id', ALERT_ID,
        'title', TITLE,
        'resolved_by', RESOLVED_BY,
        'resolved_at', RESOLVED_AT
    )) INTO v_recent_resolved
    FROM RBAC_SECURITY_ALERTS
    WHERE STATUS = 'RESOLVED'
      AND RESOLVED_AT >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())
    ORDER BY RESOLVED_AT DESC
    LIMIT 20;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'SECURITY_ALERTS',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_open', v_total_open,
            'critical', COALESCE(v_by_severity:CRITICAL, 0),
            'high', COALESCE(v_by_severity:HIGH, 0),
            'medium', COALESCE(v_by_severity:MEDIUM, 0),
            'low', COALESCE(v_by_severity:LOW, 0)
        ),
        'status', CASE 
            WHEN COALESCE(v_by_severity:CRITICAL, 0) > 0 THEN 'CRITICAL'
            WHEN COALESCE(v_by_severity:HIGH, 0) > 0 THEN 'HIGH'
            WHEN v_total_open > 10 THEN 'ELEVATED'
            ELSE 'NORMAL'
        END,
        'by_severity', COALESCE(v_by_severity, OBJECT_CONSTRUCT()),
        'by_type', COALESCE(v_by_type, OBJECT_CONSTRUCT()),
        'open_alerts', COALESCE(v_open_alerts, ARRAY_CONSTRUCT()),
        'recent_resolved', COALESCE(v_recent_resolved, ARRAY_CONSTRUCT())
    );
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Acknowledge/Resolve Alert
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.SECURITY.RBAC_RESOLVE_SECURITY_ALERT(
    P_ALERT_ID VARCHAR,
    P_ACTION VARCHAR,
    P_NOTES TEXT
)
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    // Validate action
    if (P_ACTION !== 'ACKNOWLEDGE' && P_ACTION !== 'RESOLVE') {
        return {
            status: 'ERROR',
            message: 'Invalid action. Use ACKNOWLEDGE or RESOLVE'
        };
    }
    
    // Update based on action
    if (P_ACTION === 'ACKNOWLEDGE') {
        var stmt = snowflake.createStatement({
            sqlText: `UPDATE RBAC_SECURITY_ALERTS
                      SET STATUS = 'ACKNOWLEDGED',
                          ACKNOWLEDGED_BY = CURRENT_USER(),
                          ACKNOWLEDGED_AT = CURRENT_TIMESTAMP()
                      WHERE ALERT_ID = ?`,
            binds: [P_ALERT_ID]
        });
        stmt.execute();
    } else {
        var stmt = snowflake.createStatement({
            sqlText: `UPDATE RBAC_SECURITY_ALERTS
                      SET STATUS = 'RESOLVED',
                          RESOLVED_BY = CURRENT_USER(),
                          RESOLVED_AT = CURRENT_TIMESTAMP(),
                          RESOLUTION_NOTES = ?
                      WHERE ALERT_ID = ?`,
            binds: [P_NOTES, P_ALERT_ID]
        });
        stmt.execute();
    }
    
    // Get current user
    var userStmt = snowflake.createStatement({
        sqlText: "SELECT CURRENT_USER()"
    });
    var userRs = userStmt.execute();
    userRs.next();
    var currentUser = userRs.getColumnValue(1);
    
    return {
        status: 'SUCCESS',
        alert_id: P_ALERT_ID,
        action: P_ACTION,
        performed_by: currentUser
    };
$$;

-- #############################################################################
-- SECTION 7: UNIFIED SECURITY MONITORING DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Security Monitoring Dashboard (Unified)
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.SECURITY.RBAC_SECURITY_MONITORING_DASHBOARD()
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    // Gather all dashboards
    var roleDashboard, anomalyDashboard, misalignmentDashboard, alertsDashboard, exceptionsDashboard;
    
    var stmt1 = snowflake.createStatement({sqlText: "CALL ADMIN.SECURITY.RBAC_ROLE_ASSIGNMENT_DASHBOARD()"});
    var rs1 = stmt1.execute(); rs1.next(); roleDashboard = rs1.getColumnValue(1);
    
    var stmt2 = snowflake.createStatement({sqlText: "CALL ADMIN.SECURITY.RBAC_ACCESS_ANOMALY_DASHBOARD(7)"});
    var rs2 = stmt2.execute(); rs2.next(); anomalyDashboard = rs2.getColumnValue(1);
    
    var stmt3 = snowflake.createStatement({sqlText: "CALL ADMIN.SECURITY.RBAC_CONFIG_MISALIGNMENT_DASHBOARD()"});
    var rs3 = stmt3.execute(); rs3.next(); misalignmentDashboard = rs3.getColumnValue(1);
    
    var stmt4 = snowflake.createStatement({sqlText: "CALL ADMIN.SECURITY.RBAC_SECURITY_ALERTS_DASHBOARD()"});
    var rs4 = stmt4.execute(); rs4.next(); alertsDashboard = rs4.getColumnValue(1);
    
    var stmt5 = snowflake.createStatement({sqlText: "CALL ADMIN.SECURITY.RBAC_SECURITY_EXCEPTIONS_DASHBOARD()"});
    var rs5 = stmt5.execute(); rs5.next(); exceptionsDashboard = rs5.getColumnValue(1);
    
    // Determine overall health
    var overallHealth = 'HEALTHY';
    var criticalIssues = [];
    
    if (alertsDashboard && alertsDashboard.status === 'CRITICAL') {
        overallHealth = 'CRITICAL';
        criticalIssues.push('Critical security alerts detected');
    } else if (misalignmentDashboard && misalignmentDashboard.health_status === 'CRITICAL') {
        overallHealth = 'CRITICAL';
        criticalIssues.push('Critical configuration misalignments');
    } else if (anomalyDashboard && anomalyDashboard.risk_level === 'HIGH') {
        overallHealth = 'WARNING';
        criticalIssues.push('High-risk access anomalies detected');
    } else if ((alertsDashboard && alertsDashboard.status === 'HIGH') || 
               (misalignmentDashboard && misalignmentDashboard.health_status === 'WARNING')) {
        overallHealth = 'WARNING';
    }
    
    var tsStmt = snowflake.createStatement({sqlText: "SELECT CURRENT_TIMESTAMP()"});
    var tsRs = tsStmt.execute(); tsRs.next();
    var currentTimestamp = tsRs.getColumnValue(1);
    
    return {
        dashboard: 'SECURITY_MONITORING_UNIFIED',
        generated_at: currentTimestamp,
        overall_health: overallHealth,
        critical_issues: criticalIssues,
        quick_stats: {
            total_rbac_roles: roleDashboard && roleDashboard.summary ? roleDashboard.summary.total_rbac_roles : 0,
            users_with_roles: roleDashboard && roleDashboard.summary ? roleDashboard.summary.total_users_with_rbac_roles : 0,
            open_alerts: alertsDashboard && alertsDashboard.summary ? alertsDashboard.summary.total_open : 0,
            active_exceptions: exceptionsDashboard && exceptionsDashboard.summary ? exceptionsDashboard.summary.total_active : 0,
            config_misalignments: misalignmentDashboard && misalignmentDashboard.summary ? misalignmentDashboard.summary.total_misalignments : 0,
            anomalies_detected: anomalyDashboard && anomalyDashboard.summary ? anomalyDashboard.summary.total_anomalies_detected : 0
        },
        role_assignments: roleDashboard,
        access_anomalies: anomalyDashboard,
        config_misalignments: misalignmentDashboard,
        security_alerts: alertsDashboard,
        security_exceptions: exceptionsDashboard
    };
$$;

-- #############################################################################
-- SECTION 8: AUTOMATED SECURITY SCAN
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Run Security Scan
 * 
 * Purpose: Automated security scan that creates alerts for detected issues
 ******************************************************************************/

CREATE OR REPLACE PROCEDURE ADMIN.SECURITY.RBAC_RUN_SECURITY_SCAN()
RETURNS VARIANT
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    // Run anomaly detection
    var stmt1 = snowflake.createStatement({
        sqlText: "CALL ADMIN.SECURITY.RBAC_ACCESS_ANOMALY_DASHBOARD(1)"
    });
    var rs1 = stmt1.execute();
    rs1.next();
    var anomalyDashboard = rs1.getColumnValue(1);
    
    // Run misalignment detection
    var stmt2 = snowflake.createStatement({
        sqlText: "CALL ADMIN.SECURITY.RBAC_CONFIG_MISALIGNMENT_DASHBOARD()"
    });
    var rs2 = stmt2.execute();
    rs2.next();
    var misalignmentDashboard = rs2.getColumnValue(1);
    
    var alertsCreated = 0;
    
    // Create alerts for critical findings
    if (anomalyDashboard && anomalyDashboard.summary && anomalyDashboard.summary.failed_logins > 10) {
        var stmt = snowflake.createStatement({
            sqlText: `CALL ADMIN.SECURITY.RBAC_CREATE_SECURITY_ALERT(?, ?, ?, ?, NULL, NULL, PARSE_JSON(?))`,
            binds: [
                'FAILED_LOGINS',
                'HIGH',
                'Elevated Failed Login Attempts Detected',
                anomalyDashboard.summary.failed_logins + ' failed logins in the last 24 hours',
                JSON.stringify({count: anomalyDashboard.summary.failed_logins})
            ]
        });
        stmt.execute();
        alertsCreated++;
    }
    
    if (misalignmentDashboard && misalignmentDashboard.summary && misalignmentDashboard.summary.direct_grants > 0) {
        var stmt = snowflake.createStatement({
            sqlText: `CALL ADMIN.SECURITY.RBAC_CREATE_SECURITY_ALERT(?, ?, ?, ?, NULL, NULL, PARSE_JSON(?))`,
            binds: [
                'DIRECT_GRANTS',
                'MEDIUM',
                'Direct Grants Bypassing RBAC Detected',
                misalignmentDashboard.summary.direct_grants + ' direct grants found bypassing RBAC',
                JSON.stringify({count: misalignmentDashboard.summary.direct_grants})
            ]
        });
        stmt.execute();
        alertsCreated++;
    }
    
    if (anomalyDashboard && anomalyDashboard.summary && anomalyDashboard.summary.unusual_hour_access > 20) {
        var stmt = snowflake.createStatement({
            sqlText: `CALL ADMIN.SECURITY.RBAC_CREATE_SECURITY_ALERT(?, ?, ?, ?, NULL, NULL, PARSE_JSON(?))`,
            binds: [
                'UNUSUAL_ACCESS',
                'MEDIUM',
                'Unusual Hour Access Pattern Detected',
                anomalyDashboard.summary.unusual_hour_access + ' queries executed outside business hours',
                JSON.stringify({count: anomalyDashboard.summary.unusual_hour_access})
            ]
        });
        stmt.execute();
        alertsCreated++;
    }
    
    var tsStmt = snowflake.createStatement({sqlText: "SELECT CURRENT_TIMESTAMP()"});
    var tsRs = tsStmt.execute();
    tsRs.next();
    var currentTimestamp = tsRs.getColumnValue(1);
    
    return {
        status: 'SUCCESS',
        scan_timestamp: currentTimestamp,
        alerts_created: alertsCreated,
        findings: {
            anomalies: anomalyDashboard ? anomalyDashboard.summary : {},
            misalignments: misalignmentDashboard ? misalignmentDashboard.summary : {}
        }
    };
$$;

-- #############################################################################
-- SECTION 9: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_ROLE_ASSIGNMENT_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_ACCESS_ANOMALY_DASHBOARD(INTEGER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_CONFIG_MISALIGNMENT_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_CREATE_SECURITY_EXCEPTION(VARCHAR, TEXT, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_SECURITY_EXCEPTIONS_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_CREATE_SECURITY_ALERT(VARCHAR, VARCHAR, VARCHAR, TEXT, VARCHAR, VARCHAR, VARIANT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_SECURITY_ALERTS_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_RESOLVE_SECURITY_ALERT(VARCHAR, VARCHAR, TEXT) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_SECURITY_MONITORING_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_RUN_SECURITY_SCAN() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.SECURITY.RBAC_SECURITY_MONITORING_DASHBOARD() TO ROLE SRS_ACCOUNT_ADMIN;
