/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Monitoring Dashboard
 * 
 * Purpose: Real-time monitoring of clone usage, storage costs, and compliance
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          CLONES
 *   Object Type:     PROCEDURES (~5)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN, SRF_*_DBADMIN (callers)
 * 
 *   Dependencies:    
 *     - ADMIN database and CLONES schema must exist
 *     - RBAC_SP_Clone_Management.sql must be deployed first
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DASHBOARD COMPONENTS:
 * ─────────────────────────────────────────────────────────────────────────────
 *   • Clone Usage Overview      - Active clones by environment and user
 *   • Storage Cost Analysis     - Estimated storage consumption and costs
 *   • Policy Compliance Status  - Violations, warnings, and compliance %
 *   • Expiring Clones           - Clones approaching expiration
 *   • Usage Trends              - Clone creation/deletion patterns
 *   • Top Clone Consumers       - Users with most clones
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA CLONES;

-- #############################################################################
-- SECTION 1: CLONE USAGE DASHBOARD
-- #############################################################################

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CLONE_USAGE_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_total_clones INTEGER;
    v_by_environment VARIANT;
    v_by_type VARIANT;
    v_by_status VARIANT;
    v_recent_activity ARRAY;
    v_top_users ARRAY;
    v_expiring_soon ARRAY;
    v_avg_clone_age FLOAT;
BEGIN
    -- Total active clones
    SELECT COUNT(*) INTO v_total_clones
    FROM RBAC_CLONE_REGISTRY WHERE STATUS = 'ACTIVE';
    
    -- By environment
    SELECT OBJECT_AGG(ENVIRONMENT, OBJECT_CONSTRUCT(
        'count', CNT,
        'percentage', ROUND(CNT * 100.0 / NULLIF(:v_total_clones, 0), 1)
    )) INTO v_by_environment
    FROM (
        SELECT ENVIRONMENT, COUNT(*) AS CNT
        FROM RBAC_CLONE_REGISTRY WHERE STATUS = 'ACTIVE'
        GROUP BY ENVIRONMENT
    );
    
    -- By type
    SELECT OBJECT_AGG(CLONE_TYPE, CNT) INTO v_by_type
    FROM (
        SELECT CLONE_TYPE, COUNT(*) AS CNT
        FROM RBAC_CLONE_REGISTRY WHERE STATUS = 'ACTIVE'
        GROUP BY CLONE_TYPE
    );
    
    -- By status
    SELECT OBJECT_AGG(STATUS, CNT) INTO v_by_status
    FROM (
        SELECT STATUS, COUNT(*) AS CNT
        FROM RBAC_CLONE_REGISTRY
        GROUP BY STATUS
    );
    
    -- Recent activity (last 24 hours)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'operation', OPERATION,
        'clone_name', CLONE_NAME,
        'performed_by', PERFORMED_BY,
        'timestamp', TIMESTAMP,
        'status', STATUS
    )) INTO v_recent_activity
    FROM RBAC_CLONE_AUDIT_LOG
    WHERE TIMESTAMP >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP())
    ORDER BY TIMESTAMP DESC
    LIMIT 20;
    
    -- Top users by clone count
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', CREATED_BY,
        'clone_count', CNT,
        'environments', ENVS
    )) INTO v_top_users
    FROM (
        SELECT CREATED_BY, COUNT(*) AS CNT, 
               ARRAY_AGG(DISTINCT ENVIRONMENT) AS ENVS
        FROM RBAC_CLONE_REGISTRY WHERE STATUS = 'ACTIVE'
        GROUP BY CREATED_BY
        ORDER BY CNT DESC
        LIMIT 10
    );
    
    -- Expiring within 7 days
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'clone_name', CLONE_NAME,
        'owner', CREATED_BY,
        'expires_at', EXPIRES_AT,
        'days_remaining', DATEDIFF(DAY, CURRENT_TIMESTAMP(), EXPIRES_AT)
    )) INTO v_expiring_soon
    FROM RBAC_CLONE_REGISTRY
    WHERE STATUS = 'ACTIVE'
      AND EXPIRES_AT IS NOT NULL
      AND EXPIRES_AT <= DATEADD(DAY, 7, CURRENT_TIMESTAMP())
    ORDER BY EXPIRES_AT ASC
    LIMIT 20;
    
    -- Average clone age
    SELECT AVG(DATEDIFF(DAY, CREATED_AT, CURRENT_TIMESTAMP())) INTO v_avg_clone_age
    FROM RBAC_CLONE_REGISTRY WHERE STATUS = 'ACTIVE';
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'CLONE_USAGE',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_active_clones', v_total_clones,
            'average_clone_age_days', ROUND(v_avg_clone_age, 1),
            'clones_expiring_7_days', ARRAY_SIZE(COALESCE(v_expiring_soon, ARRAY_CONSTRUCT()))
        ),
        'by_environment', v_by_environment,
        'by_type', v_by_type,
        'by_status', v_by_status,
        'top_users', COALESCE(v_top_users, ARRAY_CONSTRUCT()),
        'expiring_soon', COALESCE(v_expiring_soon, ARRAY_CONSTRUCT()),
        'recent_activity', COALESCE(v_recent_activity, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 2: STORAGE COST DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Storage Dashboard
 * 
 * Purpose: Analyze storage consumption and estimated costs for clones
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CLONE_STORAGE_DASHBOARD(
    P_COST_PER_TB_MONTH FLOAT DEFAULT 23.00
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_storage_by_env ARRAY;
    v_storage_by_user ARRAY;
    v_total_bytes FLOAT := 0;
    v_total_cost FLOAT := 0;
    v_cost_per_byte FLOAT;
BEGIN
    v_cost_per_byte := P_COST_PER_TB_MONTH / (1024 * 1024 * 1024 * 1024);
    
    -- Storage by environment (estimated from table storage)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'environment', ENV,
        'clone_count', CLONE_CNT,
        'estimated_bytes', EST_BYTES,
        'estimated_gb', ROUND(EST_BYTES / (1024*1024*1024), 2),
        'estimated_monthly_cost', ROUND(EST_BYTES * :v_cost_per_byte, 2)
    )) INTO v_storage_by_env
    FROM (
        SELECT 
            c.ENVIRONMENT AS ENV,
            COUNT(*) AS CLONE_CNT,
            SUM(COALESCE(ts.ACTIVE_BYTES, 0)) AS EST_BYTES
        FROM RBAC_CLONE_REGISTRY c
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.TABLE_STORAGE_METRICS ts
            ON ts.TABLE_SCHEMA LIKE '%CLONE%'
            AND ts.TABLE_CATALOG = c.CLONE_DATABASE
        WHERE c.STATUS = 'ACTIVE'
        GROUP BY c.ENVIRONMENT
    );
    
    -- Storage by user (top 10)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', OWNER,
        'clone_count', CNT,
        'oldest_clone_days', MAX_AGE,
        'newest_clone_days', MIN_AGE
    )) INTO v_storage_by_user
    FROM (
        SELECT 
            CREATED_BY AS OWNER,
            COUNT(*) AS CNT,
            MAX(DATEDIFF(DAY, CREATED_AT, CURRENT_TIMESTAMP())) AS MAX_AGE,
            MIN(DATEDIFF(DAY, CREATED_AT, CURRENT_TIMESTAMP())) AS MIN_AGE
        FROM RBAC_CLONE_REGISTRY
        WHERE STATUS = 'ACTIVE'
        GROUP BY CREATED_BY
        ORDER BY CNT DESC
        LIMIT 10
    );
    
    -- Calculate totals
    SELECT SUM(EST_BYTES) INTO v_total_bytes
    FROM (
        SELECT COALESCE(SUM(ts.ACTIVE_BYTES), 0) AS EST_BYTES
        FROM RBAC_CLONE_REGISTRY c
        LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.TABLE_STORAGE_METRICS ts
            ON ts.TABLE_SCHEMA LIKE '%CLONE%'
        WHERE c.STATUS = 'ACTIVE'
    );
    
    v_total_cost := v_total_bytes * v_cost_per_byte;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'CLONE_STORAGE',
        'generated_at', CURRENT_TIMESTAMP(),
        'cost_assumptions', OBJECT_CONSTRUCT(
            'cost_per_tb_month', P_COST_PER_TB_MONTH,
            'currency', 'USD'
        ),
        'totals', OBJECT_CONSTRUCT(
            'estimated_total_bytes', v_total_bytes,
            'estimated_total_gb', ROUND(v_total_bytes / (1024*1024*1024), 2),
            'estimated_total_tb', ROUND(v_total_bytes / (1024*1024*1024*1024), 4),
            'estimated_monthly_cost', ROUND(v_total_cost, 2)
        ),
        'by_environment', COALESCE(v_storage_by_env, ARRAY_CONSTRUCT()),
        'by_user', COALESCE(v_storage_by_user, ARRAY_CONSTRUCT()),
        'cost_optimization', OBJECT_CONSTRUCT(
            'recommendation', 'Review clones older than 30 days for potential cleanup',
            'action', 'CALL RBAC_CLEANUP_EXPIRED_CLONES(NULL, TRUE);'
        )
    );
END;
$$;

-- #############################################################################
-- SECTION 3: POLICY COMPLIANCE DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Compliance Dashboard
 * 
 * Purpose: Real-time policy compliance status and violation tracking
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CLONE_COMPLIANCE_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_total_clones INTEGER;
    v_compliant_count INTEGER := 0;
    v_violation_count INTEGER := 0;
    v_active_policies INTEGER;
    v_open_violations ARRAY;
    v_violations_by_severity VARIANT;
    v_violations_by_policy ARRAY;
    v_compliance_trend ARRAY;
    v_policy_summary ARRAY;
BEGIN
    -- Get counts
    SELECT COUNT(*) INTO v_total_clones
    FROM RBAC_CLONE_REGISTRY WHERE STATUS = 'ACTIVE';
    
    SELECT COUNT(*) INTO v_active_policies
    FROM RBAC_CLONE_POLICIES WHERE IS_ACTIVE = TRUE;
    
    -- Open violations
    SELECT COUNT(*) INTO v_violation_count
    FROM RBAC_CLONE_POLICY_VIOLATIONS WHERE STATUS = 'OPEN';
    
    v_compliant_count := v_total_clones - v_violation_count;
    
    -- Violations by severity
    SELECT OBJECT_AGG(SEVERITY, CNT) INTO v_violations_by_severity
    FROM (
        SELECT SEVERITY, COUNT(*) AS CNT
        FROM RBAC_CLONE_POLICY_VIOLATIONS
        WHERE STATUS = 'OPEN'
        GROUP BY SEVERITY
    );
    
    -- Open violations details
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'violation_id', VIOLATION_ID,
        'policy_name', POLICY_NAME,
        'clone_name', CLONE_NAME,
        'violated_by', VIOLATED_BY,
        'severity', SEVERITY,
        'timestamp', TIMESTAMP,
        'age_hours', DATEDIFF(HOUR, TIMESTAMP, CURRENT_TIMESTAMP())
    )) INTO v_open_violations
    FROM RBAC_CLONE_POLICY_VIOLATIONS
    WHERE STATUS = 'OPEN'
    ORDER BY 
        CASE SEVERITY WHEN 'CRITICAL' THEN 1 WHEN 'ERROR' THEN 2 WHEN 'WARNING' THEN 3 ELSE 4 END,
        TIMESTAMP DESC
    LIMIT 25;
    
    -- Violations by policy
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'policy_name', POLICY_NAME,
        'violation_count', CNT,
        'oldest_violation', OLDEST,
        'newest_violation', NEWEST
    )) INTO v_violations_by_policy
    FROM (
        SELECT 
            POLICY_NAME, 
            COUNT(*) AS CNT,
            MIN(TIMESTAMP) AS OLDEST,
            MAX(TIMESTAMP) AS NEWEST
        FROM RBAC_CLONE_POLICY_VIOLATIONS
        WHERE STATUS = 'OPEN'
        GROUP BY POLICY_NAME
        ORDER BY CNT DESC
    );
    
    -- Compliance trend (last 7 days)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'date', DT,
        'violations_opened', OPENED,
        'violations_resolved', RESOLVED
    )) INTO v_compliance_trend
    FROM (
        SELECT 
            DATE_TRUNC('DAY', TIMESTAMP)::DATE AS DT,
            COUNT_IF(STATUS = 'OPEN') AS OPENED,
            COUNT_IF(STATUS = 'RESOLVED') AS RESOLVED
        FROM RBAC_CLONE_POLICY_VIOLATIONS
        WHERE TIMESTAMP >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())
        GROUP BY DT
        ORDER BY DT
    );
    
    -- Policy summary
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'policy_name', POLICY_NAME,
        'policy_type', POLICY_TYPE,
        'severity', SEVERITY,
        'environment', ENVIRONMENT,
        'is_active', IS_ACTIVE
    )) INTO v_policy_summary
    FROM RBAC_CLONE_POLICIES
    ORDER BY 
        CASE SEVERITY WHEN 'CRITICAL' THEN 1 WHEN 'ERROR' THEN 2 WHEN 'WARNING' THEN 3 ELSE 4 END;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'CLONE_COMPLIANCE',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_clones', v_total_clones,
            'compliant_clones', v_compliant_count,
            'non_compliant_clones', v_violation_count,
            'compliance_percentage', ROUND(v_compliant_count * 100.0 / NULLIF(v_total_clones, 0), 1),
            'active_policies', v_active_policies,
            'open_violations', v_violation_count
        ),
        'status', CASE 
            WHEN v_violation_count = 0 THEN 'COMPLIANT'
            WHEN v_violations_by_severity:CRITICAL > 0 THEN 'CRITICAL'
            WHEN v_violations_by_severity:ERROR > 0 THEN 'NON_COMPLIANT'
            ELSE 'WARNING'
        END,
        'violations_by_severity', COALESCE(v_violations_by_severity, OBJECT_CONSTRUCT()),
        'violations_by_policy', COALESCE(v_violations_by_policy, ARRAY_CONSTRUCT()),
        'open_violations', COALESCE(v_open_violations, ARRAY_CONSTRUCT()),
        'compliance_trend_7d', COALESCE(v_compliance_trend, ARRAY_CONSTRUCT()),
        'policies', COALESCE(v_policy_summary, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 4: CLONE TRENDS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Trends Dashboard
 * 
 * Purpose: Analyze clone creation and deletion patterns over time
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CLONE_TRENDS_DASHBOARD(
    P_DAYS_BACK INTEGER DEFAULT 30
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_daily_activity ARRAY;
    v_weekly_summary ARRAY;
    v_user_trends ARRAY;
    v_env_trends ARRAY;
    v_peak_hours ARRAY;
    v_total_creates INTEGER;
    v_total_deletes INTEGER;
    v_net_change INTEGER;
BEGIN
    -- Daily activity
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'date', DT,
        'creates', CREATES,
        'deletes', DELETES,
        'net_change', CREATES - DELETES
    )) INTO v_daily_activity
    FROM (
        SELECT 
            DATE_TRUNC('DAY', TIMESTAMP)::DATE AS DT,
            COUNT_IF(OPERATION = 'CREATE') AS CREATES,
            COUNT_IF(OPERATION = 'DELETE') AS DELETES
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY DT
        ORDER BY DT
    );
    
    -- Weekly summary
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'week_start', WK,
        'total_operations', TOTAL,
        'creates', CREATES,
        'deletes', DELETES,
        'unique_users', USERS
    )) INTO v_weekly_summary
    FROM (
        SELECT 
            DATE_TRUNC('WEEK', TIMESTAMP)::DATE AS WK,
            COUNT(*) AS TOTAL,
            COUNT_IF(OPERATION = 'CREATE') AS CREATES,
            COUNT_IF(OPERATION = 'DELETE') AS DELETES,
            COUNT(DISTINCT PERFORMED_BY) AS USERS
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY WK
        ORDER BY WK
    );
    
    -- User activity trends
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'user', USR,
        'total_operations', TOTAL,
        'creates', CREATES,
        'deletes', DELETES,
        'last_activity', LAST_ACT
    )) INTO v_user_trends
    FROM (
        SELECT 
            PERFORMED_BY AS USR,
            COUNT(*) AS TOTAL,
            COUNT_IF(OPERATION = 'CREATE') AS CREATES,
            COUNT_IF(OPERATION = 'DELETE') AS DELETES,
            MAX(TIMESTAMP) AS LAST_ACT
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY PERFORMED_BY
        ORDER BY TOTAL DESC
        LIMIT 15
    );
    
    -- Environment trends
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'environment', ENV,
        'total_operations', TOTAL,
        'creates', CREATES,
        'deletes', DELETES
    )) INTO v_env_trends
    FROM (
        SELECT 
            ENVIRONMENT AS ENV,
            COUNT(*) AS TOTAL,
            COUNT_IF(OPERATION = 'CREATE') AS CREATES,
            COUNT_IF(OPERATION = 'DELETE') AS DELETES
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
          AND ENVIRONMENT IS NOT NULL
        GROUP BY ENV
        ORDER BY TOTAL DESC
    );
    
    -- Peak hours
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'hour', HR,
        'operation_count', CNT
    )) INTO v_peak_hours
    FROM (
        SELECT 
            HOUR(TIMESTAMP) AS HR,
            COUNT(*) AS CNT
        FROM RBAC_CLONE_AUDIT_LOG
        WHERE TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP())
        GROUP BY HR
        ORDER BY HR
    );
    
    -- Totals
    SELECT 
        COUNT_IF(OPERATION = 'CREATE'),
        COUNT_IF(OPERATION = 'DELETE')
    INTO v_total_creates, v_total_deletes
    FROM RBAC_CLONE_AUDIT_LOG
    WHERE TIMESTAMP >= DATEADD(DAY, -P_DAYS_BACK, CURRENT_TIMESTAMP());
    
    v_net_change := v_total_creates - v_total_deletes;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'CLONE_TRENDS',
        'generated_at', CURRENT_TIMESTAMP(),
        'period', OBJECT_CONSTRUCT(
            'days_analyzed', P_DAYS_BACK,
            'start_date', DATEADD(DAY, -P_DAYS_BACK, CURRENT_DATE()),
            'end_date', CURRENT_DATE()
        ),
        'summary', OBJECT_CONSTRUCT(
            'total_creates', v_total_creates,
            'total_deletes', v_total_deletes,
            'net_change', v_net_change,
            'avg_daily_creates', ROUND(v_total_creates * 1.0 / P_DAYS_BACK, 1),
            'avg_daily_deletes', ROUND(v_total_deletes * 1.0 / P_DAYS_BACK, 1)
        ),
        'daily_activity', COALESCE(v_daily_activity, ARRAY_CONSTRUCT()),
        'weekly_summary', COALESCE(v_weekly_summary, ARRAY_CONSTRUCT()),
        'user_trends', COALESCE(v_user_trends, ARRAY_CONSTRUCT()),
        'environment_trends', COALESCE(v_env_trends, ARRAY_CONSTRUCT()),
        'peak_hours', COALESCE(v_peak_hours, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 5: UNIFIED CLONE MONITORING DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Clone Monitoring Dashboard (Unified)
 * 
 * Purpose: Single comprehensive dashboard combining all clone monitoring
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.CLONES.RBAC_CLONE_MONITORING_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_usage VARIANT;
    v_compliance VARIANT;
    v_alerts ARRAY := ARRAY_CONSTRUCT();
BEGIN
    -- Get usage dashboard
    CALL ADMIN.CLONES.RBAC_CLONE_USAGE_DASHBOARD() INTO v_usage;
    
    -- Get compliance dashboard
    CALL ADMIN.CLONES.RBAC_CLONE_COMPLIANCE_DASHBOARD() INTO v_compliance;
    
    -- Generate alerts
    IF (v_compliance:summary:open_violations > 0) THEN
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'WARNING',
            'message', v_compliance:summary:open_violations || ' open policy violations require attention',
            'action', 'CALL RBAC_GET_POLICY_VIOLATIONS(''OPEN'', NULL, NULL, NULL);'
        ));
    END IF;
    
    IF (v_usage:summary:clones_expiring_7_days > 0) THEN
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'INFO',
            'message', v_usage:summary:clones_expiring_7_days || ' clones expiring within 7 days',
            'action', 'Review expiring clones in dashboard'
        ));
    END IF;
    
    IF (v_compliance:violations_by_severity:CRITICAL > 0) THEN
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'CRITICAL',
            'message', 'Critical policy violations detected',
            'action', 'Immediate review required'
        ));
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'CLONE_MONITORING_UNIFIED',
        'generated_at', CURRENT_TIMESTAMP(),
        'health_status', CASE 
            WHEN v_compliance:status = 'CRITICAL' THEN 'CRITICAL'
            WHEN v_compliance:status = 'NON_COMPLIANT' THEN 'WARNING'
            WHEN v_usage:summary:clones_expiring_7_days > 5 THEN 'ATTENTION'
            ELSE 'HEALTHY'
        END,
        'alerts', v_alerts,
        'quick_stats', OBJECT_CONSTRUCT(
            'total_active_clones', v_usage:summary:total_active_clones,
            'compliance_percentage', v_compliance:summary:compliance_percentage,
            'open_violations', v_compliance:summary:open_violations,
            'expiring_soon', v_usage:summary:clones_expiring_7_days
        ),
        'usage', v_usage,
        'compliance', v_compliance
    );
END;
$$;

-- #############################################################################
-- SECTION 6: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CLONE_USAGE_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CLONE_USAGE_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CLONE_STORAGE_DASHBOARD(FLOAT) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CLONE_COMPLIANCE_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CLONE_TRENDS_DASHBOARD(INTEGER) TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CLONE_MONITORING_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.CLONES.RBAC_CLONE_MONITORING_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
