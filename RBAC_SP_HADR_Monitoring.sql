/*******************************************************************************
 * RBAC STORED PROCEDURE: HA/DR Monitoring Dashboard
 * 
 * Purpose: Real-time monitoring of HA/DR status including:
 *          - Replication health and lag
 *          - Failover readiness
 *          - RTO/RPO compliance
 *          - DR test results
 *          - Historical failover events
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          HADR
 *   Object Type:     PROCEDURES (~5)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN, ACCOUNTADMIN (for replication status)
 * 
 *   Dependencies:    
 *     - ADMIN database and HADR schema must exist
 *     - RBAC_SP_HADR_Management.sql must be deployed first
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT: ADMIN.HADR schema
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA HADR;

-- #############################################################################
-- SECTION 1: REPLICATION HEALTH DASHBOARD
-- #############################################################################

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_REPLICATION_HEALTH_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_total_groups INTEGER;
    v_healthy_groups INTEGER;
    v_warning_groups INTEGER;
    v_critical_groups INTEGER;
    v_groups_detail VARIANT;
    v_replication_lag_avg INTEGER;
BEGIN
    -- Count by health status
    SELECT 
        COUNT(*),
        COUNT_IF(DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()) <= RPO_TARGET_MINUTES * 0.5),
        COUNT_IF(DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()) BETWEEN RPO_TARGET_MINUTES * 0.5 AND RPO_TARGET_MINUTES),
        COUNT_IF(DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()) > RPO_TARGET_MINUTES)
    INTO v_total_groups, v_healthy_groups, v_warning_groups, v_critical_groups
    FROM HADR_REPLICATION_GROUPS
    WHERE STATUS = 'ACTIVE';
    
    -- Average replication lag
    SELECT AVG(DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()))
    INTO v_replication_lag_avg
    FROM HADR_REPLICATION_GROUPS
    WHERE STATUS = 'ACTIVE';
    
    -- Detailed group status
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'group_name', GROUP_NAME,
        'replication_type', REPLICATION_TYPE,
        'is_primary', IS_PRIMARY,
        'source_region', SOURCE_REGION,
        'target_region', TARGET_REGION,
        'last_refresh', LAST_REFRESH_AT,
        'lag_minutes', DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()),
        'rpo_target_minutes', RPO_TARGET_MINUTES,
        'rpo_status', CASE
            WHEN DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()) <= RPO_TARGET_MINUTES * 0.5 THEN 'HEALTHY'
            WHEN DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()) <= RPO_TARGET_MINUTES THEN 'WARNING'
            ELSE 'CRITICAL'
        END,
        'databases', INCLUDED_DATABASES
    )) WITHIN GROUP (ORDER BY 
        CASE WHEN DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()) > RPO_TARGET_MINUTES THEN 0 ELSE 1 END,
        GROUP_NAME) INTO v_groups_detail
    FROM HADR_REPLICATION_GROUPS
    WHERE STATUS = 'ACTIVE';
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'REPLICATION_HEALTH',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_groups', v_total_groups,
            'healthy', v_healthy_groups,
            'warning', v_warning_groups,
            'critical', v_critical_groups,
            'average_lag_minutes', v_replication_lag_avg
        ),
        'overall_status', CASE
            WHEN v_critical_groups > 0 THEN 'CRITICAL'
            WHEN v_warning_groups > 0 THEN 'WARNING'
            ELSE 'HEALTHY'
        END,
        'groups', COALESCE(v_groups_detail, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 2: FAILOVER READINESS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Failover Readiness Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_FAILOVER_READINESS_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_failover_groups VARIANT;
    v_readiness_checks VARIANT := ARRAY_CONSTRUCT();
    v_overall_ready BOOLEAN := TRUE;
    v_last_test_results VARIANT;
BEGIN
    -- Get failover group status
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'group_name', f.GROUP_NAME,
        'failover_type', f.FAILOVER_TYPE,
        'is_primary', f.IS_PRIMARY,
        'source_account', f.SOURCE_ACCOUNT,
        'target_account', f.TARGET_ACCOUNT,
        'databases', f.DATABASES,
        'status', f.STATUS,
        'replication_lag_minutes', COALESCE(DATEDIFF(MINUTE, r.LAST_REFRESH_AT, CURRENT_TIMESTAMP()), 0),
        'failover_ready', CASE
            WHEN f.STATUS = 'ACTIVE' AND COALESCE(DATEDIFF(MINUTE, r.LAST_REFRESH_AT, CURRENT_TIMESTAMP()), 0) <= 60 THEN TRUE
            ELSE FALSE
        END
    )) INTO v_failover_groups
    FROM HADR_FAILOVER_GROUPS f
    LEFT JOIN HADR_REPLICATION_GROUPS r ON f.REPLICATION_GROUP_ID = r.GROUP_ID;
    
    -- Check if all groups are ready
    FOR i IN 0 TO ARRAY_SIZE(COALESCE(v_failover_groups, ARRAY_CONSTRUCT())) - 1 LOOP
        IF (NOT v_failover_groups[i]:failover_ready::BOOLEAN) THEN
            v_overall_ready := FALSE;
        END IF;
    END LOOP;
    
    -- Readiness checks
    -- Check 1: Active replication groups
    LET v_active_count INTEGER := 0;
    SELECT COUNT(*) INTO v_active_count
    FROM HADR_REPLICATION_GROUPS WHERE STATUS = 'ACTIVE';
    
    v_readiness_checks := ARRAY_APPEND(v_readiness_checks, OBJECT_CONSTRUCT(
        'check', 'ACTIVE_REPLICATION',
        'status', IFF(v_active_count > 0, 'PASS', 'FAIL'),
        'detail', v_active_count || ' active replication groups'
    ));
    
    -- Check 2: Recent successful refresh
    LET v_recent_refresh INTEGER := 0;
    SELECT COUNT(*) INTO v_recent_refresh
    FROM HADR_REPLICATION_GROUPS 
    WHERE STATUS = 'ACTIVE' 
      AND LAST_REFRESH_AT > DATEADD(HOUR, -1, CURRENT_TIMESTAMP());
    
    v_readiness_checks := ARRAY_APPEND(v_readiness_checks, OBJECT_CONSTRUCT(
        'check', 'RECENT_REFRESH',
        'status', IFF(v_recent_refresh > 0, 'PASS', 'WARN'),
        'detail', v_recent_refresh || ' groups refreshed in last hour'
    ));
    
    -- Check 3: DR test passed recently
    LET v_recent_test INTEGER := 0;
    SELECT COUNT(*) INTO v_recent_test
    FROM HADR_DR_TESTS 
    WHERE PASSED = TRUE 
      AND COMPLETED_AT > DATEADD(DAY, -30, CURRENT_TIMESTAMP());
    
    v_readiness_checks := ARRAY_APPEND(v_readiness_checks, OBJECT_CONSTRUCT(
        'check', 'DR_TEST_PASSED',
        'status', IFF(v_recent_test > 0, 'PASS', 'WARN'),
        'detail', v_recent_test || ' successful DR tests in last 30 days'
    ));
    
    -- Last DR test results
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'test_name', TEST_NAME,
        'test_type', TEST_TYPE,
        'completed_at', COMPLETED_AT,
        'passed', PASSED,
        'rpo_achieved', RPO_ACHIEVED_MINUTES,
        'rto_achieved', RTO_ACHIEVED_MINUTES
    )) INTO v_last_test_results
    FROM (
        SELECT * FROM HADR_DR_TESTS
        WHERE STATUS = 'COMPLETED'
        ORDER BY COMPLETED_AT DESC
        LIMIT 5
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'FAILOVER_READINESS',
        'generated_at', CURRENT_TIMESTAMP(),
        'overall_ready', v_overall_ready,
        'readiness_status', IFF(v_overall_ready, 'READY', 'NOT_READY'),
        'readiness_checks', v_readiness_checks,
        'failover_groups', COALESCE(v_failover_groups, ARRAY_CONSTRUCT()),
        'recent_dr_tests', COALESCE(v_last_test_results, ARRAY_CONSTRUCT()),
        'recommendation', IFF(v_overall_ready, 
            'System is ready for failover if needed',
            'Review failing checks before relying on DR capability')
    );
END;
$$;

-- #############################################################################
-- SECTION 3: RTO/RPO COMPLIANCE DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: RTO/RPO Compliance Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_RTORPO_COMPLIANCE_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_rpo_compliance VARIANT;
    v_rto_from_tests VARIANT;
    v_compliance_history VARIANT;
    v_overall_rpo_compliant BOOLEAN := TRUE;
    v_overall_rto_compliant BOOLEAN := TRUE;
BEGIN
    -- RPO compliance by group
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'group_name', GROUP_NAME,
        'rpo_target_minutes', RPO_TARGET_MINUTES,
        'current_lag_minutes', DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()),
        'rpo_compliant', DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP()) <= RPO_TARGET_MINUTES,
        'rpo_margin_minutes', RPO_TARGET_MINUTES - DATEDIFF(MINUTE, COALESCE(LAST_REFRESH_AT, CREATED_AT), CURRENT_TIMESTAMP())
    )) INTO v_rpo_compliance
    FROM HADR_REPLICATION_GROUPS
    WHERE STATUS = 'ACTIVE';
    
    -- Check RPO compliance
    FOR i IN 0 TO ARRAY_SIZE(COALESCE(v_rpo_compliance, ARRAY_CONSTRUCT())) - 1 LOOP
        IF (NOT v_rpo_compliance[i]:rpo_compliant::BOOLEAN) THEN
            v_overall_rpo_compliant := FALSE;
        END IF;
    END LOOP;
    
    -- RTO from actual DR tests
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'test_name', t.TEST_NAME,
        'test_date', t.COMPLETED_AT,
        'rto_target_minutes', r.RTO_TARGET_MINUTES,
        'rto_achieved_minutes', t.RTO_ACHIEVED_MINUTES,
        'rto_compliant', t.RTO_ACHIEVED_MINUTES <= r.RTO_TARGET_MINUTES
    )) INTO v_rto_from_tests
    FROM HADR_DR_TESTS t
    JOIN HADR_REPLICATION_GROUPS r ON t.REPLICATION_GROUP_ID = r.GROUP_ID
    WHERE t.STATUS = 'COMPLETED' AND t.RTO_ACHIEVED_MINUTES IS NOT NULL
    ORDER BY t.COMPLETED_AT DESC
    LIMIT 10;
    
    -- Check RTO compliance from tests
    FOR i IN 0 TO ARRAY_SIZE(COALESCE(v_rto_from_tests, ARRAY_CONSTRUCT())) - 1 LOOP
        IF (NOT v_rto_from_tests[i]:rto_compliant::BOOLEAN) THEN
            v_overall_rto_compliant := FALSE;
        END IF;
    END LOOP;
    
    -- Historical compliance (last 30 days replication history)
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'date', HISTORY_DATE,
        'avg_lag_minutes', AVG_LAG,
        'max_lag_minutes', MAX_LAG,
        'refresh_count', REFRESH_COUNT
    )) INTO v_compliance_history
    FROM (
        SELECT 
            TO_DATE(STARTED_AT) AS HISTORY_DATE,
            AVG(REPLICATION_LAG_SECONDS / 60) AS AVG_LAG,
            MAX(REPLICATION_LAG_SECONDS / 60) AS MAX_LAG,
            COUNT(*) AS REFRESH_COUNT
        FROM HADR_REPLICATION_HISTORY
        WHERE STARTED_AT > DATEADD(DAY, -30, CURRENT_TIMESTAMP())
        GROUP BY HISTORY_DATE
        ORDER BY HISTORY_DATE
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'RTO_RPO_COMPLIANCE',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'rpo_compliant', v_overall_rpo_compliant,
            'rto_compliant', v_overall_rto_compliant,
            'overall_status', CASE
                WHEN v_overall_rpo_compliant AND v_overall_rto_compliant THEN 'COMPLIANT'
                WHEN v_overall_rpo_compliant OR v_overall_rto_compliant THEN 'PARTIAL'
                ELSE 'NON_COMPLIANT'
            END
        ),
        'rpo_compliance', COALESCE(v_rpo_compliance, ARRAY_CONSTRUCT()),
        'rto_from_tests', COALESCE(v_rto_from_tests, ARRAY_CONSTRUCT()),
        'compliance_history', COALESCE(v_compliance_history, ARRAY_CONSTRUCT()),
        'recommendations', CASE
            WHEN NOT v_overall_rpo_compliant THEN 'RPO breach detected. Check replication schedule and increase refresh frequency.'
            WHEN NOT v_overall_rto_compliant THEN 'RTO targets not met in recent tests. Review failover procedures.'
            ELSE 'All RTO/RPO targets are being met.'
        END
    );
END;
$$;

-- #############################################################################
-- SECTION 4: FAILOVER EVENTS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Failover Events Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_FAILOVER_EVENTS_DASHBOARD(
    P_DAYS INTEGER DEFAULT 90
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_events VARIANT;
    v_by_type VARIANT;
    v_by_reason VARIANT;
    v_avg_duration INTEGER;
    v_avg_data_loss INTEGER;
BEGIN
    -- All events in period
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'event_id', EVENT_ID,
        'event_type', EVENT_TYPE,
        'event_reason', EVENT_REASON,
        'source_account', SOURCE_ACCOUNT,
        'target_account', TARGET_ACCOUNT,
        'status', STATUS,
        'initiated_by', INITIATED_BY,
        'initiated_at', INITIATED_AT,
        'completed_at', COMPLETED_AT,
        'duration_minutes', DURATION_MINUTES,
        'data_loss_minutes', DATA_LOSS_MINUTES
    )) INTO v_events
    FROM HADR_FAILOVER_EVENTS
    WHERE INITIATED_AT > DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP())
    ORDER BY INITIATED_AT DESC;
    
    -- Count by type
    SELECT OBJECT_AGG(EVENT_TYPE, CNT) INTO v_by_type
    FROM (
        SELECT EVENT_TYPE, COUNT(*) AS CNT
        FROM HADR_FAILOVER_EVENTS
        WHERE INITIATED_AT > DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP())
        GROUP BY EVENT_TYPE
    );
    
    -- Count by reason
    SELECT OBJECT_AGG(COALESCE(EVENT_REASON, 'UNSPECIFIED'), CNT) INTO v_by_reason
    FROM (
        SELECT EVENT_REASON, COUNT(*) AS CNT
        FROM HADR_FAILOVER_EVENTS
        WHERE INITIATED_AT > DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP())
        GROUP BY EVENT_REASON
    );
    
    -- Average metrics
    SELECT 
        AVG(DURATION_MINUTES),
        AVG(DATA_LOSS_MINUTES)
    INTO v_avg_duration, v_avg_data_loss
    FROM HADR_FAILOVER_EVENTS
    WHERE INITIATED_AT > DATEADD(DAY, -P_DAYS, CURRENT_TIMESTAMP())
      AND STATUS = 'COMPLETED';
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'FAILOVER_EVENTS',
        'generated_at', CURRENT_TIMESTAMP(),
        'period_days', P_DAYS,
        'summary', OBJECT_CONSTRUCT(
            'total_events', ARRAY_SIZE(COALESCE(v_events, ARRAY_CONSTRUCT())),
            'avg_duration_minutes', v_avg_duration,
            'avg_data_loss_minutes', v_avg_data_loss
        ),
        'by_type', COALESCE(v_by_type, OBJECT_CONSTRUCT()),
        'by_reason', COALESCE(v_by_reason, OBJECT_CONSTRUCT()),
        'events', COALESCE(v_events, ARRAY_CONSTRUCT())
    );
END;
$$;

-- #############################################################################
-- SECTION 5: DR TEST RESULTS DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: DR Test Results Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_DR_TEST_RESULTS_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_summary VARIANT;
    v_by_type VARIANT;
    v_pass_rate FLOAT;
    v_recent_tests VARIANT;
    v_trends VARIANT;
BEGIN
    -- Summary stats
    SELECT OBJECT_CONSTRUCT(
        'total_tests', COUNT(*),
        'passed', COUNT_IF(PASSED = TRUE),
        'failed', COUNT_IF(PASSED = FALSE),
        'pending', COUNT_IF(STATUS = 'SCHEDULED'),
        'avg_rpo_achieved', AVG(RPO_ACHIEVED_MINUTES),
        'avg_rto_achieved', AVG(RTO_ACHIEVED_MINUTES)
    ) INTO v_summary
    FROM HADR_DR_TESTS;
    
    -- Pass rate
    SELECT TRY_TO_DOUBLE((COUNT_IF(PASSED = TRUE) * 100.0 / NULLIF(COUNT(*), 0)))
    INTO v_pass_rate
    FROM HADR_DR_TESTS
    WHERE STATUS = 'COMPLETED';
    
    -- By test type
    SELECT OBJECT_AGG(TEST_TYPE, STATS) INTO v_by_type
    FROM (
        SELECT TEST_TYPE, OBJECT_CONSTRUCT(
            'total', COUNT(*),
            'passed', COUNT_IF(PASSED = TRUE),
            'pass_rate', TRY_TO_DOUBLE((COUNT_IF(PASSED = TRUE) * 100.0 / NULLIF(COUNT(*), 0)))
        ) AS STATS
        FROM HADR_DR_TESTS
        WHERE STATUS = 'COMPLETED'
        GROUP BY TEST_TYPE
    );
    
    -- Recent tests
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'test_id', TEST_ID,
        'test_name', TEST_NAME,
        'test_type', TEST_TYPE,
        'status', STATUS,
        'completed_at', COMPLETED_AT,
        'passed', PASSED,
        'rpo_achieved', RPO_ACHIEVED_MINUTES,
        'rto_achieved', RTO_ACHIEVED_MINUTES,
        'executed_by', EXECUTED_BY
    )) INTO v_recent_tests
    FROM (
        SELECT * FROM HADR_DR_TESTS
        ORDER BY COALESCE(COMPLETED_AT, SCHEDULED_AT) DESC
        LIMIT 15
    );
    
    -- Monthly trends
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
        'month', TEST_MONTH,
        'tests_run', CNT,
        'passed', PASS_CNT,
        'pass_rate', TRY_TO_DOUBLE((PASS_CNT * 100.0 / NULLIF(CNT, 0)))
    )) INTO v_trends
    FROM (
        SELECT 
            DATE_TRUNC('MONTH', COMPLETED_AT) AS TEST_MONTH,
            COUNT(*) AS CNT,
            COUNT_IF(PASSED = TRUE) AS PASS_CNT
        FROM HADR_DR_TESTS
        WHERE STATUS = 'COMPLETED'
        GROUP BY TEST_MONTH
        ORDER BY TEST_MONTH DESC
        LIMIT 12
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'DR_TEST_RESULTS',
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', v_summary,
        'pass_rate_percent', v_pass_rate,
        'by_test_type', COALESCE(v_by_type, OBJECT_CONSTRUCT()),
        'recent_tests', COALESCE(v_recent_tests, ARRAY_CONSTRUCT()),
        'monthly_trends', COALESCE(v_trends, ARRAY_CONSTRUCT()),
        'recommendation', CASE
            WHEN v_pass_rate IS NULL OR v_pass_rate < 80 THEN 'DR test pass rate is below 80%. Review and address failing tests.'
            WHEN (SELECT COUNT(*) FROM HADR_DR_TESTS WHERE COMPLETED_AT > DATEADD(DAY, -30, CURRENT_TIMESTAMP())) = 0 THEN 'No DR tests in last 30 days. Schedule regular DR testing.'
            ELSE 'DR testing program is healthy.'
        END
    );
END;
$$;

-- #############################################################################
-- SECTION 6: UNIFIED HADR MONITORING DASHBOARD
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Unified HADR Monitoring Dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_HADR_MONITORING_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_replication VARIANT;
    v_failover_readiness VARIANT;
    v_rtorpo VARIANT;
    v_dr_tests VARIANT;
    v_overall_health VARCHAR;
    v_alerts VARIANT := ARRAY_CONSTRUCT();
BEGIN
    -- Gather all dashboards
    CALL ADMIN.HADR.RBAC_REPLICATION_HEALTH_DASHBOARD() INTO v_replication;
    CALL ADMIN.HADR.RBAC_FAILOVER_READINESS_DASHBOARD() INTO v_failover_readiness;
    CALL ADMIN.HADR.RBAC_RTORPO_COMPLIANCE_DASHBOARD() INTO v_rtorpo;
    CALL ADMIN.HADR.RBAC_DR_TEST_RESULTS_DASHBOARD() INTO v_dr_tests;
    
    -- Determine overall health
    IF (v_replication:overall_status = 'CRITICAL') THEN
        v_overall_health := 'CRITICAL';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'CRITICAL',
            'message', 'Replication is in critical state - RPO may be breached',
            'source', 'REPLICATION_HEALTH'
        ));
    ELSEIF (NOT TO_BOOLEAN(v_failover_readiness:overall_ready)) THEN
        v_overall_health := 'WARNING';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'WARNING',
            'message', 'System is not ready for failover',
            'source', 'FAILOVER_READINESS'
        ));
    ELSEIF (v_rtorpo:summary:overall_status = 'NON_COMPLIANT') THEN
        v_overall_health := 'WARNING';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'WARNING',
            'message', 'RTO/RPO compliance issues detected',
            'source', 'RTO_RPO_COMPLIANCE'
        ));
    ELSEIF (v_replication:overall_status = 'WARNING') THEN
        v_overall_health := 'ATTENTION';
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'INFO',
            'message', 'Replication lag approaching RPO threshold',
            'source', 'REPLICATION_HEALTH'
        ));
    ELSE
        v_overall_health := 'HEALTHY';
    END IF;
    
    -- Check for stale DR tests
    LET v_days_since_test INTEGER := 0;
    SELECT DATEDIFF(DAY, MAX(COMPLETED_AT), CURRENT_TIMESTAMP())
    INTO v_days_since_test
    FROM HADR_DR_TESTS WHERE STATUS = 'COMPLETED';
    
    IF (v_days_since_test IS NULL OR v_days_since_test > 30) THEN
        v_alerts := ARRAY_APPEND(v_alerts, OBJECT_CONSTRUCT(
            'level', 'INFO',
            'message', 'No DR test in over 30 days. Consider scheduling a test.',
            'source', 'DR_TESTS'
        ));
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'HADR_MONITORING_UNIFIED',
        'generated_at', CURRENT_TIMESTAMP(),
        'overall_health', v_overall_health,
        'alerts', v_alerts,
        'quick_stats', OBJECT_CONSTRUCT(
            'replication_groups', v_replication:summary:total_groups,
            'replication_status', v_replication:overall_status,
            'failover_ready', v_failover_readiness:overall_ready,
            'rpo_compliant', v_rtorpo:summary:rpo_compliant,
            'rto_compliant', v_rtorpo:summary:rto_compliant,
            'dr_test_pass_rate', v_dr_tests:pass_rate_percent,
            'avg_replication_lag_minutes', v_replication:summary:average_lag_minutes
        ),
        'replication_health', v_replication,
        'failover_readiness', v_failover_readiness,
        'rtorpo_compliance', v_rtorpo,
        'dr_test_results', v_dr_tests
    );
END;
$$;

-- #############################################################################
-- SECTION 7: DR RUNBOOK GENERATOR
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Generate DR Runbook
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.HADR.RBAC_GENERATE_DR_RUNBOOK(
    P_GROUP_NAME VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_group VARIANT;
    v_runbook VARIANT := ARRAY_CONSTRUCT();
BEGIN
    -- Get group details
    SELECT OBJECT_CONSTRUCT(
        'group_name', r.GROUP_NAME,
        'source_account', r.SOURCE_ACCOUNT,
        'source_region', r.SOURCE_REGION,
        'target_account', r.TARGET_ACCOUNT,
        'target_region', r.TARGET_REGION,
        'databases', r.INCLUDED_DATABASES,
        'rpo_target', r.RPO_TARGET_MINUTES,
        'rto_target', r.RTO_TARGET_MINUTES
    ) INTO v_group
    FROM HADR_REPLICATION_GROUPS r
    WHERE r.GROUP_NAME = P_GROUP_NAME;
    
    IF (v_group IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Group not found: ' || P_GROUP_NAME);
    END IF;
    
    -- Build runbook steps
    v_runbook := ARRAY_APPEND(v_runbook, OBJECT_CONSTRUCT(
        'step', 1,
        'phase', 'ASSESSMENT',
        'title', 'Assess the Situation',
        'actions', ARRAY_CONSTRUCT(
            'Determine if failover is necessary (planned maintenance vs. unplanned outage)',
            'Check replication status: CALL ADMIN.HADR.RBAC_CHECK_REPLICATION_STATUS(''' || P_GROUP_NAME || ''')',
            'Verify target account accessibility',
            'Notify stakeholders of potential failover'
        ),
        'decision_point', 'Proceed with failover? If yes, continue to Step 2.'
    ));
    
    v_runbook := ARRAY_APPEND(v_runbook, OBJECT_CONSTRUCT(
        'step', 2,
        'phase', 'PREPARATION',
        'title', 'Prepare for Failover',
        'actions', ARRAY_CONSTRUCT(
            'If planned: Ensure final replication sync - CALL ADMIN.HADR.RBAC_REFRESH_REPLICATION(''' || P_GROUP_NAME || ''')',
            'Document current RPO status and any expected data loss',
            'Prepare application connection string updates',
            'Alert application teams of impending failover'
        ),
        'estimated_time', '15 minutes'
    ));
    
    v_runbook := ARRAY_APPEND(v_runbook, OBJECT_CONSTRUCT(
        'step', 3,
        'phase', 'EXECUTION',
        'title', 'Execute Failover',
        'actions', ARRAY_CONSTRUCT(
            'For PLANNED failover:',
            '  CALL ADMIN.HADR.RBAC_INITIATE_FAILOVER(''' || P_GROUP_NAME || ''', ''PLANNED'', ''<reason>'', TRUE)',
            '',
            'For UNPLANNED/EMERGENCY failover:',
            '  CALL ADMIN.HADR.RBAC_INITIATE_FAILOVER(''' || P_GROUP_NAME || ''', ''UNPLANNED'', ''<reason>'', TRUE)'
        ),
        'target_account', TO_VARCHAR(v_group:target_account),
        'estimated_time', '5-15 minutes'
    ));
    
    v_runbook := ARRAY_APPEND(v_runbook, OBJECT_CONSTRUCT(
        'step', 4,
        'phase', 'VALIDATION',
        'title', 'Validate Failover',
        'actions', ARRAY_CONSTRUCT(
            'Verify databases are accessible on ' || TO_VARCHAR(v_group:target_account),
            'Check data integrity with sample queries',
            'Verify application connectivity',
            'Run smoke tests on critical functions'
        ),
        'databases', v_group:databases,
        'estimated_time', '15-30 minutes'
    ));
    
    v_runbook := ARRAY_APPEND(v_runbook, OBJECT_CONSTRUCT(
        'step', 5,
        'phase', 'COMMUNICATION',
        'title', 'Post-Failover Communication',
        'actions', ARRAY_CONSTRUCT(
            'Update DNS/connection strings if not automatic',
            'Notify all stakeholders of completed failover',
            'Document actual RTO and any data loss (RPO breach)',
            'Create incident ticket if unplanned'
        )
    ));
    
    v_runbook := ARRAY_APPEND(v_runbook, OBJECT_CONSTRUCT(
        'step', 6,
        'phase', 'FAILBACK_PLANNING',
        'title', 'Plan Failback (When Primary Recovers)',
        'actions', ARRAY_CONSTRUCT(
            'Monitor original primary region recovery',
            'Re-establish replication to original primary',
            'Schedule failback window',
            'Execute failback: CALL ADMIN.HADR.RBAC_INITIATE_FAILBACK(''' || P_GROUP_NAME || ''', TRUE)'
        )
    ));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'runbook_type', 'DR_FAILOVER',
        'group_name', P_GROUP_NAME,
        'generated_at', CURRENT_TIMESTAMP(),
        'configuration', v_group,
        'rto_target_minutes', v_group:rto_target,
        'rpo_target_minutes', v_group:rpo_target,
        'steps', v_runbook,
        'emergency_contacts', 'Update with your team contacts',
        'notes', ARRAY_CONSTRUCT(
            'Always verify replication status before failover',
            'Document actual RTO/RPO for post-incident review',
            'Test this runbook regularly with DR drills'
        )
    );
END;
$$;

-- #############################################################################
-- SECTION 8: GRANT PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_REPLICATION_HEALTH_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_FAILOVER_READINESS_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_RTORPO_COMPLIANCE_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_FAILOVER_EVENTS_DASHBOARD(INTEGER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_DR_TEST_RESULTS_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_HADR_MONITORING_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_GENERATE_DR_RUNBOOK(VARCHAR) TO ROLE SRS_SECURITY_ADMIN;

-- DBAdmins can view dashboards
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_REPLICATION_HEALTH_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_FAILOVER_READINESS_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_RTORPO_COMPLIANCE_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_HADR_MONITORING_DASHBOARD() TO ROLE SRS_SYSTEM_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.HADR.RBAC_GENERATE_DR_RUNBOOK(VARCHAR) TO ROLE SRS_SYSTEM_ADMIN;
