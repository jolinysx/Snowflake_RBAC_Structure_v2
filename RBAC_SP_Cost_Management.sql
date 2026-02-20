/*******************************************************************************
 * RBAC STORED PROCEDURE: Cost Management & Resource Monitoring
 * 
 * Purpose: Comprehensive cost management including:
 *   - Resource Monitor creation and management
 *   - Snowflake Budget creation and tracking
 *   - Credit consumption dashboards
 *   - Cost allocation and chargeback
 *   - Alert configuration for cost thresholds
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     TABLES (4), PROCEDURES (~15)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns tables/procedures)
 *   Execution Role:  ACCOUNTADMIN (for resource monitors/budgets),
 *                    SRS_SECURITY_ADMIN (for cost centers/dashboards)
 * 
 *   Dependencies:    
 *     - ADMIN database and RBAC schema must exist
 *     - SNOWFLAKE.ACCOUNT_USAGE access required
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * COST MANAGEMENT HIERARCHY
 * ─────────────────────────────────────────────────────────────────────────────
 * 
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │                      SNOWFLAKE COST CONTROLS                            │
 *   ├─────────────────────────────────────────────────────────────────────────┤
 *   │                                                                         │
 *   │   ACCOUNT LEVEL                                                         │
 *   │   ─────────────                                                         │
 *   │   ┌─────────────────┐                                                   │
 *   │   │ Account Budget  │  Total monthly/yearly spend limit                │
 *   │   │ (Snowflake)     │  Tracks: Compute + Storage + Services            │
 *   │   └────────┬────────┘                                                   │
 *   │            │                                                            │
 *   │   WAREHOUSE LEVEL                                                       │
 *   │   ───────────────                                                       │
 *   │   ┌─────────────────┐                                                   │
 *   │   │Resource Monitor │  Credit limits per warehouse/group               │
 *   │   │                 │  Actions: Notify, Suspend, Kill                  │
 *   │   └────────┬────────┘                                                   │
 *   │            │                                                            │
 *   │   CUSTOM BUDGETS                                                        │
 *   │   ──────────────                                                        │
 *   │   ┌─────────────────┐                                                   │
 *   │   │ Custom Budgets  │  By: Environment, Team, Project, Cost Center    │
 *   │   │ (ADMIN tables)  │  Tracks: Usage vs Budget with alerts            │
 *   │   └─────────────────┘                                                   │
 *   │                                                                         │
 *   └─────────────────────────────────────────────────────────────────────────┘
 * 
 * PROCEDURES:
 * ─────────────────────────────────────────────────────────────────────────────
 *   Resource Monitors:
 *     - RBAC_CREATE_RESOURCE_MONITOR      Create resource monitor
 *     - RBAC_ASSIGN_RESOURCE_MONITOR      Assign monitor to warehouses
 *     - RBAC_MODIFY_RESOURCE_MONITOR      Update thresholds/actions
 *     - RBAC_LIST_RESOURCE_MONITORS       List all monitors with status
 *   
 *   Snowflake Budgets:
 *     - RBAC_CREATE_BUDGET                Create Snowflake budget
 *     - RBAC_MODIFY_BUDGET                Update budget amount
 *     - RBAC_LIST_BUDGETS                 List budgets with spending
 *   
 *   Custom Cost Tracking:
 *     - RBAC_CREATE_COST_CENTER           Create cost center for allocation
 *     - RBAC_TAG_WAREHOUSE_COST_CENTER    Tag warehouse to cost center
 *     - RBAC_SET_COST_CENTER_BUDGET       Set monthly budget for cost center
 *   
 *   Dashboards:
 *     - RBAC_COST_DASHBOARD               Unified cost overview
 *     - RBAC_WAREHOUSE_COST_DASHBOARD     Warehouse-level costs
 *     - RBAC_ENVIRONMENT_COST_DASHBOARD   Environment-level costs
 *     - RBAC_COST_TREND_DASHBOARD         Historical cost trends
 *     - RBAC_COST_ANOMALY_DASHBOARD       Unusual spending patterns
 *     - RBAC_CHARGEBACK_REPORT            Cost allocation report
 * 
 * Execution Role: SRS_SECURITY_ADMIN or ACCOUNTADMIN
 * 
 ******************************************************************************/

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE SRS_SYSTEM_ADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

-- #############################################################################
-- SECTION 1: COST TRACKING TABLES
-- #############################################################################

CREATE TABLE IF NOT EXISTS ADMIN.RBAC.RBAC_COST_CENTERS (
    COST_CENTER_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    COST_CENTER_NAME VARCHAR(100) NOT NULL UNIQUE,
    COST_CENTER_CODE VARCHAR(20) NOT NULL UNIQUE,
    DESCRIPTION VARCHAR(500),
    DEPARTMENT VARCHAR(100),
    OWNER_EMAIL VARCHAR(255),
    MONTHLY_BUDGET_CREDITS NUMBER(10,2),
    QUARTERLY_BUDGET_CREDITS NUMBER(10,2),
    ANNUAL_BUDGET_CREDITS NUMBER(10,2),
    ALERT_THRESHOLD_PCT NUMBER(5,2) DEFAULT 80,
    CRITICAL_THRESHOLD_PCT NUMBER(5,2) DEFAULT 95,
    IS_ACTIVE BOOLEAN DEFAULT TRUE,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS ADMIN.RBAC.RBAC_WAREHOUSE_COST_MAPPING (
    MAPPING_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    WAREHOUSE_NAME VARCHAR(255) NOT NULL,
    COST_CENTER_ID VARCHAR(36) NOT NULL REFERENCES RBAC_COST_CENTERS(COST_CENTER_ID),
    ENVIRONMENT VARCHAR(10),
    ALLOCATION_PERCENTAGE NUMBER(5,2) DEFAULT 100,
    EFFECTIVE_DATE DATE DEFAULT CURRENT_DATE(),
    END_DATE DATE,
    CREATED_BY VARCHAR(255) DEFAULT CURRENT_USER(),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS ADMIN.RBAC.RBAC_COST_ALERTS (
    ALERT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    ALERT_TYPE VARCHAR(50) NOT NULL,
    COST_CENTER_ID VARCHAR(36),
    WAREHOUSE_NAME VARCHAR(255),
    RESOURCE_MONITOR_NAME VARCHAR(255),
    THRESHOLD_PCT NUMBER(5,2),
    CURRENT_PCT NUMBER(5,2),
    CREDITS_USED NUMBER(10,2),
    CREDITS_BUDGET NUMBER(10,2),
    ALERT_MESSAGE TEXT,
    ALERT_SEVERITY VARCHAR(20),
    ACKNOWLEDGED BOOLEAN DEFAULT FALSE,
    ACKNOWLEDGED_BY VARCHAR(255),
    ACKNOWLEDGED_AT TIMESTAMP_NTZ,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS ADMIN.RBAC.RBAC_COST_SNAPSHOTS (
    SNAPSHOT_ID VARCHAR(36) DEFAULT UUID_STRING() PRIMARY KEY,
    SNAPSHOT_DATE DATE NOT NULL,
    SNAPSHOT_TYPE VARCHAR(20) NOT NULL,
    COST_CENTER_ID VARCHAR(36),
    WAREHOUSE_NAME VARCHAR(255),
    ENVIRONMENT VARCHAR(10),
    CREDITS_USED NUMBER(10,2),
    CREDITS_BUDGET NUMBER(10,2),
    COMPUTE_CREDITS NUMBER(10,2),
    CLOUD_SERVICES_CREDITS NUMBER(10,2),
    STORAGE_BYTES NUMBER(18),
    STORAGE_COST_USD NUMBER(10,2),
    TOTAL_COST_USD NUMBER(10,2),
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- #############################################################################
-- SECTION 2: RESOURCE MONITOR MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC_CREATE_RESOURCE_MONITOR
 * 
 * Creates a resource monitor with specified credit limits and actions
 * 
 * Parameters:
 *   P_MONITOR_NAME      - Name for the resource monitor
 *   P_CREDIT_QUOTA      - Monthly credit quota
 *   P_FREQUENCY         - Reset frequency: MONTHLY, WEEKLY, DAILY, YEARLY, NEVER
 *   P_START_TIMESTAMP   - When monitoring starts (NULL = immediately)
 *   P_END_TIMESTAMP     - When monitoring ends (NULL = never)
 *   P_NOTIFY_USERS      - Array of users to notify
 *   P_NOTIFY_TRIGGERS   - Array of percentages for notifications (e.g., [50, 75, 90])
 *   P_SUSPEND_TRIGGERS  - Array of percentages to suspend warehouses
 *   P_SUSPEND_IMMEDIATE_TRIGGERS - Array of percentages to kill running queries
 * 
 * Execution Role: ACCOUNTADMIN
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_RESOURCE_MONITOR(
    P_MONITOR_NAME VARCHAR,
    P_CREDIT_QUOTA NUMBER,
    P_FREQUENCY VARCHAR DEFAULT 'MONTHLY',
    P_START_TIMESTAMP TIMESTAMP_NTZ DEFAULT NULL,
    P_END_TIMESTAMP TIMESTAMP_NTZ DEFAULT NULL,
    P_NOTIFY_USERS ARRAY DEFAULT NULL,
    P_NOTIFY_TRIGGERS ARRAY DEFAULT NULL,
    P_SUSPEND_TRIGGERS ARRAY DEFAULT NULL,
    P_SUSPEND_IMMEDIATE_TRIGGERS ARRAY DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
    v_notify_list VARCHAR := '';
    v_trigger_clause VARCHAR := '';
BEGIN
    -- Validate frequency
    IF (P_FREQUENCY NOT IN ('MONTHLY', 'WEEKLY', 'DAILY', 'YEARLY', 'NEVER')) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Invalid frequency. Must be: MONTHLY, WEEKLY, DAILY, YEARLY, or NEVER'
        );
    END IF;
    
    -- Build notify users list
    IF (P_NOTIFY_USERS IS NOT NULL AND ARRAY_SIZE(P_NOTIFY_USERS) > 0) THEN
        v_notify_list := ' NOTIFY_USERS = (';
        FOR i IN 0 TO ARRAY_SIZE(P_NOTIFY_USERS) - 1 DO
            IF (i > 0) THEN
                v_notify_list := v_notify_list || ', ';
            END IF;
            v_notify_list := v_notify_list || P_NOTIFY_USERS[i];
        END FOR;
        v_notify_list := v_notify_list || ')';
    END IF;
    
    -- Build trigger clauses
    IF (P_NOTIFY_TRIGGERS IS NOT NULL) THEN
        FOR i IN 0 TO ARRAY_SIZE(P_NOTIFY_TRIGGERS) - 1 DO
            v_trigger_clause := v_trigger_clause || ' TRIGGERS ON ' || P_NOTIFY_TRIGGERS[i]::VARCHAR || ' PERCENT DO NOTIFY';
        END FOR;
    END IF;
    
    IF (P_SUSPEND_TRIGGERS IS NOT NULL) THEN
        FOR i IN 0 TO ARRAY_SIZE(P_SUSPEND_TRIGGERS) - 1 DO
            v_trigger_clause := v_trigger_clause || ' TRIGGERS ON ' || P_SUSPEND_TRIGGERS[i]::VARCHAR || ' PERCENT DO SUSPEND';
        END FOR;
    END IF;
    
    IF (P_SUSPEND_IMMEDIATE_TRIGGERS IS NOT NULL) THEN
        FOR i IN 0 TO ARRAY_SIZE(P_SUSPEND_IMMEDIATE_TRIGGERS) - 1 DO
            v_trigger_clause := v_trigger_clause || ' TRIGGERS ON ' || P_SUSPEND_IMMEDIATE_TRIGGERS[i]::VARCHAR || ' PERCENT DO SUSPEND_IMMEDIATE';
        END FOR;
    END IF;
    
    -- Default triggers if none specified
    IF (v_trigger_clause = '') THEN
        v_trigger_clause := ' TRIGGERS ON 75 PERCENT DO NOTIFY ON 90 PERCENT DO NOTIFY ON 100 PERCENT DO SUSPEND';
    END IF;
    
    -- Build CREATE statement
    v_sql := 'CREATE OR REPLACE RESOURCE MONITOR ' || P_MONITOR_NAME ||
             ' WITH CREDIT_QUOTA = ' || P_CREDIT_QUOTA ||
             ' FREQUENCY = ' || P_FREQUENCY;
    
    IF (P_START_TIMESTAMP IS NOT NULL) THEN
        v_sql := v_sql || ' START_TIMESTAMP = ''' || P_START_TIMESTAMP || '''';
    ELSE
        v_sql := v_sql || ' START_TIMESTAMP = IMMEDIATELY';
    END IF;
    
    IF (P_END_TIMESTAMP IS NOT NULL) THEN
        v_sql := v_sql || ' END_TIMESTAMP = ''' || P_END_TIMESTAMP || '''';
    END IF;
    
    v_sql := v_sql || v_notify_list || v_trigger_clause;
    
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_RESOURCE_MONITOR', 'sql', v_sql));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'monitor_name', P_MONITOR_NAME,
        'credit_quota', P_CREDIT_QUOTA,
        'frequency', P_FREQUENCY,
        'notify_triggers', P_NOTIFY_TRIGGERS,
        'suspend_triggers', P_SUSPEND_TRIGGERS,
        'suspend_immediate_triggers', P_SUSPEND_IMMEDIATE_TRIGGERS,
        'actions', v_actions,
        'message', 'Resource monitor created. Use RBAC_ASSIGN_RESOURCE_MONITOR to assign warehouses.'
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'sqlcode', SQLCODE,
            'sql_attempted', v_sql
        );
END;
$$;

/*******************************************************************************
 * RBAC_ASSIGN_RESOURCE_MONITOR
 * 
 * Assigns a resource monitor to one or more warehouses
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_ASSIGN_RESOURCE_MONITOR(
    P_MONITOR_NAME VARCHAR,
    P_WAREHOUSES ARRAY,
    P_SET_AS_ACCOUNT_MONITOR BOOLEAN DEFAULT FALSE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
    v_warehouse VARCHAR;
BEGIN
    -- Optionally set as account-level monitor
    IF (P_SET_AS_ACCOUNT_MONITOR) THEN
        v_sql := 'ALTER ACCOUNT SET RESOURCE_MONITOR = ' || P_MONITOR_NAME;
        EXECUTE IMMEDIATE v_sql;
        v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
            'action', 'SET_ACCOUNT_MONITOR',
            'sql', v_sql
        ));
    END IF;
    
    -- Assign to each warehouse
    IF (P_WAREHOUSES IS NOT NULL) THEN
        FOR i IN 0 TO ARRAY_SIZE(P_WAREHOUSES) - 1 DO
            v_warehouse := P_WAREHOUSES[i]::VARCHAR;
            v_sql := 'ALTER WAREHOUSE ' || v_warehouse || ' SET RESOURCE_MONITOR = ' || P_MONITOR_NAME;
            
            BEGIN
                EXECUTE IMMEDIATE v_sql;
                v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                    'action', 'ASSIGN_WAREHOUSE',
                    'warehouse', v_warehouse,
                    'sql', v_sql,
                    'status', 'SUCCESS'
                ));
            EXCEPTION
                WHEN OTHER THEN
                    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT(
                        'action', 'ASSIGN_WAREHOUSE',
                        'warehouse', v_warehouse,
                        'sql', v_sql,
                        'status', 'ERROR',
                        'error', SQLERRM
                    ));
            END;
        END FOR;
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'monitor_name', P_MONITOR_NAME,
        'account_monitor', P_SET_AS_ACCOUNT_MONITOR,
        'warehouses_assigned', P_WAREHOUSES,
        'actions', v_actions
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
 * RBAC_LIST_RESOURCE_MONITORS
 * 
 * Lists all resource monitors with current usage
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_LIST_RESOURCE_MONITORS()
RETURNS TABLE (
    MONITOR_NAME VARCHAR,
    CREDIT_QUOTA NUMBER,
    USED_CREDITS NUMBER,
    REMAINING_CREDITS NUMBER,
    USED_PERCENTAGE NUMBER,
    FREQUENCY VARCHAR,
    START_TIME TIMESTAMP_NTZ,
    END_TIME TIMESTAMP_NTZ,
    NOTIFY_AT VARCHAR,
    SUSPEND_AT NUMBER,
    SUSPEND_IMMEDIATE_AT NUMBER,
    LEVEL VARCHAR,
    WAREHOUSES VARCHAR
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
            NAME AS MONITOR_NAME,
            CREDIT_QUOTA,
            USED_CREDITS,
            CREDIT_QUOTA - USED_CREDITS AS REMAINING_CREDITS,
            ROUND((USED_CREDITS / NULLIF(CREDIT_QUOTA, 0)) * 100, 2) AS USED_PERCENTAGE,
            FREQUENCY,
            START_TIME,
            END_TIME,
            NOTIFY_AT,
            SUSPEND_AT,
            SUSPEND_IMMEDIATELY_AT AS SUSPEND_IMMEDIATE_AT,
            LEVEL,
            NULL AS WAREHOUSES
        FROM TABLE(INFORMATION_SCHEMA.RESOURCE_MONITORS())
        ORDER BY NAME
    );
    
    RETURN TABLE(res);
END;
$$;

-- #############################################################################
-- SECTION 3: SNOWFLAKE BUDGET MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC_CREATE_BUDGET
 * 
 * Creates a Snowflake budget for spend tracking
 * 
 * NOTE: Requires Enterprise Edition or higher
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_BUDGET(
    P_BUDGET_NAME VARCHAR,
    P_BUDGET_AMOUNT NUMBER,
    P_START_DATE DATE DEFAULT NULL,
    P_END_DATE DATE DEFAULT NULL,
    P_NOTIFY_USERS ARRAY DEFAULT NULL,
    P_EMAIL_NOTIFICATIONS BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    -- Set defaults
    v_start_date := COALESCE(P_START_DATE, DATE_TRUNC('MONTH', CURRENT_DATE()));
    v_end_date := COALESCE(P_END_DATE, DATEADD('YEAR', 1, v_start_date));
    
    -- Create budget
    v_sql := 'CREATE OR REPLACE SNOWFLAKE.CORE.BUDGET ' || P_BUDGET_NAME || '()';
    
    BEGIN
        EXECUTE IMMEDIATE v_sql;
        
        -- Set spending limit
        v_sql := 'CALL SNOWFLAKE.CORE.BUDGET!' || P_BUDGET_NAME || '!SET_SPENDING_LIMIT(' || P_BUDGET_AMOUNT || ')';
        EXECUTE IMMEDIATE v_sql;
        
        -- Enable email notifications if requested
        IF (P_EMAIL_NOTIFICATIONS) THEN
            v_sql := 'CALL SNOWFLAKE.CORE.BUDGET!' || P_BUDGET_NAME || '!SET_EMAIL_NOTIFICATIONS(TRUE)';
            EXECUTE IMMEDIATE v_sql;
        END IF;
        
        RETURN OBJECT_CONSTRUCT(
            'status', 'SUCCESS',
            'budget_name', P_BUDGET_NAME,
            'budget_amount', P_BUDGET_AMOUNT,
            'start_date', v_start_date,
            'end_date', v_end_date,
            'email_notifications', P_EMAIL_NOTIFICATIONS,
            'message', 'Budget created successfully. Use RBAC_LIST_BUDGETS to view spending.'
        );
        
    EXCEPTION
        WHEN OTHER THEN
            -- Check if it's an edition limitation
            IF (SQLERRM LIKE '%BUDGET%not%supported%' OR SQLERRM LIKE '%Enterprise%') THEN
                RETURN OBJECT_CONSTRUCT(
                    'status', 'ERROR',
                    'message', 'Snowflake Budgets require Enterprise Edition or higher. Use Resource Monitors instead.',
                    'recommendation', 'CALL RBAC_CREATE_RESOURCE_MONITOR() for credit-based limits'
                );
            ELSE
                RETURN OBJECT_CONSTRUCT(
                    'status', 'ERROR',
                    'message', SQLERRM,
                    'sqlcode', SQLCODE
                );
            END IF;
    END;
END;
$$;

/*******************************************************************************
 * RBAC_LIST_BUDGETS
 * 
 * Lists all Snowflake budgets with current spending
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_LIST_BUDGETS()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    -- Query budget information from ACCOUNT_USAGE
    LET v_budgets ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'budget_name', BUDGET_NAME,
            'spending_limit', SPENDING_LIMIT,
            'spent_amount', SPENT,
            'remaining', SPENDING_LIMIT - SPENT,
            'used_percentage', ROUND((SPENT / NULLIF(SPENDING_LIMIT, 0)) * 100, 2)
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.BUDGETS
        WHERE DELETED IS NULL
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'budgets', v_budgets,
        'retrieved_at', CURRENT_TIMESTAMP()
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'note', 'Budgets feature may not be available in your edition'
        );
END;
$$;

-- #############################################################################
-- SECTION 4: COST CENTER MANAGEMENT
-- #############################################################################

/*******************************************************************************
 * RBAC_CREATE_COST_CENTER
 * 
 * Creates a cost center for internal cost allocation/chargeback
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_COST_CENTER(
    P_NAME VARCHAR,
    P_CODE VARCHAR,
    P_DESCRIPTION VARCHAR DEFAULT NULL,
    P_DEPARTMENT VARCHAR DEFAULT NULL,
    P_OWNER_EMAIL VARCHAR DEFAULT NULL,
    P_MONTHLY_BUDGET NUMBER DEFAULT NULL,
    P_ALERT_THRESHOLD_PCT NUMBER DEFAULT 80,
    P_CRITICAL_THRESHOLD_PCT NUMBER DEFAULT 95
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    INSERT INTO RBAC_COST_CENTERS (
        COST_CENTER_NAME,
        COST_CENTER_CODE,
        DESCRIPTION,
        DEPARTMENT,
        OWNER_EMAIL,
        MONTHLY_BUDGET_CREDITS,
        ALERT_THRESHOLD_PCT,
        CRITICAL_THRESHOLD_PCT
    ) VALUES (
        P_NAME,
        UPPER(P_CODE),
        P_DESCRIPTION,
        P_DEPARTMENT,
        P_OWNER_EMAIL,
        P_MONTHLY_BUDGET,
        P_ALERT_THRESHOLD_PCT,
        P_CRITICAL_THRESHOLD_PCT
    );
    
    LET v_cost_center_id VARCHAR := (
        SELECT COST_CENTER_ID FROM RBAC_COST_CENTERS 
        WHERE COST_CENTER_CODE = UPPER(P_CODE)
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'cost_center_id', v_cost_center_id,
        'cost_center_name', P_NAME,
        'cost_center_code', UPPER(P_CODE),
        'monthly_budget_credits', P_MONTHLY_BUDGET,
        'alert_at_pct', P_ALERT_THRESHOLD_PCT,
        'critical_at_pct', P_CRITICAL_THRESHOLD_PCT,
        'message', 'Cost center created. Use RBAC_TAG_WAREHOUSE_COST_CENTER to assign warehouses.'
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
 * RBAC_TAG_WAREHOUSE_COST_CENTER
 * 
 * Associates a warehouse with a cost center for allocation
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_TAG_WAREHOUSE_COST_CENTER(
    P_WAREHOUSE_NAME VARCHAR,
    P_COST_CENTER_CODE VARCHAR,
    P_ALLOCATION_PCT NUMBER DEFAULT 100
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_cost_center_id VARCHAR;
    v_environment VARCHAR;
BEGIN
    -- Look up cost center
    SELECT COST_CENTER_ID INTO v_cost_center_id
    FROM RBAC_COST_CENTERS 
    WHERE COST_CENTER_CODE = UPPER(P_COST_CENTER_CODE)
      AND IS_ACTIVE = TRUE;
    
    IF (v_cost_center_id IS NULL) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', 'Cost center not found: ' || P_COST_CENTER_CODE
        );
    END IF;
    
    -- Determine environment from warehouse name
    v_environment := CASE 
        WHEN P_WAREHOUSE_NAME LIKE 'DEV%' THEN 'DEV'
        WHEN P_WAREHOUSE_NAME LIKE 'TST%' THEN 'TST'
        WHEN P_WAREHOUSE_NAME LIKE 'UAT%' THEN 'UAT'
        WHEN P_WAREHOUSE_NAME LIKE 'PPE%' THEN 'PPE'
        WHEN P_WAREHOUSE_NAME LIKE 'PRD%' THEN 'PRD'
        ELSE NULL
    END;
    
    -- End any existing mapping
    UPDATE RBAC_WAREHOUSE_COST_MAPPING
    SET END_DATE = CURRENT_DATE()
    WHERE WAREHOUSE_NAME = UPPER(P_WAREHOUSE_NAME)
      AND END_DATE IS NULL;
    
    -- Create new mapping
    INSERT INTO RBAC_WAREHOUSE_COST_MAPPING (
        WAREHOUSE_NAME,
        COST_CENTER_ID,
        ENVIRONMENT,
        ALLOCATION_PERCENTAGE
    ) VALUES (
        UPPER(P_WAREHOUSE_NAME),
        v_cost_center_id,
        v_environment,
        P_ALLOCATION_PCT
    );
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'warehouse', UPPER(P_WAREHOUSE_NAME),
        'cost_center_code', UPPER(P_COST_CENTER_CODE),
        'environment', v_environment,
        'allocation_percentage', P_ALLOCATION_PCT
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM
        );
END;
$$;

-- #############################################################################
-- SECTION 5: COST DASHBOARDS
-- #############################################################################

/*******************************************************************************
 * RBAC_COST_DASHBOARD
 * 
 * Unified cost overview dashboard
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_COST_DASHBOARD(
    P_DAYS_BACK INTEGER DEFAULT 30
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_start_date DATE;
BEGIN
    v_start_date := DATEADD('DAY', -P_DAYS_BACK, CURRENT_DATE());
    
    -- Total credits consumed
    LET v_total_credits NUMBER := (
        SELECT COALESCE(SUM(CREDITS_USED), 0)
        FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
        WHERE START_TIME >= v_start_date
    );
    
    -- Credits by service type
    LET v_credits_by_service VARIANT := (
        SELECT OBJECT_CONSTRUCT(
            'compute', SUM(CASE WHEN SERVICE_TYPE = 'WAREHOUSE_METERING' THEN CREDITS_USED ELSE 0 END),
            'cloud_services', SUM(CASE WHEN SERVICE_TYPE = 'CLOUD_SERVICES' THEN CREDITS_USED ELSE 0 END),
            'serverless', SUM(CASE WHEN SERVICE_TYPE LIKE '%SERVERLESS%' THEN CREDITS_USED ELSE 0 END),
            'other', SUM(CASE WHEN SERVICE_TYPE NOT IN ('WAREHOUSE_METERING', 'CLOUD_SERVICES') 
                              AND SERVICE_TYPE NOT LIKE '%SERVERLESS%' THEN CREDITS_USED ELSE 0 END)
        )
        FROM SNOWFLAKE.ACCOUNT_USAGE.METERING_HISTORY
        WHERE START_TIME >= v_start_date
    );
    
    -- Top 10 warehouses by cost
    LET v_top_warehouses ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'warehouse_name', WAREHOUSE_NAME,
            'credits_used', ROUND(credits, 2),
            'percentage', ROUND((credits / NULLIF(total_credits, 0)) * 100, 2)
        ))
        FROM (
            SELECT 
                WAREHOUSE_NAME,
                SUM(CREDITS_USED) AS credits,
                SUM(SUM(CREDITS_USED)) OVER () AS total_credits
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME >= v_start_date
            GROUP BY WAREHOUSE_NAME
            ORDER BY credits DESC
            LIMIT 10
        )
    );
    
    -- Credits by environment
    LET v_credits_by_env ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'environment', env,
            'credits_used', ROUND(credits, 2)
        ))
        FROM (
            SELECT 
                CASE 
                    WHEN WAREHOUSE_NAME LIKE 'DEV%' THEN 'DEV'
                    WHEN WAREHOUSE_NAME LIKE 'TST%' THEN 'TST'
                    WHEN WAREHOUSE_NAME LIKE 'UAT%' THEN 'UAT'
                    WHEN WAREHOUSE_NAME LIKE 'PPE%' THEN 'PPE'
                    WHEN WAREHOUSE_NAME LIKE 'PRD%' THEN 'PRD'
                    ELSE 'OTHER'
                END AS env,
                SUM(CREDITS_USED) AS credits
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME >= v_start_date
            GROUP BY env
            ORDER BY credits DESC
        )
    );
    
    -- Storage costs
    LET v_storage VARIANT := (
        SELECT OBJECT_CONSTRUCT(
            'average_bytes', ROUND(AVG(STORAGE_BYTES), 0),
            'average_tb', ROUND(AVG(STORAGE_BYTES) / POWER(1024, 4), 3),
            'stage_bytes', ROUND(AVG(STAGE_BYTES), 0),
            'failsafe_bytes', ROUND(AVG(FAILSAFE_BYTES), 0)
        )
        FROM SNOWFLAKE.ACCOUNT_USAGE.STORAGE_USAGE
        WHERE USAGE_DATE >= v_start_date
    );
    
    -- Resource monitor status
    LET v_resource_monitors ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'name', NAME,
            'credit_quota', CREDIT_QUOTA,
            'used_credits', USED_CREDITS,
            'used_percentage', ROUND((USED_CREDITS / NULLIF(CREDIT_QUOTA, 0)) * 100, 2),
            'status', CASE 
                WHEN (USED_CREDITS / NULLIF(CREDIT_QUOTA, 0)) >= 1 THEN 'EXCEEDED'
                WHEN (USED_CREDITS / NULLIF(CREDIT_QUOTA, 0)) >= 0.9 THEN 'CRITICAL'
                WHEN (USED_CREDITS / NULLIF(CREDIT_QUOTA, 0)) >= 0.75 THEN 'WARNING'
                ELSE 'OK'
            END
        ))
        FROM TABLE(INFORMATION_SCHEMA.RESOURCE_MONITORS())
    );
    
    -- Daily trend
    LET v_daily_trend ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'date', TO_CHAR(START_TIME::DATE, 'YYYY-MM-DD'),
            'credits', ROUND(SUM(CREDITS_USED), 2)
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
        WHERE START_TIME >= v_start_date
        GROUP BY START_TIME::DATE
        ORDER BY START_TIME::DATE
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'COST_OVERVIEW',
        'period_days', P_DAYS_BACK,
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_credits', ROUND(v_total_credits, 2),
            'avg_daily_credits', ROUND(v_total_credits / P_DAYS_BACK, 2),
            'projected_monthly', ROUND((v_total_credits / P_DAYS_BACK) * 30, 2)
        ),
        'credits_by_service', v_credits_by_service,
        'top_warehouses', v_top_warehouses,
        'credits_by_environment', v_credits_by_env,
        'storage', v_storage,
        'resource_monitors', v_resource_monitors,
        'daily_trend', v_daily_trend
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM
        );
END;
$$;

/*******************************************************************************
 * RBAC_WAREHOUSE_COST_DASHBOARD
 * 
 * Detailed warehouse-level cost analysis
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_WAREHOUSE_COST_DASHBOARD(
    P_WAREHOUSE_NAME VARCHAR DEFAULT NULL,
    P_DAYS_BACK INTEGER DEFAULT 30
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_start_date DATE;
BEGIN
    v_start_date := DATEADD('DAY', -P_DAYS_BACK, CURRENT_DATE());
    
    -- Warehouse summary
    LET v_warehouse_summary ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'warehouse_name', WAREHOUSE_NAME,
            'warehouse_size', WAREHOUSE_SIZE,
            'credits_used', ROUND(SUM(CREDITS_USED), 2),
            'hours_running', ROUND(SUM(CREDITS_USED) / 
                CASE WAREHOUSE_SIZE 
                    WHEN 'X-Small' THEN 1 WHEN 'Small' THEN 2 
                    WHEN 'Medium' THEN 4 WHEN 'Large' THEN 8
                    WHEN 'X-Large' THEN 16 WHEN '2X-Large' THEN 32
                    WHEN '3X-Large' THEN 64 WHEN '4X-Large' THEN 128
                    ELSE 1 
                END, 2),
            'avg_daily_credits', ROUND(AVG(daily_credits), 2),
            'max_daily_credits', ROUND(MAX(daily_credits), 2),
            'days_active', COUNT(DISTINCT START_TIME::DATE)
        ))
        FROM (
            SELECT 
                WAREHOUSE_NAME,
                WAREHOUSE_SIZE,
                START_TIME::DATE AS day,
                SUM(CREDITS_USED) AS daily_credits,
                SUM(CREDITS_USED) AS CREDITS_USED
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME >= v_start_date
              AND (P_WAREHOUSE_NAME IS NULL OR WAREHOUSE_NAME = P_WAREHOUSE_NAME)
            GROUP BY WAREHOUSE_NAME, WAREHOUSE_SIZE, START_TIME::DATE
        )
        GROUP BY WAREHOUSE_NAME, WAREHOUSE_SIZE
        ORDER BY SUM(CREDITS_USED) DESC
    );
    
    -- Hourly pattern (for specific warehouse or top warehouse)
    LET v_hourly_pattern ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'hour', hour_of_day,
            'avg_credits', ROUND(AVG(hourly_credits), 4)
        ))
        FROM (
            SELECT 
                HOUR(START_TIME) AS hour_of_day,
                SUM(CREDITS_USED) AS hourly_credits
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME >= v_start_date
              AND (P_WAREHOUSE_NAME IS NULL OR WAREHOUSE_NAME = P_WAREHOUSE_NAME)
            GROUP BY START_TIME::DATE, HOUR(START_TIME)
        )
        GROUP BY hour_of_day
        ORDER BY hour_of_day
    );
    
    -- Weekly pattern
    LET v_weekly_pattern ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'day_of_week', DAYNAME(START_TIME::DATE),
            'day_number', DAYOFWEEK(START_TIME::DATE),
            'avg_credits', ROUND(AVG(daily_credits), 2)
        ))
        FROM (
            SELECT 
                START_TIME::DATE AS day,
                SUM(CREDITS_USED) AS daily_credits
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME >= v_start_date
              AND (P_WAREHOUSE_NAME IS NULL OR WAREHOUSE_NAME = P_WAREHOUSE_NAME)
            GROUP BY START_TIME::DATE
        )
        GROUP BY DAYOFWEEK(day), DAYNAME(day)
        ORDER BY DAYOFWEEK(day)
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'WAREHOUSE_COSTS',
        'warehouse_filter', P_WAREHOUSE_NAME,
        'period_days', P_DAYS_BACK,
        'generated_at', CURRENT_TIMESTAMP(),
        'warehouse_summary', v_warehouse_summary,
        'hourly_usage_pattern', v_hourly_pattern,
        'weekly_usage_pattern', v_weekly_pattern
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM
        );
END;
$$;

/*******************************************************************************
 * RBAC_COST_ANOMALY_DASHBOARD
 * 
 * Identifies unusual spending patterns
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_COST_ANOMALY_DASHBOARD(
    P_DAYS_BACK INTEGER DEFAULT 30,
    P_ANOMALY_THRESHOLD_PCT NUMBER DEFAULT 50
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_start_date DATE;
BEGIN
    v_start_date := DATEADD('DAY', -P_DAYS_BACK, CURRENT_DATE());
    
    -- Warehouses with usage spikes
    LET v_spikes ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'warehouse_name', WAREHOUSE_NAME,
            'date', TO_CHAR(spike_date, 'YYYY-MM-DD'),
            'credits_that_day', ROUND(daily_credits, 2),
            'avg_credits', ROUND(avg_credits, 2),
            'spike_percentage', ROUND(spike_pct, 1),
            'severity', CASE 
                WHEN spike_pct >= 200 THEN 'CRITICAL'
                WHEN spike_pct >= 100 THEN 'HIGH'
                WHEN spike_pct >= 50 THEN 'MEDIUM'
                ELSE 'LOW'
            END
        ))
        FROM (
            SELECT 
                WAREHOUSE_NAME,
                START_TIME::DATE AS spike_date,
                SUM(CREDITS_USED) AS daily_credits,
                AVG(SUM(CREDITS_USED)) OVER (
                    PARTITION BY WAREHOUSE_NAME 
                    ORDER BY START_TIME::DATE 
                    ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING
                ) AS avg_credits,
                ((SUM(CREDITS_USED) / NULLIF(AVG(SUM(CREDITS_USED)) OVER (
                    PARTITION BY WAREHOUSE_NAME 
                    ORDER BY START_TIME::DATE 
                    ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING
                ), 0)) - 1) * 100 AS spike_pct
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME >= v_start_date
            GROUP BY WAREHOUSE_NAME, START_TIME::DATE
        )
        WHERE spike_pct >= P_ANOMALY_THRESHOLD_PCT
        ORDER BY spike_pct DESC
        LIMIT 20
    );
    
    -- Unusual query patterns
    LET v_unusual_queries ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'warehouse_name', WAREHOUSE_NAME,
            'date', TO_CHAR(QUERY_DATE, 'YYYY-MM-DD'),
            'query_count', query_count,
            'avg_execution_time', ROUND(avg_exec_time, 2),
            'total_credits', ROUND(total_credits, 2)
        ))
        FROM (
            SELECT 
                WAREHOUSE_NAME,
                START_TIME::DATE AS QUERY_DATE,
                COUNT(*) AS query_count,
                AVG(TOTAL_ELAPSED_TIME) / 1000 AS avg_exec_time,
                SUM(CREDITS_USED_CLOUD_SERVICES) AS total_credits
            FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
            WHERE START_TIME >= v_start_date
              AND WAREHOUSE_NAME IS NOT NULL
            GROUP BY WAREHOUSE_NAME, START_TIME::DATE
            HAVING COUNT(*) > 1000 OR AVG(TOTAL_ELAPSED_TIME) > 60000
        )
        ORDER BY total_credits DESC
        LIMIT 10
    );
    
    -- New warehouses with high usage
    LET v_new_high_usage ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'warehouse_name', wh.NAME,
            'created_on', TO_CHAR(wh.CREATED_ON, 'YYYY-MM-DD'),
            'days_old', DATEDIFF('DAY', wh.CREATED_ON, CURRENT_DATE()),
            'credits_used', ROUND(m.credits_used, 2)
        ))
        FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSES wh
        LEFT JOIN (
            SELECT WAREHOUSE_NAME, SUM(CREDITS_USED) AS credits_used
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME >= v_start_date
            GROUP BY WAREHOUSE_NAME
        ) m ON wh.NAME = m.WAREHOUSE_NAME
        WHERE wh.CREATED_ON >= DATEADD('DAY', -14, CURRENT_DATE())
          AND wh.DELETED IS NULL
          AND m.credits_used > 10
        ORDER BY m.credits_used DESC
    );
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'COST_ANOMALIES',
        'period_days', P_DAYS_BACK,
        'anomaly_threshold_pct', P_ANOMALY_THRESHOLD_PCT,
        'generated_at', CURRENT_TIMESTAMP(),
        'usage_spikes', v_spikes,
        'unusual_query_patterns', v_unusual_queries,
        'new_warehouses_high_usage', v_new_high_usage,
        'alerts_count', ARRAY_SIZE(COALESCE(v_spikes, ARRAY_CONSTRUCT())) + 
                        ARRAY_SIZE(COALESCE(v_unusual_queries, ARRAY_CONSTRUCT())) +
                        ARRAY_SIZE(COALESCE(v_new_high_usage, ARRAY_CONSTRUCT()))
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM
        );
END;
$$;

/*******************************************************************************
 * RBAC_CHARGEBACK_REPORT
 * 
 * Generates cost allocation report by cost center
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CHARGEBACK_REPORT(
    P_MONTH DATE DEFAULT NULL,
    P_COST_CENTER_CODE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_month DATE;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    -- Default to current month
    v_month := COALESCE(P_MONTH, DATE_TRUNC('MONTH', CURRENT_DATE()));
    v_start_date := v_month;
    v_end_date := DATEADD('MONTH', 1, v_month);
    
    -- Cost by cost center
    LET v_cost_by_center ARRAY := (
        SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
            'cost_center_code', cc.COST_CENTER_CODE,
            'cost_center_name', cc.COST_CENTER_NAME,
            'department', cc.DEPARTMENT,
            'warehouses', wh_list,
            'credits_used', ROUND(credits, 2),
            'monthly_budget', cc.MONTHLY_BUDGET_CREDITS,
            'budget_used_pct', ROUND((credits / NULLIF(cc.MONTHLY_BUDGET_CREDITS, 0)) * 100, 2),
            'status', CASE 
                WHEN (credits / NULLIF(cc.MONTHLY_BUDGET_CREDITS, 0)) >= 1 THEN 'OVER_BUDGET'
                WHEN (credits / NULLIF(cc.MONTHLY_BUDGET_CREDITS, 0)) >= cc.CRITICAL_THRESHOLD_PCT / 100 THEN 'CRITICAL'
                WHEN (credits / NULLIF(cc.MONTHLY_BUDGET_CREDITS, 0)) >= cc.ALERT_THRESHOLD_PCT / 100 THEN 'WARNING'
                ELSE 'OK'
            END
        ))
        FROM RBAC_COST_CENTERS cc
        LEFT JOIN (
            SELECT 
                m.COST_CENTER_ID,
                ARRAY_AGG(DISTINCT m.WAREHOUSE_NAME) AS wh_list,
                SUM(h.CREDITS_USED * (m.ALLOCATION_PERCENTAGE / 100)) AS credits
            FROM RBAC_WAREHOUSE_COST_MAPPING m
            JOIN SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY h
                ON m.WAREHOUSE_NAME = h.WAREHOUSE_NAME
            WHERE h.START_TIME >= v_start_date
              AND h.START_TIME < v_end_date
              AND (m.END_DATE IS NULL OR m.END_DATE > v_start_date)
            GROUP BY m.COST_CENTER_ID
        ) usage ON cc.COST_CENTER_ID = usage.COST_CENTER_ID
        WHERE cc.IS_ACTIVE = TRUE
          AND (P_COST_CENTER_CODE IS NULL OR cc.COST_CENTER_CODE = UPPER(P_COST_CENTER_CODE))
        ORDER BY credits DESC NULLS LAST
    );
    
    -- Unallocated costs (warehouses not mapped to cost centers)
    LET v_unallocated VARIANT := (
        SELECT OBJECT_CONSTRUCT(
            'warehouses', ARRAY_AGG(DISTINCT WAREHOUSE_NAME),
            'credits_used', ROUND(SUM(CREDITS_USED), 2)
        )
        FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY h
        WHERE h.START_TIME >= v_start_date
          AND h.START_TIME < v_end_date
          AND NOT EXISTS (
              SELECT 1 FROM RBAC_WAREHOUSE_COST_MAPPING m
              WHERE m.WAREHOUSE_NAME = h.WAREHOUSE_NAME
                AND (m.END_DATE IS NULL OR m.END_DATE > v_start_date)
          )
    );
    
    -- Summary
    LET v_total_credits NUMBER := (
        SELECT SUM(CREDITS_USED)
        FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
        WHERE START_TIME >= v_start_date
          AND START_TIME < v_end_date
    );
    
    RETURN OBJECT_CONSTRUCT(
        'report', 'CHARGEBACK',
        'month', TO_CHAR(v_month, 'YYYY-MM'),
        'period_start', v_start_date,
        'period_end', v_end_date,
        'generated_at', CURRENT_TIMESTAMP(),
        'summary', OBJECT_CONSTRUCT(
            'total_credits', ROUND(v_total_credits, 2),
            'cost_centers_count', ARRAY_SIZE(COALESCE(v_cost_by_center, ARRAY_CONSTRUCT()))
        ),
        'cost_by_center', v_cost_by_center,
        'unallocated_costs', v_unallocated
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM
        );
END;
$$;

/*******************************************************************************
 * RBAC_COST_MONITORING_DASHBOARD
 * 
 * Unified cost monitoring dashboard (combines all views)
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_COST_MONITORING_DASHBOARD()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
BEGIN
    -- Get individual dashboards
    CALL ADMIN.RBAC.RBAC_COST_DASHBOARD(30) INTO v_cost_overview;
    CALL ADMIN.RBAC.RBAC_WAREHOUSE_COST_DASHBOARD(NULL, 30) INTO v_warehouse_costs;
    CALL ADMIN.RBAC.RBAC_COST_ANOMALY_DASHBOARD(30, 50) INTO v_anomalies;
    CALL ADMIN.RBAC.RBAC_CHARGEBACK_REPORT(NULL, NULL) INTO v_chargeback;
    
    RETURN OBJECT_CONSTRUCT(
        'dashboard', 'UNIFIED_COST_MONITORING',
        'generated_at', CURRENT_TIMESTAMP(),
        'overview', v_cost_overview,
        'warehouse_analysis', v_warehouse_costs,
        'anomaly_detection', v_anomalies,
        'chargeback_current_month', v_chargeback
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM
        );
END;
$$;

-- #############################################################################
-- SECTION 6: ENHANCED WAREHOUSE CREATION WITH COST CONTROLS
-- #############################################################################

/*******************************************************************************
 * RBAC_CREATE_WAREHOUSE_WITH_MONITOR
 * 
 * Enhanced warehouse creation that includes resource monitor setup
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE_WITH_MONITOR(
    P_ENVIRONMENT VARCHAR,
    P_WAREHOUSE_SIZE VARCHAR DEFAULT 'XSMALL',
    P_AUTO_SUSPEND INTEGER DEFAULT 60,
    P_WAREHOUSE_SUFFIX VARCHAR DEFAULT NULL,
    P_CREDIT_QUOTA NUMBER DEFAULT NULL,
    P_COST_CENTER_CODE VARCHAR DEFAULT NULL,
    P_CREATE_RESOURCE_MONITOR BOOLEAN DEFAULT TRUE,
    P_NOTIFY_TRIGGERS ARRAY DEFAULT NULL,
    P_SUSPEND_TRIGGERS ARRAY DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_warehouse_name VARCHAR;
    v_monitor_name VARCHAR;
    v_create_result VARIANT;
    v_monitor_result VARIANT;
    v_assign_result VARIANT;
    v_tag_result VARIANT;
    v_default_quota NUMBER;
BEGIN
    -- Build warehouse name
    IF (P_WAREHOUSE_SUFFIX IS NOT NULL AND P_WAREHOUSE_SUFFIX != '') THEN
        v_warehouse_name := P_ENVIRONMENT || '_' || P_WAREHOUSE_SUFFIX || '_WH';
    ELSE
        v_warehouse_name := P_ENVIRONMENT || '_WH';
    END IF;
    
    -- Set default quota based on environment if not specified
    IF (P_CREDIT_QUOTA IS NULL) THEN
        v_default_quota := CASE P_ENVIRONMENT
            WHEN 'DEV' THEN 100
            WHEN 'TST' THEN 50
            WHEN 'UAT' THEN 50
            WHEN 'PPE' THEN 100
            WHEN 'PRD' THEN 500
            ELSE 100
        END;
    ELSE
        v_default_quota := P_CREDIT_QUOTA;
    END IF;
    
    -- Create the warehouse
    CALL ADMIN.RBAC.RBAC_CREATE_WAREHOUSE(
        P_ENVIRONMENT,
        P_WAREHOUSE_SIZE,
        P_AUTO_SUSPEND,
        P_WAREHOUSE_SUFFIX
    ) INTO v_create_result;
    
    IF (v_create_result:status != 'SUCCESS') THEN
        RETURN v_create_result;
    END IF;
    
    -- Create resource monitor if requested
    IF (P_CREATE_RESOURCE_MONITOR) THEN
        v_monitor_name := v_warehouse_name || '_MONITOR';
        
        CALL ADMIN.RBAC.RBAC_CREATE_RESOURCE_MONITOR(
            v_monitor_name,
            v_default_quota,
            'MONTHLY',
            NULL,
            NULL,
            NULL,
            COALESCE(P_NOTIFY_TRIGGERS, ARRAY_CONSTRUCT(75, 90)),
            COALESCE(P_SUSPEND_TRIGGERS, ARRAY_CONSTRUCT(100)),
            NULL
        ) INTO v_monitor_result;
        
        IF (v_monitor_result:status = 'SUCCESS') THEN
            -- Assign monitor to warehouse
            CALL ADMIN.RBAC.RBAC_ASSIGN_RESOURCE_MONITOR(
                v_monitor_name,
                ARRAY_CONSTRUCT(v_warehouse_name),
                FALSE
            ) INTO v_assign_result;
        END IF;
    END IF;
    
    -- Tag to cost center if specified
    IF (P_COST_CENTER_CODE IS NOT NULL) THEN
        CALL ADMIN.RBAC.RBAC_TAG_WAREHOUSE_COST_CENTER(
            v_warehouse_name,
            P_COST_CENTER_CODE,
            100
        ) INTO v_tag_result;
    END IF;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'warehouse', OBJECT_CONSTRUCT(
            'name', v_warehouse_name,
            'size', P_WAREHOUSE_SIZE,
            'environment', P_ENVIRONMENT,
            'auto_suspend', P_AUTO_SUSPEND
        ),
        'resource_monitor', CASE WHEN P_CREATE_RESOURCE_MONITOR THEN OBJECT_CONSTRUCT(
            'name', v_monitor_name,
            'credit_quota', v_default_quota,
            'status', v_monitor_result:status
        ) ELSE NULL END,
        'cost_center', CASE WHEN P_COST_CENTER_CODE IS NOT NULL THEN OBJECT_CONSTRUCT(
            'code', P_COST_CENTER_CODE,
            'status', v_tag_result:status
        ) ELSE NULL END
    );
    
EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'ERROR',
            'message', SQLERRM,
            'warehouse_name', v_warehouse_name
        );
END;
$$;

-- #############################################################################
-- SECTION 7: GRANTS
-- #############################################################################

-- Grant execute permissions
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_RESOURCE_MONITOR(VARCHAR, NUMBER, VARCHAR, TIMESTAMP_NTZ, TIMESTAMP_NTZ, ARRAY, ARRAY, ARRAY, ARRAY) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_ASSIGN_RESOURCE_MONITOR(VARCHAR, ARRAY, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_LIST_RESOURCE_MONITORS() TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_LIST_RESOURCE_MONITORS() TO ROLE SRF_DEV_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_LIST_RESOURCE_MONITORS() TO ROLE SRF_PRD_DBADMIN;

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_BUDGET(VARCHAR, NUMBER, DATE, DATE, ARRAY, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_LIST_BUDGETS() TO ROLE SRS_SECURITY_ADMIN;

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_COST_CENTER(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, NUMBER, NUMBER, NUMBER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_TAG_WAREHOUSE_COST_CENTER(VARCHAR, VARCHAR, NUMBER) TO ROLE SRS_SECURITY_ADMIN;

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_COST_DASHBOARD(INTEGER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_COST_DASHBOARD(INTEGER) TO ROLE SRF_DEV_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_COST_DASHBOARD(INTEGER) TO ROLE SRF_PRD_DBADMIN;

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_WAREHOUSE_COST_DASHBOARD(VARCHAR, INTEGER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_WAREHOUSE_COST_DASHBOARD(VARCHAR, INTEGER) TO ROLE SRF_DEV_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_WAREHOUSE_COST_DASHBOARD(VARCHAR, INTEGER) TO ROLE SRF_PRD_DBADMIN;

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_COST_ANOMALY_DASHBOARD(INTEGER, NUMBER) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CHARGEBACK_REPORT(DATE, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_COST_MONITORING_DASHBOARD() TO ROLE SRS_SECURITY_ADMIN;

GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE_WITH_MONITOR(VARCHAR, VARCHAR, INTEGER, VARCHAR, NUMBER, VARCHAR, BOOLEAN, ARRAY, ARRAY) TO ROLE SRF_DEV_DBADMIN;
GRANT USAGE ON PROCEDURE ADMIN.RBAC.RBAC_CREATE_WAREHOUSE_WITH_MONITOR(VARCHAR, VARCHAR, INTEGER, VARCHAR, NUMBER, VARCHAR, BOOLEAN, ARRAY, ARRAY) TO ROLE SRF_PRD_DBADMIN;
