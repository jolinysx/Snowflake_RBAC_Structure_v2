/*******************************************************************************
 * RBAC STORED PROCEDURE: Third-Party Integration (ServiceNow, Jira, etc.)
 * 
 * Purpose: Integrates RBAC workflow with external ticketing and approval systems
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * DEPLOYMENT INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 *   Database:        ADMIN
 *   Schema:          RBAC
 *   Object Type:     TABLES (3), PROCEDURES (~12)
 * 
 *   Deployment Role: SRS_SYSTEM_ADMIN (owns the objects)
 *   Execution Role:  SRS_SECURITY_ADMIN (caller must have this role)
 * 
 *   Dependencies:    
 *     - ADMIN database and RBAC schema must exist
 *     - External Functions for ticketing system integration
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * INTEGRATION POINTS IN RBAC WORKFLOW:
 * 
 *   ┌─────────────────────────────────────────────────────────────────────────┐
 *   │                         RBAC WORKFLOW WITH INTEGRATION                  │
 *   ├─────────────────────────────────────────────────────────────────────────┤
 *   │                                                                         │
 *   │  1. USER REQUESTS ACCESS                                               │
 *   │     └── RBAC_REQUEST_ACCESS_TICKET() ──► ServiceNow/Jira Ticket        │
 *   │                                                                         │
 *   │  2. APPROVAL WORKFLOW (in external system)                             │
 *   │     └── Manager approves in ServiceNow/Jira                            │
 *   │                                                                         │
 *   │  3. CHECK APPROVAL & GRANT ACCESS                                      │
 *   │     └── RBAC_CHECK_AND_GRANT_APPROVED() ◄── Checks ticket status       │
 *   │         └── If approved: RBAC_CONFIGURE_USER()                         │
 *   │         └── RBAC_LOG_AUDIT_EVENT() ──► Audit log                       │
 *   │                                                                         │
 *   │  4. PERIODIC ACCESS REVIEW                                             │
 *   │     └── RBAC_CREATE_ACCESS_REVIEW_TICKETS() ──► Review tickets         │
 *   │                                                                         │
 *   │  5. ACCESS REVOCATION                                                  │
 *   │     └── RBAC_REVOKE_AND_LOG() ──► Audit log + Close ticket             │
 *   │                                                                         │
 *   └─────────────────────────────────────────────────────────────────────────┘
 * 
 * SUPPORTED PLATFORMS:
 *   - ServiceNow (ITSM, SecOps)
 *   - Jira (Service Management, Software)
 *   - Generic REST API (any system with REST interface)
 *   - Microsoft Teams / Slack (notifications)
 * 
 * PREREQUISITES:
 *   1. External Network Access configured (NETWORK RULE, EXTERNAL ACCESS INTEGRATION)
 *   2. API credentials stored as Snowflake SECRETS
 *   3. Appropriate Snowflake edition (Enterprise+ for External Access)
 ******************************************************************************/

-- #############################################################################
-- SECTION 1: INFRASTRUCTURE SETUP
-- #############################################################################

-- =============================================================================
-- DEPLOYMENT CONTEXT
-- =============================================================================
USE ROLE ACCOUNTADMIN;
USE DATABASE ADMIN;
USE SCHEMA RBAC;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup External Access for ServiceNow
 * 
 * Purpose: Creates network rules and external access integration for ServiceNow
 * 
 * Parameters:
 *   P_INSTANCE_NAME   - ServiceNow instance (e.g., 'mycompany' for mycompany.service-now.com)
 *   P_SECRET_NAME     - Name for the secret to store credentials
 *   P_USERNAME        - ServiceNow API username
 *   P_PASSWORD        - ServiceNow API password
 *   P_INTEGRATION_NAME- Name for the external access integration
 * 
 * Execution Role: ACCOUNTADMIN
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_SETUP_SERVICENOW_ACCESS(
    P_INSTANCE_NAME VARCHAR,
    P_SECRET_NAME VARCHAR,
    P_USERNAME VARCHAR,
    P_PASSWORD VARCHAR,
    P_INTEGRATION_NAME VARCHAR DEFAULT 'SERVICENOW_INTEGRATION'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_host VARCHAR;
    v_network_rule VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
BEGIN
    v_host := P_INSTANCE_NAME || '.service-now.com';
    v_network_rule := 'SERVICENOW_' || UPPER(P_INSTANCE_NAME) || '_RULE';
    
    -- Create network rule for ServiceNow
    v_sql := 'CREATE OR REPLACE NETWORK RULE ' || v_network_rule || '
        MODE = EGRESS
        TYPE = HOST_PORT
        VALUE_LIST = (''' || v_host || ''')';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_NETWORK_RULE', 'rule', v_network_rule));
    
    -- Create secret for credentials
    v_sql := 'CREATE OR REPLACE SECRET ' || P_SECRET_NAME || '
        TYPE = PASSWORD
        USERNAME = ''' || P_USERNAME || '''
        PASSWORD = ''' || P_PASSWORD || '''
        COMMENT = ''ServiceNow API credentials for ' || v_host || '''';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_SECRET', 'secret', P_SECRET_NAME));
    
    -- Create external access integration
    v_sql := 'CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION ' || P_INTEGRATION_NAME || '
        ALLOWED_NETWORK_RULES = (' || v_network_rule || ')
        ALLOWED_AUTHENTICATION_SECRETS = (' || P_SECRET_NAME || ')
        ENABLED = TRUE
        COMMENT = ''External access for ServiceNow RBAC integration''';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_INTEGRATION', 'integration', P_INTEGRATION_NAME));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'servicenow_instance', v_host,
        'network_rule', v_network_rule,
        'secret_name', P_SECRET_NAME,
        'integration_name', P_INTEGRATION_NAME,
        'actions', v_actions,
        'next_steps', ARRAY_CONSTRUCT(
            '1. Grant integration to roles that need it:',
            '   GRANT USAGE ON INTEGRATION ' || P_INTEGRATION_NAME || ' TO ROLE SRS_SECURITY_ADMIN;',
            '2. Grant secret usage:',
            '   GRANT READ ON SECRET ' || P_SECRET_NAME || ' TO ROLE SRS_SECURITY_ADMIN;',
            '3. Test with: CALL RBAC_TEST_SERVICENOW_CONNECTION(''' || P_INTEGRATION_NAME || ''', ''' || P_SECRET_NAME || ''');'
        )
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Setup External Access for Jira
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_SETUP_JIRA_ACCESS(
    P_JIRA_URL VARCHAR,           -- e.g., 'mycompany.atlassian.net' or 'jira.mycompany.com'
    P_SECRET_NAME VARCHAR,
    P_EMAIL VARCHAR,              -- Jira user email
    P_API_TOKEN VARCHAR,          -- Jira API token
    P_INTEGRATION_NAME VARCHAR DEFAULT 'JIRA_INTEGRATION'
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_sql VARCHAR;
    v_network_rule VARCHAR;
    v_actions ARRAY := ARRAY_CONSTRUCT();
BEGIN
    v_network_rule := 'JIRA_RULE';
    
    -- Create network rule for Jira
    v_sql := 'CREATE OR REPLACE NETWORK RULE ' || v_network_rule || '
        MODE = EGRESS
        TYPE = HOST_PORT
        VALUE_LIST = (''' || P_JIRA_URL || ''')';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_NETWORK_RULE'));
    
    -- Create secret for API token (Jira uses email:token as basic auth)
    v_sql := 'CREATE OR REPLACE SECRET ' || P_SECRET_NAME || '
        TYPE = PASSWORD
        USERNAME = ''' || P_EMAIL || '''
        PASSWORD = ''' || P_API_TOKEN || '''
        COMMENT = ''Jira API credentials''';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_SECRET'));
    
    -- Create external access integration
    v_sql := 'CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION ' || P_INTEGRATION_NAME || '
        ALLOWED_NETWORK_RULES = (' || v_network_rule || ')
        ALLOWED_AUTHENTICATION_SECRETS = (' || P_SECRET_NAME || ')
        ENABLED = TRUE
        COMMENT = ''External access for Jira RBAC integration''';
    EXECUTE IMMEDIATE v_sql;
    v_actions := ARRAY_APPEND(v_actions, OBJECT_CONSTRUCT('action', 'CREATE_INTEGRATION'));
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'jira_url', P_JIRA_URL,
        'network_rule', v_network_rule,
        'secret_name', P_SECRET_NAME,
        'integration_name', P_INTEGRATION_NAME,
        'actions', v_actions
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM, 'sqlcode', SQLCODE);
END;
$$;

-- #############################################################################
-- SECTION 2: SERVICENOW INTEGRATION PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Access Request Ticket in ServiceNow
 * 
 * Purpose: Creates a ServiceNow ticket for access request approval
 * 
 * PREREQUISITES:
 *   - Run RBAC_SETUP_SERVICENOW_ACCESS() first to create the integration and secret
 *   - Default secret name: SERVICENOW_CREDENTIALS
 *   - Default integration name: SERVICENOW_INTEGRATION
 * 
 * Parameters:
 *   P_REQUESTOR       - User requesting access
 *   P_ENVIRONMENT     - Target environment
 *   P_DOMAIN          - Target domain/department
 *   P_CAPABILITY      - Requested capability level
 *   P_JUSTIFICATION   - Business justification
 *   P_INTEGRATION_NAME- External access integration name
 *   P_SECRET_NAME     - Secret containing credentials
 ******************************************************************************/

-- ============================================================================
-- COMMENTED OUT: Uncomment after running RBAC_SETUP_SERVICENOW_ACCESS()
-- This procedure requires SERVICENOW_INTEGRATION and ADMIN.RBAC.SERVICENOW_CREDENTIALS
-- ============================================================================
/*
CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_SERVICENOW_CREATE_ACCESS_REQUEST(
    P_REQUESTOR VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN VARCHAR,
    P_CAPABILITY VARCHAR,
    P_JUSTIFICATION VARCHAR,
    P_INTEGRATION_NAME VARCHAR DEFAULT 'SERVICENOW_INTEGRATION',
    P_SECRET_NAME VARCHAR DEFAULT 'SERVICENOW_CREDENTIALS'
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'create_ticket'
EXTERNAL_ACCESS_INTEGRATIONS = (SERVICENOW_INTEGRATION)
SECRETS = ('cred' = ADMIN.RBAC.SERVICENOW_CREDENTIALS)
PACKAGES = ('requests', 'snowflake-snowpark-python')
AS
$$
import requests
import json
import _snowflake

def create_ticket(session, p_requestor, p_environment, p_domain, p_capability, 
                  p_justification, p_integration_name, p_secret_name):
    try:
        # Get credentials from secret
        username = _snowflake.get_username_password('cred').username
        password = _snowflake.get_username_password('cred').password
        
        # Build ticket description
        description = f"""
Snowflake RBAC Access Request

Requestor: {p_requestor}
Environment: {p_environment}
Domain: {p_domain}
Capability: {p_capability}

Business Justification:
{p_justification}

Requested Roles:
- SRF_{p_environment}_{p_capability}
- SRA_{p_environment}_{p_domain}_ACCESS

Upon Approval:
Run in Snowflake: CALL RBAC_CONFIGURE_USER('{p_requestor}', '{p_environment}', '{p_domain}', '{p_capability}', '{p_environment}_WH', NULL);
"""
        
        # ServiceNow REST API endpoint
        # Note: Update instance name in the URL
        url = "https://YOUR_INSTANCE.service-now.com/api/now/table/sc_request"
        
        payload = {
            "short_description": f"Snowflake Access Request: {p_requestor} - {p_environment} {p_domain} {p_capability}",
            "description": description,
            "requested_for": p_requestor,
            "urgency": "3",
            "impact": "3",
            "assignment_group": "Snowflake Security Admin",
            "category": "Access Management",
            "subcategory": "Snowflake RBAC"
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        response = requests.post(
            url,
            auth=(username, password),
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            result = response.json()
            ticket_number = result.get('result', {}).get('number', 'Unknown')
            ticket_sys_id = result.get('result', {}).get('sys_id', 'Unknown')
            
            return {
                "status": "SUCCESS",
                "ticket_number": ticket_number,
                "ticket_sys_id": ticket_sys_id,
                "requestor": p_requestor,
                "requested_access": {
                    "environment": p_environment,
                    "domain": p_domain,
                    "capability": p_capability
                },
                "message": f"Access request ticket {ticket_number} created successfully"
            }
        else:
            return {
                "status": "ERROR",
                "http_status": response.status_code,
                "message": response.text
            }
            
    except Exception as e:
        return {
            "status": "ERROR",
            "message": str(e)
        }
$$;
*/

/*******************************************************************************
 * RBAC STORED PROCEDURE: Check ServiceNow Ticket Status
 ******************************************************************************/

-- ============================================================================
-- COMMENTED OUT: Uncomment after running RBAC_SETUP_SERVICENOW_ACCESS()
-- ============================================================================
/*
CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_SERVICENOW_CHECK_TICKET_STATUS(
    P_TICKET_NUMBER VARCHAR,
    P_INTEGRATION_NAME VARCHAR DEFAULT 'SERVICENOW_INTEGRATION',
    P_SECRET_NAME VARCHAR DEFAULT 'SERVICENOW_CREDENTIALS'
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'check_status'
EXTERNAL_ACCESS_INTEGRATIONS = (SERVICENOW_INTEGRATION)
SECRETS = ('cred' = ADMIN.RBAC.SERVICENOW_CREDENTIALS)
PACKAGES = ('requests', 'snowflake-snowpark-python')
AS
$$
import requests
import _snowflake

def check_status(session, p_ticket_number, p_integration_name, p_secret_name):
    try:
        username = _snowflake.get_username_password('cred').username
        password = _snowflake.get_username_password('cred').password
        
        # Query ServiceNow for ticket status
        url = f"https://YOUR_INSTANCE.service-now.com/api/now/table/sc_request?sysparm_query=number={p_ticket_number}"
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        response = requests.get(
            url,
            auth=(username, password),
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('result'):
                ticket = result['result'][0]
                state = ticket.get('state', 'Unknown')
                approval = ticket.get('approval', 'Unknown')
                
                # Map ServiceNow states
                state_map = {
                    '1': 'Open',
                    '2': 'Work in Progress',
                    '3': 'Closed Complete',
                    '4': 'Closed Incomplete',
                    '7': 'Closed Skipped'
                }
                
                approval_map = {
                    'approved': 'APPROVED',
                    'rejected': 'REJECTED',
                    'requested': 'PENDING',
                    'not requested': 'NOT_REQUESTED'
                }
                
                return {
                    "status": "SUCCESS",
                    "ticket_number": p_ticket_number,
                    "ticket_state": state_map.get(state, state),
                    "approval_status": approval_map.get(approval.lower(), approval),
                    "is_approved": approval.lower() == 'approved',
                    "is_closed": state in ['3', '4', '7'],
                    "raw_state": state,
                    "raw_approval": approval
                }
            else:
                return {"status": "ERROR", "message": "Ticket not found"}
        else:
            return {"status": "ERROR", "http_status": response.status_code}
            
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Log Audit Event to ServiceNow
 ******************************************************************************/

-- ============================================================================
-- COMMENTED OUT: Uncomment after running RBAC_SETUP_SERVICENOW_ACCESS()
-- ============================================================================
/*
CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_SERVICENOW_LOG_AUDIT_EVENT(
    P_EVENT_TYPE VARCHAR,         -- 'GRANT', 'REVOKE', 'CREATE', 'MODIFY'
    P_USER_NAME VARCHAR,
    P_ROLE_NAME VARCHAR,
    P_PERFORMED_BY VARCHAR,
    P_TICKET_NUMBER VARCHAR DEFAULT NULL,
    P_DETAILS VARCHAR DEFAULT NULL,
    P_INTEGRATION_NAME VARCHAR DEFAULT 'SERVICENOW_INTEGRATION',
    P_SECRET_NAME VARCHAR DEFAULT 'SERVICENOW_CREDENTIALS'
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'log_event'
EXTERNAL_ACCESS_INTEGRATIONS = (SERVICENOW_INTEGRATION)
SECRETS = ('cred' = ADMIN.RBAC.SERVICENOW_CREDENTIALS)
PACKAGES = ('requests', 'snowflake-snowpark-python')
AS
$$
import requests
import json
from datetime import datetime
import _snowflake

def log_event(session, p_event_type, p_user_name, p_role_name, p_performed_by,
              p_ticket_number, p_details, p_integration_name, p_secret_name):
    try:
        username = _snowflake.get_username_password('cred').username
        password = _snowflake.get_username_password('cred').password
        
        # Create audit log entry in ServiceNow
        url = "https://YOUR_INSTANCE.service-now.com/api/now/table/syslog"
        
        message = f"""
Snowflake RBAC Audit Event
Event Type: {p_event_type}
User: {p_user_name}
Role: {p_role_name}
Performed By: {p_performed_by}
Ticket: {p_ticket_number or 'N/A'}
Timestamp: {datetime.utcnow().isoformat()}
Details: {p_details or 'N/A'}
"""
        
        payload = {
            "message": message,
            "source": "Snowflake RBAC",
            "level": "0"  # Info level
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        response = requests.post(
            url,
            auth=(username, password),
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            return {
                "status": "SUCCESS",
                "event_type": p_event_type,
                "user": p_user_name,
                "role": p_role_name,
                "logged_at": datetime.utcnow().isoformat()
            }
        else:
            return {"status": "ERROR", "http_status": response.status_code}
            
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}
$$;
*/

-- #############################################################################
-- SECTION 3: JIRA INTEGRATION PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Access Request Issue in Jira
 ******************************************************************************/

-- ============================================================================
-- COMMENTED OUT: Uncomment after running RBAC_SETUP_JIRA_ACCESS()
-- ============================================================================
/*
CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_JIRA_CREATE_ACCESS_REQUEST(
    P_REQUESTOR VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN VARCHAR,
    P_CAPABILITY VARCHAR,
    P_JUSTIFICATION VARCHAR,
    P_PROJECT_KEY VARCHAR,        -- Jira project key (e.g., 'SNOWFLAKE')
    P_INTEGRATION_NAME VARCHAR DEFAULT 'JIRA_INTEGRATION',
    P_SECRET_NAME VARCHAR DEFAULT 'JIRA_CREDENTIALS'
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'create_issue'
EXTERNAL_ACCESS_INTEGRATIONS = (JIRA_INTEGRATION)
SECRETS = ('cred' = ADMIN.RBAC.JIRA_CREDENTIALS)
PACKAGES = ('requests', 'snowflake-snowpark-python')
AS
$$
import requests
import json
import base64
import _snowflake

def create_issue(session, p_requestor, p_environment, p_domain, p_capability,
                 p_justification, p_project_key, p_integration_name, p_secret_name):
    try:
        email = _snowflake.get_username_password('cred').username
        api_token = _snowflake.get_username_password('cred').password
        
        # Jira uses Basic Auth with email:token
        auth_string = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        
        description = f"""
h2. Snowflake RBAC Access Request

||Field||Value||
|Requestor|{p_requestor}|
|Environment|{p_environment}|
|Domain|{p_domain}|
|Capability|{p_capability}|

h3. Business Justification
{p_justification}

h3. Requested Roles
* SRF_{p_environment}_{p_capability}
* SRA_{p_environment}_{p_domain}_ACCESS

h3. Upon Approval
{{code:sql}}
CALL RBAC_CONFIGURE_USER('{p_requestor}', '{p_environment}', '{p_domain}', '{p_capability}', '{p_environment}_WH', NULL);
{{code}}
"""
        
        url = "https://YOUR_INSTANCE.atlassian.net/rest/api/3/issue"
        
        payload = {
            "fields": {
                "project": {"key": p_project_key},
                "summary": f"Snowflake Access: {p_requestor} - {p_environment} {p_domain} {p_capability}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}]
                        }
                    ]
                },
                "issuetype": {"name": "Task"},
                "labels": ["snowflake-rbac", "access-request", p_environment.lower()]
            }
        }
        
        headers = {
            "Authorization": f"Basic {auth_string}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code in [200, 201]:
            result = response.json()
            return {
                "status": "SUCCESS",
                "issue_key": result.get('key'),
                "issue_id": result.get('id'),
                "issue_url": f"https://YOUR_INSTANCE.atlassian.net/browse/{result.get('key')}",
                "requestor": p_requestor,
                "requested_access": {
                    "environment": p_environment,
                    "domain": p_domain,
                    "capability": p_capability
                }
            }
        else:
            return {"status": "ERROR", "http_status": response.status_code, "message": response.text}
            
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}
$$;
*/

/*******************************************************************************
 * RBAC STORED PROCEDURE: Check Jira Issue Status
 ******************************************************************************/

-- ============================================================================
-- COMMENTED OUT: Uncomment after running RBAC_SETUP_JIRA_ACCESS()
-- ============================================================================
/*
CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_JIRA_CHECK_ISSUE_STATUS(
    P_ISSUE_KEY VARCHAR,
    P_INTEGRATION_NAME VARCHAR DEFAULT 'JIRA_INTEGRATION',
    P_SECRET_NAME VARCHAR DEFAULT 'JIRA_CREDENTIALS'
)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'check_status'
EXTERNAL_ACCESS_INTEGRATIONS = (JIRA_INTEGRATION)
SECRETS = ('cred' = ADMIN.RBAC.JIRA_CREDENTIALS)
PACKAGES = ('requests', 'snowflake-snowpark-python')
AS
$$
import requests
import base64
import _snowflake

def check_status(session, p_issue_key, p_integration_name, p_secret_name):
    try:
        email = _snowflake.get_username_password('cred').username
        api_token = _snowflake.get_username_password('cred').password
        auth_string = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        
        url = f"https://YOUR_INSTANCE.atlassian.net/rest/api/3/issue/{p_issue_key}"
        
        headers = {
            "Authorization": f"Basic {auth_string}",
            "Accept": "application/json"
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            status = result.get('fields', {}).get('status', {}).get('name', 'Unknown')
            resolution = result.get('fields', {}).get('resolution')
            
            # Map common Jira statuses to approval states
            approved_statuses = ['Done', 'Approved', 'Closed', 'Resolved']
            rejected_statuses = ['Rejected', 'Declined', 'Cancelled']
            pending_statuses = ['To Do', 'Open', 'In Progress', 'In Review', 'Awaiting Approval']
            
            if status in approved_statuses:
                approval_status = 'APPROVED'
            elif status in rejected_statuses:
                approval_status = 'REJECTED'
            else:
                approval_status = 'PENDING'
            
            return {
                "status": "SUCCESS",
                "issue_key": p_issue_key,
                "jira_status": status,
                "approval_status": approval_status,
                "is_approved": approval_status == 'APPROVED',
                "is_closed": resolution is not None,
                "resolution": resolution.get('name') if resolution else None
            }
        else:
            return {"status": "ERROR", "http_status": response.status_code}
            
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}
$$;
*/

-- #############################################################################
-- SECTION 4: UNIFIED WORKFLOW PROCEDURES
-- #############################################################################

/*******************************************************************************
 * RBAC STORED PROCEDURE: Request Access (Creates Ticket)
 * 
 * Purpose: Unified procedure to request access - creates ticket in configured system
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_REQUEST_ACCESS(
    P_REQUESTOR VARCHAR,
    P_ENVIRONMENT VARCHAR,
    P_DOMAIN VARCHAR,
    P_CAPABILITY VARCHAR,
    P_JUSTIFICATION VARCHAR,
    P_TICKET_SYSTEM VARCHAR DEFAULT 'SERVICENOW',  -- 'SERVICENOW' or 'JIRA'
    P_PROJECT_KEY VARCHAR DEFAULT NULL             -- Required for Jira
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_result VARIANT;
BEGIN
    -- Validate inputs
    IF (P_ENVIRONMENT NOT IN ('DEV', 'TST', 'UAT', 'PPE', 'PRD')) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid environment');
    END IF;
    
    IF (P_CAPABILITY NOT IN ('END_USER', 'ANALYST', 'DEVELOPER', 'TEAM_LEADER', 'DATA_SCIENTIST', 'DBADMIN')) THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid capability level');
    END IF;
    
    -- Create ticket in appropriate system
    IF (UPPER(P_TICKET_SYSTEM) = 'SERVICENOW') THEN
        CALL RBAC_SERVICENOW_CREATE_ACCESS_REQUEST(
            P_REQUESTOR, P_ENVIRONMENT, P_DOMAIN, P_CAPABILITY, P_JUSTIFICATION,
            'SERVICENOW_INTEGRATION', 'SERVICENOW_CREDENTIALS'
        ) INTO v_result;
    ELSEIF (UPPER(P_TICKET_SYSTEM) = 'JIRA') THEN
        IF (P_PROJECT_KEY IS NULL) THEN
            RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Project key required for Jira');
        END IF;
        CALL RBAC_JIRA_CREATE_ACCESS_REQUEST(
            P_REQUESTOR, P_ENVIRONMENT, P_DOMAIN, P_CAPABILITY, P_JUSTIFICATION,
            P_PROJECT_KEY, 'JIRA_INTEGRATION', 'JIRA_CREDENTIALS'
        ) INTO v_result;
    ELSE
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid ticket system. Use SERVICENOW or JIRA');
    END IF;
    
    -- Log the request in Snowflake (local audit table)
    BEGIN
        INSERT INTO RBAC_ACCESS_REQUESTS (
            REQUEST_ID, REQUESTOR, ENVIRONMENT, DOMAIN, CAPABILITY,
            JUSTIFICATION, TICKET_SYSTEM, TICKET_NUMBER, STATUS, CREATED_AT
        )
        SELECT
            UUID_STRING(),
            P_REQUESTOR,
            P_ENVIRONMENT,
            P_DOMAIN,
            P_CAPABILITY,
            P_JUSTIFICATION,
            P_TICKET_SYSTEM,
            v_result:ticket_number::VARCHAR,
            'PENDING',
            CURRENT_TIMESTAMP();
    EXCEPTION
        WHEN OTHER THEN
            NULL; -- Table may not exist yet
    END;
    
    RETURN v_result;

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Check Approval and Grant Access
 * 
 * Purpose: Checks ticket status and grants access if approved
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CHECK_AND_GRANT_APPROVED(
    P_TICKET_NUMBER VARCHAR,
    P_TICKET_SYSTEM VARCHAR DEFAULT 'SERVICENOW',
    P_REQUESTOR VARCHAR DEFAULT NULL,
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_DOMAIN VARCHAR DEFAULT NULL,
    P_CAPABILITY VARCHAR DEFAULT NULL,
    P_WAREHOUSE VARCHAR DEFAULT NULL
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_status VARIANT;
    v_grant_result VARIANT;
BEGIN
    -- Check ticket status
    IF (UPPER(P_TICKET_SYSTEM) = 'SERVICENOW') THEN
        CALL RBAC_SERVICENOW_CHECK_TICKET_STATUS(P_TICKET_NUMBER) INTO v_status;
    ELSEIF (UPPER(P_TICKET_SYSTEM) = 'JIRA') THEN
        CALL RBAC_JIRA_CHECK_ISSUE_STATUS(P_TICKET_NUMBER) INTO v_status;
    ELSE
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', 'Invalid ticket system');
    END IF;
    
    -- Check if approved
    IF (v_status:status = 'SUCCESS' AND v_status:is_approved = TRUE) THEN
        -- Grant access if parameters provided
        IF (P_REQUESTOR IS NOT NULL AND P_ENVIRONMENT IS NOT NULL AND 
           P_DOMAIN IS NOT NULL AND P_CAPABILITY IS NOT NULL) THEN
            
            CALL RBAC_CONFIGURE_USER(
                P_REQUESTOR, P_ENVIRONMENT, P_DOMAIN, P_CAPABILITY,
                COALESCE(P_WAREHOUSE, P_ENVIRONMENT || '_WH'), NULL
            ) INTO v_grant_result;
            
            -- Log the grant
            BEGIN
                CALL RBAC_SERVICENOW_LOG_AUDIT_EVENT(
                    'GRANT', P_REQUESTOR, 
                    'SRF_' || P_ENVIRONMENT || '_' || P_CAPABILITY,
                    CURRENT_USER(), P_TICKET_NUMBER, 'Auto-granted via approved ticket'
                );
            EXCEPTION
                WHEN OTHER THEN NULL;
            END;
            
            RETURN OBJECT_CONSTRUCT(
                'status', 'SUCCESS',
                'action', 'ACCESS_GRANTED',
                'ticket_number', P_TICKET_NUMBER,
                'approval_status', v_status:approval_status,
                'user', P_REQUESTOR,
                'roles_granted', ARRAY_CONSTRUCT(
                    'SRF_' || P_ENVIRONMENT || '_' || P_CAPABILITY,
                    'SRA_' || P_ENVIRONMENT || '_' || P_DOMAIN || '_ACCESS'
                ),
                'grant_result', v_grant_result
            );
        ELSE
            RETURN OBJECT_CONSTRUCT(
                'status', 'SUCCESS',
                'action', 'APPROVED_PENDING_GRANT',
                'ticket_number', P_TICKET_NUMBER,
                'approval_status', v_status:approval_status,
                'message', 'Ticket approved. Provide user details to grant access.',
                'next_step', 'Re-run with all parameters to grant access'
            );
        END IF;
    ELSEIF (v_status:is_approved = FALSE) THEN
        RETURN OBJECT_CONSTRUCT(
            'status', 'SUCCESS',
            'action', 'NOT_APPROVED',
            'ticket_number', P_TICKET_NUMBER,
            'approval_status', v_status:approval_status,
            'message', 'Ticket not yet approved or was rejected'
        );
    ELSE
        RETURN v_status;
    END IF;

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

/*******************************************************************************
 * RBAC STORED PROCEDURE: Create Access Review Tickets
 * 
 * Purpose: Creates periodic access review tickets for all users with RBAC roles
 ******************************************************************************/

CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_CREATE_ACCESS_REVIEW_TICKETS(
    P_ENVIRONMENT VARCHAR DEFAULT NULL,
    P_TICKET_SYSTEM VARCHAR DEFAULT 'SERVICENOW',
    P_PROJECT_KEY VARCHAR DEFAULT NULL,
    P_DRY_RUN BOOLEAN DEFAULT TRUE
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_reviews_created ARRAY := ARRAY_CONSTRUCT();
    v_env_filter VARCHAR;
BEGIN
    IF (P_ENVIRONMENT IS NOT NULL) THEN
        v_env_filter := '_' || P_ENVIRONMENT || '_';
    ELSE
        v_env_filter := '_%_';
    END IF;
    
    -- Get users with RBAC roles for review
    FOR user_rec IN (
        SELECT DISTINCT 
            u.NAME AS user_name,
            u.EMAIL,
            LISTAGG(DISTINCT g.ROLE, ', ') AS roles
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
        JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS g ON u.NAME = g.GRANTEE_NAME
        WHERE u.DELETED_ON IS NULL
          AND g.DELETED_ON IS NULL
          AND (g.ROLE LIKE 'SRF' || v_env_filter || '%' OR g.ROLE LIKE 'SRA' || v_env_filter || '%')
          AND (u.TYPE = 'PERSON' OR u.TYPE IS NULL)
        GROUP BY u.NAME, u.EMAIL
    ) DO
        IF (NOT P_DRY_RUN) THEN
            -- Create review ticket (implementation depends on ticket system)
            -- This is a placeholder - would call SERVICENOW or JIRA procedure
            NULL;
        END IF;
        
        v_reviews_created := ARRAY_APPEND(v_reviews_created, OBJECT_CONSTRUCT(
            'user', user_rec.user_name,
            'email', user_rec.EMAIL,
            'roles', user_rec.roles
        ));
    END FOR;
    
    RETURN OBJECT_CONSTRUCT(
        'status', 'SUCCESS',
        'mode', IFF(P_DRY_RUN, 'DRY_RUN', 'EXECUTED'),
        'environment_filter', COALESCE(P_ENVIRONMENT, 'ALL'),
        'users_for_review', ARRAY_SIZE(v_reviews_created),
        'reviews', v_reviews_created
    );

EXCEPTION
    WHEN OTHER THEN
        RETURN OBJECT_CONSTRUCT('status', 'ERROR', 'message', SQLERRM);
END;
$$;

-- #############################################################################
-- SECTION 5: LOCAL AUDIT TABLE (for tracking without external system)
-- #############################################################################

/*******************************************************************************
 * Create local audit table for tracking access requests
 ******************************************************************************/

CREATE TABLE IF NOT EXISTS RBAC_ACCESS_REQUESTS (
    REQUEST_ID VARCHAR(36) PRIMARY KEY,
    REQUESTOR VARCHAR(255) NOT NULL,
    ENVIRONMENT VARCHAR(10) NOT NULL,
    DOMAIN VARCHAR(100) NOT NULL,
    CAPABILITY VARCHAR(50) NOT NULL,
    JUSTIFICATION TEXT,
    TICKET_SYSTEM VARCHAR(50),
    TICKET_NUMBER VARCHAR(100),
    STATUS VARCHAR(50) DEFAULT 'PENDING',
    APPROVED_BY VARCHAR(255),
    APPROVED_AT TIMESTAMP_NTZ,
    GRANTED_AT TIMESTAMP_NTZ,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    UPDATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS RBAC_AUDIT_LOG (
    AUDIT_ID VARCHAR(36) DEFAULT UUID_STRING(),
    EVENT_TYPE VARCHAR(50) NOT NULL,
    USER_NAME VARCHAR(255),
    ROLE_NAME VARCHAR(255),
    PERFORMED_BY VARCHAR(255),
    TICKET_NUMBER VARCHAR(100),
    DETAILS TEXT,
    CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- #############################################################################
-- GRANT EXECUTE PERMISSIONS
-- #############################################################################

GRANT USAGE ON PROCEDURE RBAC_SETUP_SERVICENOW_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_SETUP_JIRA_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE ACCOUNTADMIN;
GRANT USAGE ON PROCEDURE RBAC_REQUEST_ACCESS(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_CHECK_AND_GRANT_APPROVED(VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR) TO ROLE SRS_SECURITY_ADMIN;
GRANT USAGE ON PROCEDURE RBAC_CREATE_ACCESS_REVIEW_TICKETS(VARCHAR, VARCHAR, VARCHAR, BOOLEAN) TO ROLE SRS_SECURITY_ADMIN;
