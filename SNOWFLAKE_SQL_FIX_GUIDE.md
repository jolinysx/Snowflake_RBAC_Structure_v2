# Snowflake SQL Syntax Fix Guide

**Purpose:** Reference guide for identifying and fixing common Snowflake SQL syntax issues in stored procedures  
**Last Updated:** 2026-02-20

---

## 🔄 **RECOMMENDED FIX PROCESS**

When user says "fix this file" or similar:

### **ITERATION 1: Primary Scan & Fix**
1. Read entire file to understand structure
2. Identify ALL instances of common issues (see checklist below)
3. Apply fixes using `multi_edit` for batching similar changes
4. Validate with `snowflake_sql_execute` using `only_compile=true`

### **ITERATION 2: Verification & Edge Cases**
1. Re-read the file completely
2. Look for missed issues, especially:
   - Nested IF statements
   - CALL statements in different contexts
   - Variables with unusual names
   - Complex boolean expressions
3. Apply any remaining fixes
4. Final validation with SQL compilation

**✅ Only after TWO complete passes should you declare the file fixed.**

---

## 📋 **Quick Fix Checklist**

Use this for EVERY file:

- [ ] All `IF` statements have parentheses: `IF (condition) THEN`
- [ ] **All `ELSEIF` (NOT `ELSIF`)** ⭐ CRITICAL - Snowflake uses ELSEIF, not ELSIF
- [ ] All `ELSEIF` statements have parentheses: `ELSEIF (condition) THEN`
- [ ] **All loops use `FOR...LOOP` and `END LOOP`** (NOT `FOR...DO` or `END FOR`)
- [ ] All `CREATE PROCEDURE` have fully qualified names: `ADMIN.SCHEMA.NAME`
- [ ] All `CALL` statements:
  - Have fully qualified names
  - Use `CALL ... INTO variable` syntax (not assignment)
- [ ] **No `ARRAY` data type declarations (use `VARIANT`)** ⭐ CRITICAL
- [ ] **No `::VARCHAR` casting in dynamic SQL - use `TO_VARCHAR()` instead** ⭐ CRITICAL
- [ ] No `OBJECT` data type declarations (use `VARIANT`)
- [ ] No direct array index assignment (use `ARRAY_APPEND`)
- [ ] **No multi-line string concatenations with `||` - keep on single line**
- [ ] **No `ORDER BY` in SELECT...INTO statements** ⭐ CRITICAL
- [ ] **No WITH clause before SELECT...INTO - convert to subquery** ⭐ CRITICAL
- [ ] **Multiple ARRAY_AGG in SELECT...INTO? Use CTE pattern** ⭐ CRITICAL
- [ ] **Multiple RESULTSETs? Capture LAST_QUERY_ID() after EACH** ⚠️ OR use CTE instead
- [ ] SECRETS have schema prefix: `DATABASE.SCHEMA.SECRET_NAME`
- [ ] EXTERNAL_ACCESS_INTEGRATIONS have NO prefix
- [ ] `EXECUTE IMMEDIATE FROM` with variables uses dynamic SQL
- [ ] No GRANT statements to non-existent roles (comment if needed)

---

## 🔧 **Fix Patterns**

### **1. IF Statement Syntax** ⭐ MOST COMMON

#### ❌ Wrong
```sql
IF condition THEN
IF NOT condition THEN
IF condition1 AND condition2 THEN
IF condition1 OR condition2 THEN
ELSIF condition THEN  -- WRONG: Snowflake uses ELSEIF not ELSIF
ELSEIF condition THEN  -- Missing parentheses
```

#### ✅ Correct
```sql
IF (condition) THEN
IF (NOT condition) THEN
IF (condition1 AND condition2) THEN
IF (condition1 OR condition2) THEN
ELSEIF (condition) THEN  -- Use ELSEIF with parentheses
```

#### Examples
```sql
-- Simple conditions
IF (P_ENVIRONMENT = 'DEV') THEN
IF (NOT v_exists) THEN
IF (v_count > 0) THEN
IF (i > 0) THEN

-- NULL checks
IF (P_VALUE IS NULL) THEN
IF (P_VALUE IS NOT NULL) THEN
IF (v_result IS NULL) THEN

-- Complex conditions
IF (P_SECTION = 'ROLES' OR P_SECTION IS NULL) THEN
IF (P_NOTIFY_USERS IS NOT NULL AND ARRAY_SIZE(P_NOTIFY_USERS) > 0) THEN

-- ELSEIF chains
IF (v_type = 'TABLE') THEN
    -- do something
ELSEIF (v_type = 'VIEW') THEN
    -- do something else
ELSE
    -- default case
END IF;

-- Nested parentheses for NOT
IF (NOT (condition1 OR condition2)) THEN
IF (NOT (P_ENV = 'DEV' AND P_TYPE = 'TEST')) THEN

-- Boolean variables
IF (P_DRY_RUN) THEN
IF (P_ENABLED) THEN
IF (NOT P_DRY_RUN) THEN

-- JSON path conditions
IF (v_result:status = 'SUCCESS') THEN
IF (v_result:is_approved = TRUE) THEN

-- Array operations
IF (ARRAY_SIZE(v_array) > 0) THEN
IF (v_expected[P_SECTION] IS NOT NULL) THEN

-- LIKE conditions
IF (SQLERRM LIKE '%error%') THEN
IF (SQLERRM LIKE '%ERROR%' OR SQLERRM LIKE '%FAIL%') THEN
```

---

### **2. Stored Procedure Naming**

#### ❌ Wrong
```sql
CREATE OR REPLACE SECURE PROCEDURE PROCEDURE_NAME(...)
CREATE PROCEDURE MY_PROCEDURE(...)
```

#### ✅ Correct
```sql
CREATE OR REPLACE SECURE PROCEDURE DATABASE.SCHEMA.PROCEDURE_NAME(...)
CREATE OR REPLACE SECURE PROCEDURE DATABASE.SCHEMA.ANOTHER_PROCEDURE(...)
```

**Pattern:** Always use `DATABASE.SCHEMA.PROCEDURE_NAME`

**Common schemas:**
- `DATABASE.SCHEMA.*` - Use appropriate database and schema names
- Examples: `ADMIN.RBAC.*`, `ADMIN.DEVOPS.*`, `ADMIN.SECURITY.*`

---

### **3. CALL Statement Syntax**

#### ❌ Wrong
```sql
-- Wrong: Assignment with parentheses
v_result := (CALL PROCEDURE_NAME(...));
LET v_result := (CALL PROCEDURE_NAME(...));

-- Wrong: Unqualified name
CALL MY_PROCEDURE(...) INTO v_result;
CALL PROCEDURE_NAME(...) INTO v_result;
```

#### ✅ Correct
```sql
-- Correct: CALL ... INTO syntax with qualified name
CALL DATABASE.SCHEMA.PROCEDURE_NAME(...) INTO v_result;
CALL DATABASE.SCHEMA.ANOTHER_PROCEDURE(...) INTO v_result;
CALL DATABASE.SCHEMA.COST_DASHBOARD(30) INTO v_cost_overview;
```

**Key points:**
1. Always use fully qualified names: `DATABASE.SCHEMA.PROCEDURE_NAME`
2. Always use `INTO` syntax, never assignment with `(CALL ...)`
3. Can be used anywhere in code, including inside loops

---

### **4. SELECT...INTO with ORDER BY** ⭐ CRITICAL

#### ❌ Wrong
```sql
-- ORDER BY not allowed with SELECT INTO
SELECT ARRAY_AGG(OBJECT_CONSTRUCT(...)) INTO v_results
FROM table
ORDER BY column DESC;  -- ❌ Compilation error!

-- Also fails in subqueries
SELECT ARRAY_AGG(...) INTO v_data
FROM (
    SELECT col1, col2
    FROM table
    ORDER BY col1  -- ❌ Not allowed
);
```

#### ✅ Correct
```sql
-- Remove ORDER BY from SELECT INTO
SELECT ARRAY_AGG(OBJECT_CONSTRUCT(...)) INTO v_results
FROM table;

-- If ordering is needed, use ARRAY_AGG with WITHIN GROUP
SELECT ARRAY_AGG(value) WITHIN GROUP (ORDER BY sort_col) INTO v_results
FROM table;

-- Or order the subquery differently
SELECT ARRAY_AGG(...) INTO v_data
FROM (
    SELECT col1, col2
    FROM table
);
```

**Rule:** Snowflake does NOT allow ORDER BY in SELECT...INTO statements.

**Error message:** `SQL compilation error: error line X at position Y INTO clause is not allowed in this context`

**Fix:** Remove ORDER BY entirely, or use `WITHIN GROUP` clause if ARRAY_AGG ordering is needed.

---

### **4B. Multiple ARRAY_AGG in SELECT...INTO** ⭐ CRITICAL

#### ❌ Wrong
```sql
-- Multiple ARRAY_AGG operations in same OBJECT_CONSTRUCT with INTO
SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
    'key', col1,
    'values', ARRAY_AGG(DISTINCT col2),  -- Problem: Multiple aggregations
    'count', COUNT(*)
)) INTO v_result
FROM table
GROUP BY col1;
```

#### ✅ Correct - Use CTE (Common Table Expression) Pattern
```sql
-- Step 1: Create CTE with aggregations
WITH temp_agg AS (
    SELECT 
        col1,
        ARRAY_AGG(DISTINCT col2) AS vals,
        COUNT(*) AS cnt
    FROM table
    GROUP BY col1
)
-- Step 2: Build OBJECT_CONSTRUCT from CTE
SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
    'key', col1,
    'values', vals,
    'count', cnt
)) INTO v_result
FROM temp_agg;
```

**Alternative - Use RESULTSET with Captured Query ID**
```sql
-- Step 1: Compute aggregations into RESULTSET
LET v_temp RESULTSET := (
    SELECT 
        col1,
        ARRAY_AGG(DISTINCT col2) AS vals,
        COUNT(*) AS cnt
    FROM table
    GROUP BY col1
);

-- Step 2: Capture query ID immediately
LET v_query_id VARCHAR := LAST_QUERY_ID();

-- Step 3: Build OBJECT_CONSTRUCT from results
SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
    'key', col1,
    'values', vals,
    'count', cnt
)) INTO v_result
FROM TABLE(RESULT_SCAN(:v_query_id));
```

**Recommendation:** Use CTE pattern - it's simpler and more reliable than RESULTSET pattern.

**Rule:** When combining ARRAY_AGG with other aggregations in OBJECT_CONSTRUCT + INTO, use CTE or RESULTSET pattern.

**Error message:** `SQL compilation error: error line X at position Y INTO clause is not allowed in this context`

**CRITICAL - Multiple RESULTSETs:** When using multiple RESULTSET variables, you MUST capture the query ID immediately after EACH assignment:

```sql
-- ❌ WRONG - LAST_QUERY_ID() gets overwritten
LET v_result1 RESULTSET := (SELECT ...);
LET v_result2 RESULTSET := (SELECT ...);  -- Overwrites LAST_QUERY_ID!
SELECT ... FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));  -- Returns wrong result!

-- ✅ CORRECT - Capture query ID for each RESULTSET
LET v_result1 RESULTSET := (SELECT ...);
LET v_id1 VARCHAR := LAST_QUERY_ID();  -- Capture immediately!

LET v_result2 RESULTSET := (SELECT ...);
LET v_id2 VARCHAR := LAST_QUERY_ID();  -- Capture immediately!

SELECT ... FROM TABLE(RESULT_SCAN(:v_id1));  -- Use captured ID
SELECT ... FROM TABLE(RESULT_SCAN(:v_id2));  -- Use captured ID
```

---

### **4C. Variable Type Declarations** ⭐ CRITICAL

#### ❌ Wrong
```sql
DECLARE
    v_list ARRAY := ARRAY_CONSTRUCT();
    v_deleted_items ARRAY;
    v_object OBJECT;
```

#### ✅ Correct
```sql
DECLARE
    v_list VARIANT := ARRAY_CONSTRUCT();
    v_deleted_items VARIANT;
    v_object VARIANT;
```

**Rule:** Snowflake SQL does NOT support `ARRAY` or `OBJECT` as data types in DECLARE blocks. Use `VARIANT` instead.

**Error message:** `SQL compilation error: syntax error line X at position Y unexpected 'ARRAY'`

**Fix:** Replace all `ARRAY` and `OBJECT` type declarations with `VARIANT`.

---

### **4D. Dynamic SQL Type Casting** ⭐ CRITICAL

#### ❌ Wrong
```sql
-- Using :: operator in dynamic SQL concatenations
v_sql := 'CREATE TABLE t AT (TIMESTAMP => ''' || P_TIME::VARCHAR || '''::TIMESTAMP_NTZ)';
v_comment := 'Created: ' || CURRENT_TIMESTAMP()::VARCHAR;
```

#### ✅ Correct
```sql
-- Use TO_VARCHAR() function instead
v_sql := 'CREATE TABLE t AT (TIMESTAMP => TO_TIMESTAMP_NTZ(''' || TO_VARCHAR(P_TIME) || '''))';
v_comment := 'Created: ' || TO_VARCHAR(CURRENT_TIMESTAMP());
```

**Rule:** The `::` casting operator can cause parsing errors when used inside string concatenations for dynamic SQL. Use explicit conversion functions instead.

**Error message:** `SQL compilation error: syntax error line X at position Y unexpected 'THEN'` (misleading - actual issue is in the line before)

**Fix:** Replace `value::VARCHAR` with `TO_VARCHAR(value)` in all dynamic SQL string concatenations.

**Common functions:**
- `TO_VARCHAR()` instead of `::VARCHAR`
- `TO_TIMESTAMP_NTZ()` instead of `::TIMESTAMP_NTZ`
- `TO_NUMBER()` instead of `::NUMBER`
- `TO_BOOLEAN()` instead of `::BOOLEAN`

---

### **4E. Multi-line String Concatenation**

#### ❌ Wrong
```sql
-- Multi-line concatenation can cause parsing issues
v_sql := 'CREATE TABLE ' || v_target || ' CLONE ' || v_source || 
         ' AT (TIMESTAMP => TO_TIMESTAMP_NTZ(''' || TO_VARCHAR(P_TIME) || '''))';
         
EXECUTE IMMEDIATE 'ALTER DATABASE ' || v_db || 
                 ' SET COMMENT = ''Comment: ' || v_name || 
                 ' | Created: ' || TO_VARCHAR(CURRENT_TIMESTAMP()) || '''';
```

#### ✅ Correct
```sql
-- Keep entire string concatenation on single line
v_sql := 'CREATE TABLE ' || v_target || ' CLONE ' || v_source || ' AT (TIMESTAMP => TO_TIMESTAMP_NTZ(''' || TO_VARCHAR(P_TIME) || '''))';

EXECUTE IMMEDIATE 'ALTER DATABASE ' || v_db || ' SET COMMENT = ''Comment: ' || v_name || ' | Created: ' || TO_VARCHAR(CURRENT_TIMESTAMP()) || '''';
```

**Rule:** Keep string concatenations on a single line when possible to avoid parsing ambiguities, especially for EXECUTE IMMEDIATE statements.

---

### **4F. Loop Syntax** ⭐ CRITICAL

#### ❌ Wrong
```sql
-- Using DO...END FOR (not valid in Snowflake)
FOR rec IN (SELECT * FROM table) DO
    -- loop body
END FOR;
```

#### ✅ Correct
```sql
-- Use LOOP...END LOOP
FOR rec IN (SELECT * FROM table) LOOP
    -- loop body
END LOOP;
```

**Rule:** Snowflake uses `FOR...LOOP` and `END LOOP`, not `FOR...DO` and `END FOR`.

**Error message:** `SQL compilation error: syntax error line X at position Y unexpected 'DO'` or `unexpected 'THEN'`

**Fix:** Replace `DO` with `LOOP` and `END FOR` with `END LOOP`.

---

### **4G. WITH Clause with SELECT...INTO** ⭐ CRITICAL

#### ❌ Wrong
```sql
-- CTE (WITH clause) followed by SELECT...INTO
WITH temp_agg AS (
    SELECT col1, COUNT(*) AS cnt
    FROM table
    GROUP BY col1
)
SELECT ARRAY_AGG(OBJECT_CONSTRUCT(...)) INTO v_result
FROM temp_agg;
```

#### ✅ Correct
```sql
-- Convert CTE to inline subquery
SELECT ARRAY_AGG(OBJECT_CONSTRUCT(...)) INTO v_result
FROM (
    SELECT col1, COUNT(*) AS cnt
    FROM table
    GROUP BY col1
);
```

**Rule:** Snowflake does NOT allow WITH clause (CTE) before SELECT...INTO statements. Convert to subquery.

**Error message:** `SQL compilation error: error line X at position Y INTO clause is not allowed in this context`

**Fix:** Remove the WITH clause and convert it to an inline subquery in the FROM clause.

---

### **6. External Integrations & Secrets**

#### ❌ Wrong
```sql
-- Wrong: Prefix on integration
EXTERNAL_ACCESS_INTEGRATIONS = (DATABASE.SCHEMA.INTEGRATION_NAME)

-- Wrong: No prefix on secret
SECRETS = ('cred' = SECRET_NAME)
```

#### ✅ Correct
```sql
-- Correct: No prefix on integration (account-level)
EXTERNAL_ACCESS_INTEGRATIONS = (INTEGRATION_NAME)

-- Correct: Schema prefix on secret (schema-level)
SECRETS = ('cred' = DATABASE.SCHEMA.SECRET_NAME)
```

**Rule:**
- **EXTERNAL_ACCESS_INTEGRATIONS**: Account-level object, NO database.schema prefix
- **SECRETS**: Schema-level object, REQUIRES database.schema prefix

---

### **7. Array Operations**

#### ❌ Wrong
```sql
-- Direct array index assignment NOT supported
v_array[index] := value;
v_actions[ARRAY_SIZE(v_actions) - 1] := updated_value;
```

#### ✅ Correct
```sql
-- Use ARRAY_APPEND instead
v_array := ARRAY_APPEND(v_array, value);
v_actions := ARRAY_APPEND(v_actions, new_action);

-- Reading is OK
LET v_item := v_array[index];
IF (v_array[i] = 'value') THEN
```

**Rule:** You can READ from array indices, but cannot ASSIGN to them.

---

### **8. Data Types**

#### ❌ Wrong
```sql
DECLARE
    v_obj OBJECT;
    v_data OBJECT;
```

#### ✅ Correct
```sql
DECLARE
    v_obj VARIANT;
    v_data VARIANT;
```

**Common correct types:**
- `VARCHAR` - Strings
- `NUMBER` / `INTEGER` - Numeric values
- `BOOLEAN` - True/False
- `ARRAY` - Arrays
- `VARIANT` - JSON-like objects, semi-structured data
- `TIMESTAMP_NTZ` - Timestamps

**Note:** There is no `OBJECT` type in Snowflake SQL. Use `VARIANT`.

---

### **9. EXECUTE IMMEDIATE FROM with Variables**

#### ❌ Wrong
```sql
EXECUTE IMMEDIATE FROM :v_file_location;
EXECUTE IMMEDIATE FROM v_file_location;
```

#### ✅ Correct
```sql
-- Build the EXECUTE IMMEDIATE statement as a string first
LET v_exec_sql VARCHAR := 'EXECUTE IMMEDIATE FROM ' || v_file_location;
EXECUTE IMMEDIATE v_exec_sql;
```

**Explanation:** `EXECUTE IMMEDIATE FROM` doesn't directly support variable substitution. Build it as dynamic SQL.

---

### **10. Non-Existent Dependencies**

When procedures require secrets/integrations that don't exist yet:

#### ❌ Wrong
```sql
CREATE PROCEDURE ... 
SECRETS = ('cred' = NON_EXISTENT_SECRET)
-- This will fail at creation time
```

#### ✅ Correct - Option 1: Comment Out
```sql
-- ============================================================================
-- COMMENTED OUT: Uncomment after creating required dependencies
-- This procedure requires INTEGRATION_NAME and DATABASE.SCHEMA.SECRET_NAME
-- ============================================================================
/*
CREATE OR REPLACE SECURE PROCEDURE DATABASE.SCHEMA.PROCEDURE_NAME(...)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'handler_function'
EXTERNAL_ACCESS_INTEGRATIONS = (INTEGRATION_NAME)
SECRETS = ('cred' = DATABASE.SCHEMA.SECRET_NAME)
PACKAGES = ('requests', 'snowflake-snowpark-python')
AS
$$
...
$$;
*/
```

#### ✅ Correct - Option 2: Add Prerequisites Section
```sql
/*******************************************************************************
 * PREREQUISITES:
 *   1. Create required dependencies first:
 *      - INTEGRATION_NAME (external access integration)
 *      - DATABASE.SCHEMA.SECRET_NAME (secret)
 *   2. Then uncomment and deploy this procedure
 ******************************************************************************/
```

---

### **11. Missing Roles in GRANT Statements**

#### ❌ Wrong
```sql
-- Will fail if role doesn't exist
GRANT USAGE ON PROCEDURE ... TO ROLE ROLE_NAME;
```

#### ✅ Correct
```sql
-- Comment out with instructions
-- ============================================================================
-- NOTE: Uncomment after creating ROLE_NAME role
-- ============================================================================
-- CREATE ROLE IF NOT EXISTS ROLE_NAME;
-- GRANT ROLE ROLE_NAME TO ROLE ACCOUNTADMIN;
-- GRANT USAGE ON PROCEDURE PROCEDURE_NAME(...) TO ROLE ROLE_NAME;
```

---

## 🔍 **Common Edge Cases**

### **Nested IF Statements**
```sql
-- All levels need parentheses
IF (condition1) THEN
    IF (condition2) THEN
        IF (condition3) THEN
            -- code
        END IF;
    END IF;
END IF;
```

### **IF with Complex Boolean Logic**
```sql
-- Multiple layers of parentheses
IF (NOT (
    (P_SOURCE = 'DEV' AND P_TARGET = 'TST') OR
    (P_SOURCE = 'TST' AND P_TARGET = 'UAT') OR
    (P_SOURCE = 'UAT' AND P_TARGET = 'PRD')
)) THEN
    -- code
END IF;
```

### **FOR Loops**
```sql
-- For loop variables don't need IF, but conditions inside do
FOR i IN 0 TO ARRAY_SIZE(v_array) - 1 DO
    IF (i > 0) THEN
        -- code
    END IF;
END FOR;

FOR record IN cursor_name DO
    IF (record.status = 'ACTIVE') THEN
        -- code
    END IF;
END FOR;
```

### **CASE Statements in Variables**
```sql
-- CASE statements don't need parentheses like IF
v_value := CASE 
    WHEN condition1 THEN 'value1'
    WHEN condition2 THEN 'value2'
    ELSE 'default'
END;
```

---

## 🚀 **Multi-Edit Strategy**

When fixing multiple similar issues, use `multi_edit` with batching:

```python
multi_edit([
    {
        "old_string": "    IF P_ENVIRONMENT = 'DEV' THEN",
        "new_string": "    IF (P_ENVIRONMENT = 'DEV') THEN"
    },
    {
        "old_string": "    IF NOT v_exists THEN",
        "new_string": "    IF (NOT v_exists) THEN",
        "replace_all": true  # Use when pattern appears multiple times
    },
    {
        "old_string": "CREATE OR REPLACE SECURE PROCEDURE RBAC_",
        "new_string": "CREATE OR REPLACE SECURE PROCEDURE ADMIN.RBAC.RBAC_",
        "replace_all": true
    }
])
```

---

## ✅ **Validation Steps**

After each fix iteration:

1. **Compile check:**
```python
snowflake_sql_execute(
    description="Validate procedure compiles",
    only_compile=true,
    sql="CREATE OR REPLACE PROCEDURE ADMIN.RBAC.TEST_PROC() ..."
)
```

2. **Look for these success indicators:**
   - `"status": "validated"`
   - `"result": "SQL validation successful"`

3. **Common error patterns to watch for:**
   - `"syntax error ... unexpected"` - Usually missing parentheses or wrong syntax
   - `"does not exist or not authorized"` - Missing dependencies (roles, secrets, etc.)
   - `"invalid value"` - Wrong prefix on integrations/secrets

---

## 📝 **Fix Order Priority**

Process files in this order for efficiency:

1. **IF statements** - Most common, affects most procedures
2. **Procedure names** - Affects creation of all objects
3. **CALL statements** - Depends on procedure names being correct
4. **Data types** - Affects variable declarations
5. **Array operations** - Less common but important
6. **EXECUTE IMMEDIATE** - Specific use cases
7. **Dependencies** - Comment out what doesn't exist

---

## 🎯 **Quick Reference Commands**

### Search for issues:
- `IF ` followed by identifier (not parenthesis)
- `CALL ` not followed by `ADMIN.`
- `OBJECT` in DECLARE blocks
- `[index] :=` for array assignment
- `EXECUTE IMMEDIATE FROM :` with colon

### Validate schema for common issues:
```sql
-- Check for procedures without schema
SHOW PROCEDURES LIKE '%RBAC%';

-- Verify roles exist
SHOW ROLES LIKE 'SRS_%';

-- Check secrets
SHOW SECRETS IN SCHEMA ADMIN.RBAC;
```

---

## 📚 **Related Documentation**

- [Snowflake SQL IF Statement](https://docs.snowflake.com/en/sql-reference/constructs/if)
- [Stored Procedures](https://docs.snowflake.com/en/sql-reference/stored-procedures)
- [EXTERNAL ACCESS](https://docs.snowflake.com/en/sql-reference/sql/create-external-access-integration)
- [Secrets](https://docs.snowflake.com/en/sql-reference/sql/create-secret)

---

**Remember:** When user says "fix this file", do TWO complete iterations!
