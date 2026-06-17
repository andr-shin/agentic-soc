"""Steampipe SQL execution tools (local psycopg2 connection to Steampipe PostgreSQL)"""
import json
from strands import tool


def _execute_query(sql, timeout=30):
    """Execute a SQL query against Steampipe (internal helper)."""
    import psycopg2
    import psycopg2.extras

    try:
        conn = psycopg2.connect(
            host="localhost", port=9193,
            user="steampipe", password="steampipe",
            dbname="steampipe", connect_timeout=10,
            options=f"-c statement_timeout={timeout * 1000}"
        )
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql)
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description] if cur.description else []
        cur.close()
        conn.close()

        result_rows = []
        for row in rows:
            result_rows.append({k: str(v) if v is not None else None for k, v in dict(row).items()})

        return {
            "success": True,
            "columns": columns,
            "rows": result_rows,
            "row_count": len(result_rows)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "rows": [],
            "row_count": 0
        }


def _list_tables(schema="aws"):
    """List available Steampipe tables (internal helper)."""
    sql = f"""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = '{schema}'
        ORDER BY table_name
    """
    return _execute_query(sql)


@tool
def execute_steampipe_sql(sql: str, timeout: int = 30) -> dict:
    """Execute SQL queries against 579 AWS resource tables via Steampipe. Only SELECT and WITH (CTE) queries are allowed. Table naming: aws_<service>_<resource>. Examples: 'SELECT * FROM aws_ec2_instance WHERE instance_state=\\'running\\'', 'SELECT i.instance_id, s.group_name FROM aws_ec2_instance i JOIN aws_vpc_security_group s ON i.vpc_id = s.vpc_id', 'SELECT * FROM aws_iam_user WHERE mfa_enabled = false'. Use LIMIT for large result sets."""
    sql_stripped = sql.strip()
    sql_upper = sql_stripped.upper()
    if not sql_upper.startswith("SELECT") and not sql_upper.startswith("WITH"):
        return {
            "success": False,
            "error": "Only SELECT and WITH (CTE) queries are allowed",
            "rows": [],
            "row_count": 0
        }

    timeout = min(timeout, 120)
    result = _execute_query(sql_stripped, timeout=timeout)

    # Truncate if too large
    result_str = json.dumps(result)
    if len(result_str) > 50000:
        result["rows"] = result["rows"][:50]
        result["truncated"] = True
        result["message"] = f"Results truncated to 50 rows (original: {result['row_count']})"

    return result


@tool
def list_steampipe_tables(filter: str = None) -> dict:
    """List available Steampipe AWS tables. Use this to discover table names before writing queries. Can filter by name pattern."""
    if filter:
        sql = f"SELECT table_name FROM information_schema.tables WHERE table_schema='aws' AND table_name LIKE '%{filter}%' ORDER BY table_name"
    else:
        sql = "SELECT table_name FROM information_schema.tables WHERE table_schema='aws' ORDER BY table_name"

    result = _execute_query(sql)
    if result.get('success') and result.get('rows'):
        return {'tables': [r['table_name'] for r in result['rows']], 'count': len(result['rows'])}
    return result
