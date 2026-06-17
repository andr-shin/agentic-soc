"""Steampipe Agent Tools — SQL-based AWS resource analysis"""
from tools.steampipe_tools import execute_steampipe_sql, list_steampipe_tables

ALL_TOOLS = [
    execute_steampipe_sql,
    list_steampipe_tables,
]


def get_all_tools():
    return list(ALL_TOOLS)
