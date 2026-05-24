# PostgreSQL — Basics & Reconnaisance Queries

Familiarity with psql and the schema structure before getting into injection.

---

## Connecting

```bash
psql -h <HOST> -p <PORT> -U <USER> <DATABASE>
# with password inline (scripting):
PGPASSWORD="pass" psql -h HOST -p PORT -U user dbname -c "SELECT 1;"
```

---

## Essential psql Meta-Commands

| Command | Purpose |
|---------|---------|
| `\l` | List databases |
| `\c <db>` | Switch database |
| `\dt` | List tables in current schema |
| `\dt+` | List tables with size info |
| `\d <table>` | Describe table (columns, types, constraints, FK) |
| `\d+ <table>` | Extended table description |
| `\q` | Quit |

---

## Common Recon Query Patterns

### Department / category lookup
```sql
SELECT id, name FROM departments WHERE name = 'Information Technology';
```

### Count members in a group (via junction table)
```sql
SELECT COUNT(*) FROM dept_emp WHERE dept_id = 4;
```

### Most recently hired (or latest record)
```sql
SELECT e.email, e.hire_date
FROM employees e
JOIN dept_emp de ON e.id = de.emp_id
WHERE de.dept_id = 4
ORDER BY e.hire_date DESC
LIMIT 1;
```

### Nth lowest/highest value (e.g., second-lowest salary)
```sql
-- Get all ordered, pick the 2nd row with OFFSET
SELECT salary
FROM salaries s
JOIN dept_emp de ON s.emp_id = de.emp_id
JOIN employees e ON e.id = s.emp_id
WHERE de.dept_id = 4 AND e.first_name = 'William'
ORDER BY s.salary ASC
LIMIT 1 OFFSET 1;
```

---

## Schema Layout (acmecorp sample DB)

```
departments   (id, name)
employees     (id, username, email, password, first_name, last_name, birth_date, hire_date)
dept_emp      (emp_id → employees.id, dept_id → departments.id, from_date, to_date)
salaries      (emp_id → employees.id, salary, ...)
titles        (emp_id → employees.id, ...)
```

The `dept_emp` junction table links employees to departments. Always join through it when filtering by department.

---

## PostgreSQL vs MySQL Differences to Know

| Feature | PostgreSQL | MySQL |
|---------|-----------|-------|
| String concat | `||` or `CONCAT()` | `CONCAT()` or space |
| Limit/offset | `LIMIT n OFFSET m` | `LIMIT m, n` |
| Boolean | `true` / `false` | `1` / `0` |
| Schema info | `information_schema` + `pg_catalog` | `information_schema` |
| Sleep | `pg_sleep(n)` | `SLEEP(n)` |
| Current user | `current_user` | `user()` |
| Version | `version()` | `version()` |
| List databases | `SELECT datname FROM pg_database` | `SHOW DATABASES` |
| List tables | `SELECT tablename FROM pg_tables WHERE schemaname='public'` | `SHOW TABLES` |
