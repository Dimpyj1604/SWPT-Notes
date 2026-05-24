# PostgreSQL Logging for SQL Injection Debugging

Enabling SQL logging on the server gives real-time visibility into every query the app executes — parameterized values included. Useful during whitebox testing to verify injection payloads land correctly.

---

## Enabling Logging

Edit `/etc/postgresql/<version>/main/postgresql.conf`:

```
logging_collector = on          # was: #logging_collector = off
log_statement = 'all'           # was: #log_statement = 'none'
log_directory = 'pg_log'        # uncomment and set
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'  # uncomment
```

Then restart:
```bash
sudo systemctl restart postgresql
```

---

## Tailing the Log

```bash
sudo watch -n 1 tail /var/log/postgresql/<logfile>.log
# or wherever log_directory points
sudo tail -f /opt/bluebird/pg_log/postgresql-*.log
```

---

## What the Log Shows

Parameterized queries log with `$1`, `$2` placeholders plus a DETAIL line for the bound values:

```
LOG:  execute <unnamed>: SELECT * FROM users WHERE username = $1
DETAIL:  parameters: $1 = 'bmdyy'
```

Raw-concat queries log the full string — injection payloads appear verbatim.

---

## application_name

When a Spring Boot / JDBC app connects, PostgreSQL logs:

```
LOG:  execute <unnamed>: SET application_name = 'PostgreSQL JDBC Driver'
```

This identifies the connection as coming from the JDBC driver (not psql or pgAdmin). Useful when correlating log entries to specific app connections in multi-client setups.
