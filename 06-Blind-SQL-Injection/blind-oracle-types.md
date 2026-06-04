# Blind SQLi — Boolean vs Time-Based Oracles

Blind = the query result never appears in the response. You extract data one
true/false answer at a time through a **side channel**. Two oracle types, picked by what
the app leaks.

## Boolean-based

The page renders **differently** for a true vs false condition (a record appears/vanishes,
a "welcome" string toggles, length changes). Fastest blind channel — one request per bit,
no waiting.

```sql
-- inject a condition; observe the page differ
... AND (SELECT SUBSTRING(@@version,1,1))='M'
... AND 1=1     -- baseline "true" page
... AND 1=2     -- baseline "false" page
```

Use it when you can find any reliable content difference between `1=1` and `1=2`.

## Time-based

No visible difference, but you can make the DB **sleep** on a true condition. The response
*time* is the oracle. Slower (you pay the delay per probe) but works when output is
identical:

```sql
-- MSSQL
';IF(<condition>) WAITFOR DELAY '0:0:5';--
-- MySQL
' AND IF(<condition>, SLEEP(5), 0)-- -
-- PostgreSQL
'; SELECT CASE WHEN (<condition>) THEN pg_sleep(5) ELSE pg_sleep(0) END;--
```

If `response_time >= delay` → condition true. Keep the delay short (2–3 s) but above
network jitter; verify borderline hits twice.

## Extraction strategy

Both oracles answer yes/no, so you binary-search or bit-test each character:

- **Bit-by-bit** (7 requests/char, ASCII printable): test each bit with
  `ASCII(SUBSTRING((<query>),i,1)) & 2^b > 0`. Deterministic, parallelisable.
- **Binary search** (≈log₂(N) ≈ 7 requests/char): `... > 'm'` style comparisons. Same
  cost, sometimes simpler to code.

Always extract a **length first** (`LEN(...)`/`LENGTH(...)`) so you know when to stop, then
loop the characters.

## Reducing request count

- Boolean beats time-based on speed — always look for a content diff first.
- Parallelise independent probes (different char positions / the 256 byte guesses) with a
  thread pool; serial blind extraction of a hash takes ages.
- Cache the true/false baselines once; don't re-fetch them every probe.

## Mitigation

Parameterised queries / prepared statements everywhere; a least-privilege DB account;
generic error and timing behaviour so neither content nor latency leaks the boolean.
