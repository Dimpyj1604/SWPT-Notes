# Searching for SQL Injection in Java Source (Whitebox)

After decompiling a JAR, the goal is to locate SQL queries and identify which ones concatenate user input unsafely. RegEx grep patterns speed this up significantly.

---

## Grep Patterns for SQL Injection Hunting

```bash
# Find all SQL keywords
grep -irnE 'SELECT|UPDATE|DELETE|INSERT|CREATE|ALTER|DROP' .

# Find string concatenation near WHERE/VALUES clauses
grep -nrE '(WHERE|VALUES).*" \+' .

# Find lines with sql variable and a double quote (common Java pattern)
grep -nrE '.*sql.*"' .

# Find jdbcTemplate usage
grep -nrE 'jdbcTemplate' .
```

Run from the `BOOT-INF/classes/` directory after extraction. The `--include='*.java'` flag can scope it to Java files only if you have mixed content.

---

## Spring Boot / JdbcTemplate Patterns

Safe (parameterized — not injectable):
```java
String sql = "SELECT * FROM users WHERE username = ?";
jdbcTemplate.queryForObject(sql, new Object[]{username}, ...);
```

Vulnerable (string concatenation):
```java
String sql = "SELECT * FROM users WHERE email = '" + email + "'";
jdbcTemplate.queryForObject(sql, ...);
```

The `?` placeholder means parameterized query — safe. Raw string concatenation is the injection surface.

---

## BlueBird Injection Points Found

### 1. `/find-user` (GET, IndexController.java)
```java
// Vulnerable — username concatenated directly
String sql = "SELECT * FROM users WHERE username LIKE '" + u + "'";
```
Has some input filtering (regex + space check), but likely bypassable.

### 2. `/forgot` (POST, AuthController.java)
```java
// Vulnerable — email concatenated directly
String sql = "SELECT * FROM users WHERE email = '" + email + "'";
```
Email validated against `^.*@[A-Za-z]*\\.[A-Za-z]*$` — but `@` and dots are still allowed, giving room to inject.
Error output leaks a full stack trace when client IP is `127.0.1.1` — useful for error-based extraction.

### 3. `/profile/{id}` (GET, ProfileController.java)
```java
// Second-order — email comes from DB, but is the user's stored email injected into query
sql = "SELECT ... FROM posts JOIN users ON posts.author_id = users.id WHERE email = '" + user.getEmail() + "'";
```
The `user.getEmail()` value comes from a prior parameterized query. This is only exploitable if we can store a malicious email during registration (second-order injection).

### 4. `/signup` INSERT (POST, AuthController.java)
```java
// signupPOST params: name, username, email, password, repeatPassword
String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
String sql3 = "INSERT INTO users (name, username, email, password) VALUES ('"
    + name + "', '" + username + "', '" + email + "', '" + passwordHash + "')";
```
The function receives 5 form params: `name`, `username`, `email`, `password`, `repeatPassword`.

- `name`, `username`, `email` — concatenated raw into the INSERT, all injectable.
- `password` — bcrypt-hashed before insertion (`passwordHash`). The hash output (`$2a$10$...`) is fixed-format and not injectable. However, `password` at least reaches the query (as the hash).
- `repeatPassword` — only used for the `password.equals(repeatPassword)` equality check, then **discarded entirely**. It never reaches the INSERT query at all — cannot be used for exploitation.

---

## Key Principle: What Blocks Injection?

| Scenario | Injectable? |
|----------|------------|
| Raw string concat into query | Yes |
| Regex validation (partial — allows `@`, `.`) | Usually still exploitable |
| Parameterized query (`?`) | No |
| Field value is hashed before insertion | No — hash output is fixed-format |
| Field value from a prior parameterized query | Only if you can control what was stored (second-order) |

If a field passes through a one-way transform (hash, HMAC, encode) before reaching the SQL string, it's not injectable regardless of what you submit.

---

## Decompiling Without Fernflower

For hunting SQL strings specifically, you don't always need a full decompile. The JVM bytecode contains string literals in the constant pool — readable with `javap -verbose` or `strings`:

```bash
# Fast — gets all string constants including SQL queries
javap -verbose AuthController.class | grep 'String '

# Even faster but less reliable for complex strings
strings AuthController.class | grep -i 'SELECT\|INSERT\|WHERE'
```

Use full decompile (Fernflower/JD-GUI) when you need to understand the control flow and validation logic, not just find the queries.
