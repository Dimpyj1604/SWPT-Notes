# Introduction to Serialization

Serialization converts an in-memory object into bytes for storage/transmission. Deserialization reconstructs it. Both PHP and Python support native serialization.

---

## PHP Serialization

`serialize()` produces a human-readable format. `unserialize()` reconstructs it.

```php
$data = array("HTB", 123, 7.77);
echo serialize($data);
// a:3:{i:0;s:3:"HTB";i:1;i:123;i:2;d:7.77;}
```

**Format breakdown:**

| Token | Meaning |
|-------|---------|
| `a:N:{...}` | Array with N items |
| `s:N:"val"` | String of length N |
| `i:N` | Integer N |
| `d:N` | Double/float N |
| `b:N` | Boolean (0 or 1) |
| `N;` | Null |
| `O:N:"ClassName":M:{...}` | Object of class with M properties |

**Example — associative array:**
```php
serialize(array("cereal" => "cheerios"))
// a:1:{s:6:"cereal";s:8:"cheerios";}
```

---

## Python Pickle Serialization

Pickle is Python's native serialization library. The output is binary and not human-readable without decoding.

```python
import pickle
data = ["HTB", 123, 7.77]
serialized = pickle.dumps(data)
# b'\x80\x04\x95\x16\x00...'
```

Pickle implements a virtual **Pickle Machine (PM)** with a stack (LIFO) and memo (long-term memory for shared/recursive objects).

### Protocol Versions

| Protocol | Default in |
|----------|-----------|
| 0 | Python 2 (ASCII-readable) |
| 1 | Python 2 (binary) |
| 2 | Python 2.3+ |
| 3 | Python 3.0–3.7 |
| 4 | Python 3.4+ (default since 3.8) |
| 5 | Python 3.8+ |

### Protocol 0 — Human-Readable Format

Protocol 0 is the original ASCII protocol. Useful for understanding pickle internals.

**Common opcodes:**

| Opcode | Meaning |
|--------|---------|
| `(` | MARK — push marker onto stack |
| `d` | DICT — create dict from items since MARK |
| `l` | LIST — create list from items since MARK |
| `t` | TUPLE — create tuple from items since MARK |
| `s` | SETITEM — set dict[key]=value (single) |
| `u` | SETITEMS — set multiple dict items since MARK |
| `a` | APPEND — append to list |
| `e` | APPENDS — extend list with items since MARK |
| `V<str>\n` | UNICODE — push unicode string |
| `S'<str>'\n` | STRING — push string (Python 2 style) |
| `I<n>\n` | INT — push integer |
| `F<n>\n` | FLOAT — push float |
| `p<n>\n` | PUT — memoize top of stack at index n |
| `g<n>\n` | GET — push memo[n] onto stack |
| `.` | STOP — end of pickle, top of stack is result |

### Protocol 0 Example — Dict

```python
import pickle
pickle.dumps({"gangnam": "style"}, 0)
# b'(dp0\nVgangnam\np1\nVstyle\np2\ns.'
```

**Disassembly:**
```
(        MARK
d            DICT       (MARK at 0)   — create empty dict
p   0        PUT 0                    — memoize dict
V gangnam    UNICODE 'gangnam'        — push key
p   1        PUT 1                    — memoize key
V style      UNICODE 'style'          — push value
p   2        PUT 2                    — memoize value
s            SETITEM                  — dict[key] = value
.            STOP
```

**Answer:** serialized value of `{"gangnam":"style"}` with protocol 0:
```
(dp0\nVgangnam\np1\nVstyle\np2\ns.
```

### Protocol 0 Example — List

```python
pickle.dumps(["HTB", 123, 7.77], 0)
# b'\x80\x04\x95\x16\x00...'  (higher default protocol)
# With protocol=0: uses ] (EMPTY_LIST), a (APPEND), e (APPENDS)
```

---

## Key Insight — Why Deserialization Is Dangerous

The pickle machine executes **opcodes** when deserializing. If an attacker controls serialized data, they can craft opcodes that execute arbitrary code — particularly via the `__reduce__` method which pickle calls during deserialization of custom objects.

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
pickle.loads(payload)  # executes: os.system('id')
```

This is why `pickle.loads()` on untrusted data is a critical vulnerability.
