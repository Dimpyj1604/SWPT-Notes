# Advanced .NET Deserialization

This module covers deserialization attacks in .NET — the kind where you turn a base64 blob into remote code execution. The gadget chains here are well-documented (ysoserial.net is your best friend), but the challenge is knowing which one to use and how to deliver it.

## Labs

- [BinaryFormatter + TypeConfuseDelegate](./binaryformatter.md) — Classic TTAUTH chain, works in IIS/MTA environments
- [XmlSerializer](./xmlserializer.md) — ExpandedWrapper gadget for XamlReader
- [Cerealizer — JSON.NET + WindowsIdentity](./cerealizer.md) — JSON.NET TypeNameHandling + WindowsIdentity gadget, reverse-engineered AES token
