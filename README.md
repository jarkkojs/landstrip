# landstrip

`landstrip` runs a command in a Linux sandbox built from Landlock access control
rules and seccomp.

`landstrip` accepts the Anthropic Sandbox Runtime JSON subset used by the
macOS Seatbelt backend.

## Seatbelt and Landstrip comparison

| Area      | Seatbelt backend         | Landstrip backend          |
| --------- | ------------------------ | -------------------------- |
| Kernel    | sandbox-exec / Seatbelt  | Landlock + seccomp         |
| FS view   | host view + path rules   | host view + object rules   |
| Timing    | dynamic path checks      | launch-time snapshot       |
| Globs     | profile regex/path match | expanded at launch         |
| TCP net   | localhost proxy ports    | loopback proxy ports       |
| Proxies   | supplied by runtime      | supplied by caller/runtime |
| Unix sock | path allowlist           | path allowlist via broker  |
| Runtime   | unknown settings ignored | unknown settings ignored   |

## Licensing

`landstrip` is licensed under `LGPL-2.1-or-later`.
