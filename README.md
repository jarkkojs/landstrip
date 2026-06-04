# landstrip

`landstrip` runs a command in a Linux OS-level sandbox using Landlock LSM in
Linux, and Seatbelt in macOS.  It accepts the Anthropic Sandbox Runtime JSON
subset as the policy.

Backends compared:

| Area         | macOS                    | Linux                        |
| ------------ | ------------------------ | -----------------------------|
| Policy       | path based rules         | file based rules             |
| Timing       | dynamic subset of paths  | file based static ruleset    |
| TCP          | localhost proxy ports    | loopback proxy ports         |
| Unix sockets | allowlist                | allowlist via seccomp broker |

## Licensing

`landstrip` is licensed under `LGPL-2.1-or-later`.
