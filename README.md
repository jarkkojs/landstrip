# landstrip

`landstrip` is a sandbox for coding agents with parametrized state based on
Landlock LSM and SECCOMP. The state is parametrized from JSON policy files,
which are compatible with the JSON format of
[Anthropic Sandbox Runtime](https://github.com/anthropic-experimental/sandbox-runtime).

Comparison to macOS/Seatbelt backend:

- Seatbelt: sandbox-exec/Seatbelt. Landstrip: Landlock + seccomp.
- Seatbelt: dynamic filesystem rules. Landstrip: snapshot at launch.
- Seatbelt: proxy ports via Seatbelt. Landstrip: loopback proxy ports
- Both accept Claude Code-style JSON subset and ignore unknown settings.

Landstrip's practical benefit is exactly this near-proximity of configuration
with Seatbelt sandbox.

## Sandbox model

### Files

`landstrip` defines filesystem configuration as a Landlock allowlist. Deny rules
are handled by traversing the directory tree and allowing only the roots that
remain after subtracting denied paths.

In other words, policy has snapshot semantics: access is based on the filesystem
objects that existed and were opened when the sandbox was created.

Landlock rules are not path-based rules. If an allowed directory is removed and
the same pathname is created again later, the new directory is a different
filesystem object and is not automatically allowed. It becomes accessible only
when an allowed ancestor rule covers it.

Directories created outside the sandbox after policy setup are not exposed
merely because their paths match a previous traversal result.

Paths use the same syntax as the macOS sandbox runtime: absolute paths,
relative paths from the current directory, `~`, and gitignore-style `*`, `**`,
`?`, and character-class globs. Glob patterns are resolved when the sandbox is
created and therefore follow the same snapshot semantics as other paths.

### Network

For TCP port rules `landstrip` uses Landlock TCP port rules and a seccomp
user-notification broker for address-level decisions. When the sandbox is
applied, direct TCP connections are denied by default.

`httpProxyPort` and `socksProxyPort` select local HTTP and SOCKS proxy ports.
Connections to these ports are allowed only on loopback addresses. `landstrip`
does not start proxies or set proxy environment variables; the caller supplies
those when needed. Domain filtering is likewise a caller/runtime responsibility.
Direct TCP remains denied except for configured proxy ports. Other settings are
ignored.

Unix domain sockets are denied by default. `allowUnixSockets` permits pathname
socket `connect` and `bind` operations under listed paths, with relative paths
resolved against the sandboxed process current directory. Abstract and unnamed
sockets, `socketpair`, and inherited descriptors are not path-mediated;
`allowAllUnixSockets` permits new Unix sockets without path checks.

## Documenting errors

The following snippet demonstrates the recommended pattern for documenting the
return values on error:

```
/// # Errors
///
/// Returns [`<variant's unqualified name>`](<variant's unqualified name>)
/// Returns ...
```

## Licensing

`landstrip` is licensed under `LGPL-2.1-or-later`.
