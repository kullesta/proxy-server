# Security Policy

## Supported Versions

This repository currently supports the Windows proxy implementation (`proxy.c`) and the Linux proxy implementation (`proxylinux.c`).

## Reporting a Vulnerability

If you discover a security issue in this project, please report it privately and avoid disclosing it publicly until a fix is available.

## Security Considerations

- The proxy requires configuration for username/password authentication. Ensure credentials are strong and changed regularly.
- The whitelist and blacklist functionality is based on IP address patterns. Do not rely on this as a substitute for secure authentication.
- Blocked host filtering is simple and may not catch all variants of a website or URL.
- Do not expose the proxy directly to untrusted public networks unless properly secured.
- Keep the system and compiler toolchain updated on both Windows and Linux.

## Best Practices

- Use TLS-protected channels where possible around the proxy.
- Protect `config.ini`, `ip_whitelist.txt`, `ip_blacklist.txt`, and `blocked.txt` with proper file permissions.
- Monitor logs for unusual access or repeated authentication failures.
- Regularly review and update whitelist/blacklist entries.
