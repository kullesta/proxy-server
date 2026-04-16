# proxy-server
This is a proxy server for windows and linux. You can have username and password. You can also block websites and use ip_blacklist ip_whitelist for clients

# Proxy Server

This project is a small proxy server implementation that works on both Windows and Linux.

## Features

- Supports username/password authentication for proxy clients
- Supports IP whitelist and blacklist for client access control
- Supports wildcard IP patterns like `*.*.*.*`, `192.*.*.*`, `192.0.*.*`, `192.0.0.*`, `46.15.*.*`
- Periodically enforces whitelist/blacklist rules on connected clients
- Can block websites based on configured blocked hosts
- Configurable via `config.ini`

## Files

- `proxy.c` - Windows proxy server implementation
- `proxylinux.c` - Linux proxy server implementation
- `config.ini` - main configuration file
- `ip_whitelist.txt` - client IP whitelist
- `ip_blacklist.txt` - client IP blacklist
- `blocked.txt` - blocked host/site list

## Usage

1. Enable whitelist or blacklist in `config.ini`.
2. Add allowed client IPs to `ip_whitelist.txt` or blocked IPs to `ip_blacklist.txt`.
3. Add blocked websites to `blocked.txt`.
4. Start the proxy server.
5. Use commands like `enableipwhite`, `disableipwhite`, `enableipblack`, `disableipblack`, `setstats <s>` and `setkick <s>`.

## Notes

- The proxy can only filter by IP patterns and blocked host entries.
- It does not automatically detect country-based IP ranges; you must add the desired IP ranges manually.
- Works as a proxy server for both Windows and Linux builds.
