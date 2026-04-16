Proxy Server Readme
===================

This proxy server provides a simple HTTP/HTTPS proxy with authentication,
host blocking, and client IP blacklist/whitelist support.

Configuration files and runtime files:
  config.ini       - proxy settings (username, password, bind IP, port, status interval)
  proxy.log         - runtime log file with timestamps
  blocked.txt       - blocked host/domain list
  ip_blacklist.txt  - blocked client IP list (supports wildcard patterns)
  ip_whitelist.txt  - allowed client IP list (supports wildcard patterns)
  readme.txt        - this file

Command examples:
  help               - show available commands
  stats              - show current connection stats
  list               - list active connections
  clear              - clear the console and refresh stats
  addblocked <host>  - block a host, domain, or site
  rmblocked <host>   - remove a blocked host/domain/site
  addipblack <ip>    - add a client IP or pattern to the blacklist
  rmipblack <ip>     - remove a client IP from the blacklist
  addipwhite <ip>    - add a client IP or pattern to the whitelist
  rmipwhite <ip>     - remove a client IP from the whitelist
  enableipblack      - enable client IP blacklist checking
  disableipblack     - disable client IP blacklist checking
  enableipwhite      - enable client IP whitelist checking
  disableipwhite     - disable client IP whitelist checking
  setstats <seconds> - set stats refresh interval
  reload             - reload configuration and lists from disk
  resetconfig        - reset settings and lists to default values
  exit               - stop the proxy server

IP list format:
  - Use IPv4 addresses like 192.168.1.100
  - Use wildcard patterns like 192.168.1.*
  - Comments and empty lines are ignored

If whitelist mode is enabled, only IPs in ip_whitelist.txt are allowed.
If blacklist mode is enabled, IPs in ip_blacklist.txt are blocked.
