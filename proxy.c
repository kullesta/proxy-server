#define FD_SETSIZE 256
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#ifndef _countof
#define _countof(x) (sizeof(x) / sizeof((x)[0]))
#endif
#ifndef _stricmp
#define _stricmp strcasecmp
#endif
#ifndef _strnicmp
#define _strnicmp strncasecmp
#endif

#pragma comment(lib, "Ws2_32.lib")

#define MAX_BUFFER 8192
#define CONFIG_FILE "config.ini"
#define LOG_FILE "proxy.log"
#define BLOCKED_FILE "blocked.txt"
#define IP_BLACKLIST_FILE "ip_blacklist.txt"
#define IP_WHITELIST_FILE "ip_whitelist.txt"

typedef struct {
    SOCKET clientSock;
    SOCKET remoteSock;
    char clientIp[64];
    int clientPort;
    char requestedHost[256];
    int state;
    int remoteConnecting;
    char initialBuffer[MAX_BUFFER];
    int initialLen;
    ULONGLONG connectStartTick;
    DWORD lastRemoteSendTick;
    int lastPingMs;
    char pendingToRemote[MAX_BUFFER];
    int pendingToRemoteLen;
    int pendingToRemotePos;
    char pendingToClient[MAX_BUFFER];
    int pendingToClientLen;
    int pendingToClientPos;
} ClientInfo;

static ClientInfo* clients = NULL;
static int clientCapacity = 0;
static char authUser[64] = "user";
static char authPass[64] = "user";
static char bindIp[64] = "0.0.0.0";
static int bindPort = 8080;
static int statusReloadSec = 10; // default 10 seconds
static int ipCheckIntervalSec = 1; // default 1 second
static int ipBlacklistEnabled = 0;
static int ipWhitelistEnabled = 0;
static volatile int running = 1;
static volatile int commandReady = 0;
static char commandBuffer[256];
static CRITICAL_SECTION commandLock;
static CRITICAL_SECTION consoleLock;
static SOCKET listenSock = INVALID_SOCKET;
static char** blockedEntries = NULL;
static int blockedCapacity = 0;
static int blockedCount = 0;
static char** ipBlacklistEntries = NULL;
static int ipBlacklistCapacity = 0;
static int ipBlacklistCount = 0;
static char** ipWhitelistEntries = NULL;
static int ipWhitelistCapacity = 0;
static int ipWhitelistCount = 0;

static int ensureClientCapacity(int minCapacity) {
    if (clientCapacity >= minCapacity) return 1;
    int newCapacity = clientCapacity ? clientCapacity * 2 : 16;
    while (newCapacity < minCapacity) newCapacity *= 2;
    ClientInfo* newList = (ClientInfo*)realloc(clients, newCapacity * sizeof(ClientInfo));
    if (!newList) return 0;
    clients = newList;
    for (int i = clientCapacity; i < newCapacity; i++) {
        clients[i].clientSock = INVALID_SOCKET;
        clients[i].remoteSock = INVALID_SOCKET;
        clients[i].clientIp[0] = '\0';
        clients[i].clientPort = 0;
        clients[i].requestedHost[0] = '\0';
        clients[i].state = 0;
        clients[i].remoteConnecting = 0;
        clients[i].initialLen = 0;
        clients[i].connectStartTick = 0;
        clients[i].lastRemoteSendTick = 0;
        clients[i].lastPingMs = 0;
        clients[i].pendingToRemoteLen = 0;
        clients[i].pendingToRemotePos = 0;
        clients[i].pendingToClientLen = 0;
        clients[i].pendingToClientPos = 0;
    }
    clientCapacity = newCapacity;
    return 1;
}

static int ensureBlockedCapacity(int minCapacity) {
    if (blockedCapacity >= minCapacity) return 1;
    int newCapacity = blockedCapacity ? blockedCapacity * 2 : 16;
    while (newCapacity < minCapacity) newCapacity *= 2;
    char** newEntries = (char**)realloc(blockedEntries, newCapacity * sizeof(char*));
    if (!newEntries) return 0;
    for (int i = blockedCapacity; i < newCapacity; i++) {
        newEntries[i] = NULL;
    }
    blockedEntries = newEntries;
    blockedCapacity = newCapacity;
    return 1;
}

static int ensureIpBlacklistCapacity(int minCapacity) {
    if (ipBlacklistCapacity >= minCapacity) return 1;
    int newCapacity = ipBlacklistCapacity ? ipBlacklistCapacity * 2 : 16;
    while (newCapacity < minCapacity) newCapacity *= 2;
    char** newEntries = (char**)realloc(ipBlacklistEntries, newCapacity * sizeof(char*));
    if (!newEntries) return 0;
    for (int i = ipBlacklistCapacity; i < newCapacity; i++) {
        newEntries[i] = NULL;
    }
    ipBlacklistEntries = newEntries;
    ipBlacklistCapacity = newCapacity;
    return 1;
}

static int ensureIpWhitelistCapacity(int minCapacity) {
    if (ipWhitelistCapacity >= minCapacity) return 1;
    int newCapacity = ipWhitelistCapacity ? ipWhitelistCapacity * 2 : 16;
    while (newCapacity < minCapacity) newCapacity *= 2;
    char** newEntries = (char**)realloc(ipWhitelistEntries, newCapacity * sizeof(char*));
    if (!newEntries) return 0;
    for (int i = ipWhitelistCapacity; i < newCapacity; i++) {
        newEntries[i] = NULL;
    }
    ipWhitelistEntries = newEntries;
    ipWhitelistCapacity = newCapacity;
    return 1;
}

static void initClients(void) {
    clientCapacity = 0;
    clients = NULL;
    ensureClientCapacity(16);
}

static void resetBlockedList(void) {
    for (int i = 0; i < blockedCount; i++) {
        free(blockedEntries[i]);
        blockedEntries[i] = NULL;
    }
    blockedCount = 0;
}

static void resetIpBlacklist(void) {
    for (int i = 0; i < ipBlacklistCount; i++) {
        free(ipBlacklistEntries[i]);
        ipBlacklistEntries[i] = NULL;
    }
    ipBlacklistCount = 0;
}

static void resetIpWhitelist(void) {
    for (int i = 0; i < ipWhitelistCount; i++) {
        free(ipWhitelistEntries[i]);
        ipWhitelistEntries[i] = NULL;
    }
    ipWhitelistCount = 0;
}

static int isInputInteractive(void) {
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (stdinHandle == INVALID_HANDLE_VALUE) return 0;
    DWORD mode;
    return GetConsoleMode(stdinHandle, &mode) != 0;
}

static int localtime_safe(const time_t* timep, struct tm* result) {
#if defined(_MSC_VER)
    return localtime_s(result, timep);
#else
    struct tm* tmp = localtime(timep);
    if (!tmp) return -1;
    *result = *tmp;
    return 0;
#endif
}

static void logMessage(const char* format, ...) {
    FILE* f = fopen(LOG_FILE, "a");
    if (!f) return;
    time_t t = time(NULL);
    struct tm tm;
    localtime_safe(&t, &tm);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(f, "[%s] ", timestr);
    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);
}

static void trimWhitespace(char* str) {
    char* start = str;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') start++;
    if (start != str) memmove(str, start, strlen(start) + 1);
    char* end = str + strlen(str) - 1;
    while (end >= str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) *end-- = '\0';
}

static void safeCopy(char* dst, size_t size, const char* src) {
    if (!dst || size == 0) return;
    if (!src) src = "";
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

static int parseBoolean(const char* value) {
    if (!value) return 0;
    if (_stricmp(value, "1") == 0 || _stricmp(value, "true") == 0 || _stricmp(value, "yes") == 0 || _stricmp(value, "on") == 0) return 1;
    if (_stricmp(value, "0") == 0 || _stricmp(value, "false") == 0 || _stricmp(value, "no") == 0 || _stricmp(value, "off") == 0) return 0;
    return -1;
}

static void ensureFileExists(const char* path) {
    FILE* f = fopen(path, "a");
    if (f) {
        fclose(f);
        return;
    }
    remove(path);
    f = fopen(path, "w");
    if (f) fclose(f);
}

static void createReadmeFile(void) {
    DWORD attrs = GetFileAttributesA("README.txt");
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (GetFileAttributesA("readme.txt") == INVALID_FILE_ATTRIBUTES) {
            MoveFileA("README.txt", "readme.txt");
        } else {
            DeleteFileA("README.txt");
        }
    }
    attrs = GetFileAttributesA("readme.txt");
    if (attrs != INVALID_FILE_ATTRIBUTES) return;
    FILE* f = fopen("readme.txt", "w");
    if (!f) return;
    fprintf(f, "Proxy Server Readme\n");
    fprintf(f, "===================\n\n");
    fprintf(f, "This proxy server provides a simple HTTP/HTTPS proxy with authentication,\n");
    fprintf(f, "host blocking, and client IP blacklist/whitelist support.\n\n");
    fprintf(f, "Configuration files and runtime files:\n");
    fprintf(f, "  config.ini       - proxy settings (username, password, bind IP, port, status interval)\n");
    fprintf(f, "  proxy.log         - runtime log file with timestamps\n");
    fprintf(f, "  blocked.txt       - blocked host/domain list\n");
    fprintf(f, "  ip_blacklist.txt  - blocked client IP list (supports wildcard patterns)\n");
    fprintf(f, "  ip_whitelist.txt  - allowed client IP list (supports wildcard patterns)\n");
    fprintf(f, "  readme.txt        - this file\n\n");
    fprintf(f, "Command examples:\n");
    fprintf(f, "  help               - show available commands\n");
    fprintf(f, "  stats              - show current connection stats\n");
    fprintf(f, "  list               - list active connections\n");
    fprintf(f, "  clear              - clear the console and refresh stats\n");
    fprintf(f, "  addblocked <host>  - block a host, domain, or site\n");
    fprintf(f, "  rmblocked <host>   - remove a blocked host/domain/site\n");
    fprintf(f, "  addipblack <ip>    - add a client IP or pattern to the blacklist\n");
    fprintf(f, "  rmipblack <ip>     - remove a client IP from the blacklist\n");
    fprintf(f, "  addipwhite <ip>    - add a client IP or pattern to the whitelist\n");
    fprintf(f, "  rmipwhite <ip>     - remove a client IP from the whitelist\n");
    fprintf(f, "  enableipblack      - enable client IP blacklist checking\n");
    fprintf(f, "  disableipblack     - disable client IP blacklist checking\n");
    fprintf(f, "  enableipwhite      - enable client IP whitelist checking\n");
    fprintf(f, "  disableipwhite     - disable client IP whitelist checking\n");
    fprintf(f, "  setstats <seconds> - set stats refresh interval\n");
    fprintf(f, "  reload             - reload configuration and lists from disk\n");
    fprintf(f, "  resetconfig        - reset settings and lists to default values\n");
    fprintf(f, "  exit               - stop the proxy server\n\n");
    fprintf(f, "IP list format:\n");
    fprintf(f, "  - Use IPv4 addresses like 192.168.1.100\n");
    fprintf(f, "  - Use wildcard patterns like 192.168.1.*\n");
    fprintf(f, "  - Comments and empty lines are ignored\n\n");
    fprintf(f, "If whitelist mode is enabled, only IPs in ip_whitelist.txt are allowed.\n");
    fprintf(f, "If blacklist mode is enabled, IPs in ip_blacklist.txt are blocked.\n");
    fclose(f);
}

static void saveBlockedList(void) {
    FILE* f = fopen(BLOCKED_FILE, "w");
    if (!f) {
        logMessage("ERROR: Failed to write blocked list file %s", BLOCKED_FILE);
        return;
    }
    fprintf(f, "# blocked domains / IPs / websites - one entry per line\n");
    fprintf(f, "# example: example.com\n");
    fprintf(f, "# example: 1.2.3.4\n");
    fprintf(f, "# example: facebook.com\n");
    for (int i = 0; i < blockedCount; i++) {
        fprintf(f, "%s\n", blockedEntries[i]);
    }
    fclose(f);
}

static int findBlockedEntry(const char* entry) {
    if (!entry || !*entry) return -1;
    for (int i = 0; i < blockedCount; i++) {
        if (_stricmp(blockedEntries[i], entry) == 0) return i;
    }
    return -1;
}

static int matchesBlockedEntry(const char* host, const char* entry) {
    int hostLen = (int)strlen(host);
    int entryLen = (int)strlen(entry);
    if (entryLen == 0 || hostLen == 0) return 0;
    if (_stricmp(host, entry) == 0) return 1;
    if (hostLen > entryLen && _stricmp(host + hostLen - entryLen, entry) == 0) {
        if (host[hostLen - entryLen - 1] == '.') return 1;
    }
    return 0;
}

static int findStringEntry(char** entries, int count, const char* entry) {
    if (!entry || !*entry) return -1;
    for (int i = 0; i < count; i++) {
        if (_stricmp(entries[i], entry) == 0) return i;
    }
    return -1;
}

static int matchesIpPattern(const char* ip, const char* pattern) {
    if (!ip || !pattern) return 0;
    if (*pattern == '\0') return *ip == '\0';
    if (*pattern == '*') {
        return matchesIpPattern(ip, pattern + 1) || (*ip && matchesIpPattern(ip + 1, pattern));
    }
    if (*ip == '\0') return 0;
    if (*pattern != *ip) return 0;
    return matchesIpPattern(ip + 1, pattern + 1);
}

static int findPatternEntry(char** entries, int count, const char* ip) {
    if (!ip || !*ip) return -1;
    for (int i = 0; i < count; i++) {
        if (matchesIpPattern(ip, entries[i])) return i;
    }
    return -1;
}

static int isClientIpAllowed(const char* ip) {
    if (!ip || !*ip) return 0;
    if (ipWhitelistEnabled) {
        return findPatternEntry(ipWhitelistEntries, ipWhitelistCount, ip) >= 0;
    }
    if (ipBlacklistEnabled && findPatternEntry(ipBlacklistEntries, ipBlacklistCount, ip) >= 0) return 0;
    return 1;
}

static void closeClient(int index);

static void enforceClientIpRules(void) {
    if (!ipWhitelistEnabled && !ipBlacklistEnabled) return;
    for (int i = 0; i < clientCapacity; i++) {
        if (clients[i].clientSock == INVALID_SOCKET) continue;
        if (!isClientIpAllowed(clients[i].clientIp)) {
            closeClient(i);
        }
    }
}

static void saveIpList(const char* path, char** entries, int count, const char* heading) {
    FILE* f = fopen(path, "w");
    if (!f) {
        logMessage("ERROR: Failed to write IP list file %s", path);
        return;
    }
    fprintf(f, "# %s - one IP per line\n", heading);
    fprintf(f, "# example: 192.168.1.10\n");
    fprintf(f, "# example: 192.0.0.*\n");
    fprintf(f, "# example: 10.0.0.1\n");
    for (int i = 0; i < count; i++) {
        fprintf(f, "%s\n", entries[i]);
    }
    fclose(f);
}

static void loadIpList(const char* path, char*** entriesPtr, int* countPtr, int* capacityPtr, const char* heading) {
    FILE* f = fopen(path, "r");
    if (!f) {
        if (*entriesPtr) {
            for (int i = 0; i < *countPtr; i++) {
                free((*entriesPtr)[i]);
            }
            *countPtr = 0;
        }
        ensureFileExists(path);
        saveIpList(path, *entriesPtr, *countPtr, heading);
        return;
    }
    if (*entriesPtr) {
        for (int i = 0; i < *countPtr; i++) {
            free((*entriesPtr)[i]);
        }
        *countPtr = 0;
    }
    char line[256];
    int parseError = 0;
    while (fgets(line, sizeof(line), f)) {
        trimWhitespace(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        if ((int)strlen(line) >= 256) {
            parseError = 1;
            continue;
        }
        if (*capacityPtr < *countPtr + 1) {
            int newCapacity = *capacityPtr ? *capacityPtr * 2 : 16;
            while (newCapacity < *countPtr + 1) newCapacity *= 2;
            char** newEntries = (char**)realloc(*entriesPtr, newCapacity * sizeof(char*));
            if (!newEntries) { parseError = 1; break; }
            for (int i = *capacityPtr; i < newCapacity; i++) newEntries[i] = NULL;
            *entriesPtr = newEntries;
            *capacityPtr = newCapacity;
        }
        (*entriesPtr)[*countPtr] = (char*)malloc(strlen(line) + 1);
        if (!(*entriesPtr)[*countPtr]) { parseError = 1; break; }
        strcpy((*entriesPtr)[*countPtr], line);
        (*countPtr)++;
    }
    if (ferror(f)) parseError = 1;
    fclose(f);
    if (parseError) {
        for (int i = 0; i < *countPtr; i++) free((*entriesPtr)[i]);
        *countPtr = 0;
        saveIpList(path, *entriesPtr, *countPtr, heading);
    }
}

static int isBlockedHost(const char* host) {
    if (!host || !*host) return 0;
    for (int i = 0; i < blockedCount; i++) {
        if (matchesBlockedEntry(host, blockedEntries[i])) return 1;
    }
    return 0;
}

static void loadBlockedList(void) {
    FILE* f = fopen(BLOCKED_FILE, "r");
    if (!f) {
        resetBlockedList();
        saveBlockedList();
        return;
    }
    resetBlockedList();
    char line[256];
    int parseError = 0;
    while (fgets(line, sizeof(line), f)) {
        trimWhitespace(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        if ((int)strlen(line) >= 256) {
            parseError = 1;
            continue;
        }
        if (!ensureBlockedCapacity(blockedCount + 1)) {
            parseError = 1;
            continue;
        }
        blockedEntries[blockedCount] = (char*)malloc(strlen(line) + 1);
        if (!blockedEntries[blockedCount]) {
            parseError = 1;
            continue;
        }
        strcpy(blockedEntries[blockedCount], line);
        blockedCount++;
    }
    if (ferror(f)) parseError = 1;
    fclose(f);
    if (parseError) {
        resetBlockedList();
        saveBlockedList();
    }
}

static void saveConfig(void) {
    FILE* f = fopen(CONFIG_FILE, "w");
    if (!f) {
        logMessage("ERROR: Failed to write config file %s", CONFIG_FILE);
        return;
    }
    fprintf(f, "username=%s\n", authUser);
    fprintf(f, "password=%s\n", authPass);
    fprintf(f, "ip=%s\n", bindIp);
    fprintf(f, "port=%d\n", bindPort);
    fprintf(f, "status_reload_s=%d\n", statusReloadSec);
    fprintf(f, "ip_check_interval=%d\n", ipCheckIntervalSec);
    fprintf(f, "ip_blacklist_enabled=%s\n", ipBlacklistEnabled ? "true" : "false");
    fprintf(f, "ip_whitelist_enabled=%s\n", ipWhitelistEnabled ? "true" : "false");
    fclose(f);
}

static void loadConfig(void) {
    FILE* f = fopen(CONFIG_FILE, "r");
    if (!f) {
        saveConfig();
        return;
    }
    char line[256];
    int parseError = 0;
    while (fgets(line, sizeof(line), f)) {
        char* eq = strchr(line, '=');
        if (!eq) {
            parseError = 1;
            continue;
        }
        *eq = '\0';
        char* key = line;
        char* value = eq + 1;
        trimWhitespace(key);
        trimWhitespace(value);
        if (_stricmp(key, "username") == 0) safeCopy(authUser, sizeof(authUser), value);
        else if (_stricmp(key, "password") == 0) safeCopy(authPass, sizeof(authPass), value);
        else if (_stricmp(key, "ip") == 0) safeCopy(bindIp, sizeof(bindIp), value);
        else if (_stricmp(key, "port") == 0) {
            int port = atoi(value);
            if (port <= 0 || port > 65535) {
                parseError = 1;
            } else {
                bindPort = port;
            }
        }
        else if (_stricmp(key, "status_reload_s") == 0) {
            int valueInt = atoi(value);
            if (valueInt < 0) parseError = 1;
            else statusReloadSec = valueInt;
        }
        else if (_stricmp(key, "ip_check_interval") == 0) {
            int valueInt = atoi(value);
            if (valueInt < 1) valueInt = 1;
            ipCheckIntervalSec = valueInt;
        }
        else if (_stricmp(key, "ip_blacklist_enabled") == 0) {
            int boolValue = parseBoolean(value);
            if (boolValue < 0) parseError = 1;
            else ipBlacklistEnabled = boolValue;
        }
        else if (_stricmp(key, "ip_whitelist_enabled") == 0) {
            int boolValue = parseBoolean(value);
            if (boolValue < 0) parseError = 1;
            else ipWhitelistEnabled = boolValue;
        }
    }
    if (ferror(f)) parseError = 1;
    fclose(f);
    if (parseError) {
        saveConfig();
    }
}

static SOCKET createListener(const char* ip, int port);
static void closeClient(int index);

static int reloadConfig(void) {
    char oldIp[64];
    safeCopy(oldIp, sizeof(oldIp), bindIp);
    int oldPort = bindPort;
    loadConfig();
    loadBlockedList();
    loadIpList(IP_BLACKLIST_FILE, &ipBlacklistEntries, &ipBlacklistCount, &ipBlacklistCapacity, "Client IP blacklist");
    loadIpList(IP_WHITELIST_FILE, &ipWhitelistEntries, &ipWhitelistCount, &ipWhitelistCapacity, "Client IP whitelist");
    if (_stricmp(oldIp, bindIp) != 0 || oldPort != bindPort) {
        SOCKET newSock = createListener(bindIp, bindPort);
        if (newSock == INVALID_SOCKET) {
            safeCopy(bindIp, sizeof(bindIp), oldIp);
            bindPort = oldPort;
            return 0;
        }
        closesocket(listenSock);
        listenSock = newSock;
        for (int i = 0; i < clientCapacity; i++) {
            if (clients[i].clientSock != INVALID_SOCKET) {
                clients[i].clientPort = bindPort;
            }
        }
    }
    return 1;
}

static int resetConfigToDefaults(void) {
    char oldIp[64];
    safeCopy(oldIp, sizeof(oldIp), bindIp);
    int oldPort = bindPort;
    char oldUser[64];
    char oldPass[64];
    safeCopy(oldUser, sizeof(oldUser), authUser);
    safeCopy(oldPass, sizeof(oldPass), authPass);
    int oldStatusReload = statusReloadSec;

    safeCopy(authUser, sizeof(authUser), "user");
    safeCopy(authPass, sizeof(authPass), "user");
    safeCopy(bindIp, sizeof(bindIp), "0.0.0.0");
    bindPort = 8080;
    statusReloadSec = 10;
    ipBlacklistEnabled = 0;
    ipWhitelistEnabled = 0;

    SOCKET newSock = createListener(bindIp, bindPort);
    if (newSock == INVALID_SOCKET) {
        safeCopy(bindIp, sizeof(bindIp), oldIp);
        bindPort = oldPort;
        safeCopy(authUser, sizeof(authUser), oldUser);
        safeCopy(authPass, sizeof(authPass), oldPass);
        statusReloadSec = oldStatusReload;
        return 0;
    }

    closesocket(listenSock);
    listenSock = newSock;
    for (int i = 0; i < clientCapacity; i++) {
        if (clients[i].clientSock != INVALID_SOCKET) {
            clients[i].clientPort = bindPort;
        }
    }
    saveConfig();
    resetBlockedList();
    saveBlockedList();
    resetIpBlacklist();
    saveIpList(IP_BLACKLIST_FILE, ipBlacklistEntries, ipBlacklistCount, "Client IP blacklist");
    resetIpWhitelist();
    saveIpList(IP_WHITELIST_FILE, ipWhitelistEntries, ipWhitelistCount, "Client IP whitelist");
    return 1;
}

static int flushPendingRemote(int index) {
    ClientInfo* c = &clients[index];
    if (c->remoteConnecting) return 1;
    while (c->pendingToRemotePos < c->pendingToRemoteLen) {
        int sendLen = c->pendingToRemoteLen - c->pendingToRemotePos;
        int sent = send(c->remoteSock, c->pendingToRemote + c->pendingToRemotePos, sendLen, 0);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) return 0;
            closeClient(index);
            return 0;
        }
        c->pendingToRemotePos += sent;
    }
    if (c->pendingToRemotePos >= c->pendingToRemoteLen) {
        c->pendingToRemoteLen = 0;
        c->pendingToRemotePos = 0;
    }
    return 1;
}

static int flushPendingClient(int index) {
    ClientInfo* c = &clients[index];
    while (c->pendingToClientPos < c->pendingToClientLen) {
        int sendLen = c->pendingToClientLen - c->pendingToClientPos;
        int sent = send(c->clientSock, c->pendingToClient + c->pendingToClientPos, sendLen, 0);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) return 0;
            closeClient(index);
            return 0;
        }
        c->pendingToClientPos += sent;
    }
    if (c->pendingToClientPos >= c->pendingToClientLen) {
        c->pendingToClientLen = 0;
        c->pendingToClientPos = 0;
    }
    return 1;
}

static int queueToRemote(int index, const char* data, int len) {
    ClientInfo* c = &clients[index];
    if (c->remoteConnecting) {
        if (c->pendingToRemoteLen + len > MAX_BUFFER) return 0;
        memcpy(c->pendingToRemote + c->pendingToRemoteLen, data, len);
        c->pendingToRemoteLen += len;
        return 1;
    }
    if (c->pendingToRemoteLen > 0) {
        if (!flushPendingRemote(index)) {
            if (c->pendingToRemoteLen + len > MAX_BUFFER) return 0;
            memcpy(c->pendingToRemote + c->pendingToRemoteLen, data, len);
            c->pendingToRemoteLen += len;
            return 1;
        }
    }
    while (len > 0) {
        int sent = send(c->remoteSock, data, len, 0);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                if (len > MAX_BUFFER) return 0;
                memcpy(c->pendingToRemote, data, len);
                c->pendingToRemoteLen = len;
                c->pendingToRemotePos = 0;
                return 1;
            }
            closeClient(index);
            return 0;
        }
        data += sent;
        len -= sent;
    }
    return 1;
}

static int queueToClient(int index, const char* data, int len) {
    ClientInfo* c = &clients[index];
    if (c->pendingToClientLen > 0) {
        if (!flushPendingClient(index)) {
            if (c->pendingToClientLen + len > MAX_BUFFER) return 0;
            memcpy(c->pendingToClient + c->pendingToClientLen, data, len);
            c->pendingToClientLen += len;
            return 1;
        }
    }
    while (len > 0) {
        int sent = send(c->clientSock, data, len, 0);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                if (len > MAX_BUFFER) return 0;
                memcpy(c->pendingToClient, data, len);
                c->pendingToClientLen = len;
                c->pendingToClientPos = 0;
                return 1;
            }
            closeClient(index);
            return 0;
        }
        data += sent;
        len -= sent;
    }
    return 1;
}

static int base64Decode(const char* input, unsigned char* output, int maxOut) {
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0;
    int valb = -8;
    int outLen = 0;
    for (const char* p = input; *p; p++) {
        if (*p == '=') break;
        const char* pos = strchr(alphabet, *p);
        if (!pos) continue;
        val = (val << 6) + (int)(pos - alphabet);
        valb += 6;
        if (valb >= 0) {
            if (outLen < maxOut) output[outLen] = (unsigned char)((val >> valb) & 0xFF);
            outLen++;
            valb -= 8;
        }
    }
    return outLen;
}

static const char* findSubstringCaseInsensitive(const char* haystack, const char* needle) {
    int needleLen = (int)strlen(needle);
    if (needleLen == 0) return haystack;
    for (const char* p = haystack; *p; p++) {
        if (_strnicmp(p, needle, needleLen) == 0) return p;
    }
    return NULL;
}

static int checkProxyAuth(const char* request) {
    const char* auth = findSubstringCaseInsensitive(request, "Proxy-Authorization:");
    if (!auth) return 0;
    const char* eol = strstr(auth, "\r\n");
    if (!eol) return 0;
    char header[512] = {0};
    int len = (int)(eol - auth);
    if (len <= 0 || len >= (int)sizeof(header)) return 0;
    memcpy(header, auth, len);
    header[len] = '\0';
    const char* basic = findSubstringCaseInsensitive(header, "Basic");
    if (!basic) return 0;
    basic += 5;
    while (*basic == ' ') basic++;
    unsigned char decoded[128] = {0};
    int decodedLen = base64Decode(basic, decoded, sizeof(decoded) - 1);
    if (decodedLen <= 0) return 0;
    decoded[decodedLen] = '\0';
    char expected[128];
    snprintf(expected, sizeof(expected), "%s:%s", authUser, authPass);
    return strcmp((char*)decoded, expected) == 0;
}

static void parseHostPort(const char* request, char* host, int hostSize, int* port, int* isConnect) {
    host[0] = '\0';
    *port = 80;
    *isConnect = 0;
    char method[16] = {0};
    char url[1024] = {0};
    if (sscanf(request, "%15s %1023s", method, url) < 2) return;
    if (_stricmp(method, "CONNECT") == 0) {
        *isConnect = 1;
        char* sep = strchr(url, ':');
        if (sep) {
            *sep = '\0';
            safeCopy(host, hostSize, url);
            *port = atoi(sep + 1);
            if (*port == 0) *port = 443;
        } else {
            safeCopy(host, hostSize, url);
            *port = 443;
        }
        return;
    }
    const char* hostHeader = findSubstringCaseInsensitive(request, "Host:");
    if (hostHeader) {
        hostHeader += 5;
        while (*hostHeader == ' ' || *hostHeader == '\t') hostHeader++;
        char hostLine[256] = {0};
        int i = 0;
        while (*hostHeader && *hostHeader != '\r' && *hostHeader != '\n' && i < (int)sizeof(hostLine) - 1) {
            hostLine[i++] = *hostHeader++;
        }
        hostLine[i] = '\0';
        char* sep = strchr(hostLine, ':');
        if (sep) {
            *sep = '\0';
            *port = atoi(sep + 1);
            if (*port == 0) *port = 80;
        }
        safeCopy(host, hostSize, hostLine);
        return;
    }
    if (strncmp(url, "http://", 7) == 0) {
        const char* start = url + 7;
        const char* end = strpbrk(start, ":/\r\n");
        int len = end ? (int)(end - start) : (int)strlen(start);
        if (len >= hostSize) len = hostSize - 1;
        memcpy(host, start, len);
        host[len] = '\0';
        if (end && *end == ':') {
            *port = atoi(end + 1);
            if (*port == 0) *port = 80;
        }
    }
}

static int buildRemoteRequest(const char* request, char* output, int outputSize) {
    char method[16] = {0};
    char url[1024] = {0};
    char version[16] = {0};
    const char* lineEnd = strstr(request, "\r\n");
    if (!lineEnd) return 0;
    if (sscanf(request, "%15s %1023s %15s", method, url, version) != 3) return 0;

    const char* path = url;
    if (strncmp(url, "http://", 7) == 0) {
        path = strchr(url + 7, '/');
        if (!path) path = "/";
    } else if (strncmp(url, "https://", 8) == 0) {
        path = strchr(url + 8, '/');
        if (!path) path = "/";
    }

    int written = snprintf(output, outputSize, "%s %s %s\r\n", method, path, version);
    if (written < 0 || written >= outputSize) return 0;

    const char* headerLine = lineEnd + 2;
    while (*headerLine) {
        const char* nextLine = strstr(headerLine, "\r\n");
        if (!nextLine) break;
        int lineLen = (int)(nextLine - headerLine);
        if (lineLen == 0) {
            if ((int)strlen(output) + 2 >= outputSize) return 0;
            strcat(output, "\r\n");
            headerLine = nextLine + 2;
            break;
        }
        if (_strnicmp(headerLine, "Proxy-Authorization:", 20) != 0 &&
            _strnicmp(headerLine, "Proxy-Connection:", 17) != 0) {
            if ((int)strlen(output) + lineLen + 2 >= outputSize) return 0;
            strncat(output, headerLine, lineLen);
            strcat(output, "\r\n");
        }
        headerLine = nextLine + 2;
    }
    if (*headerLine) {
        if ((int)strlen(output) + (int)strlen(headerLine) >= outputSize) return 0;
        strcat(output, headerLine);
    }
    return 1;
}

static SOCKET createListener(const char* ip, int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (addr.sin_addr.s_addr == INADDR_NONE) addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

static int setSocketNonBlocking(SOCKET sock) {
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == NO_ERROR;
}

static int addClient(SOCKET client, const struct sockaddr_in* addr) {
    const char* clientIp = inet_ntoa(addr->sin_addr);
    if (!isClientIpAllowed(clientIp)) {
        return -1;
    }
    for (int i = 0; i < clientCapacity; i++) {
        if (clients[i].clientSock == INVALID_SOCKET) {
            clients[i].clientSock = client;
            clients[i].remoteSock = INVALID_SOCKET;
            safeCopy(clients[i].clientIp, sizeof(clients[i].clientIp), clientIp);
            clients[i].clientPort = bindPort;
            clients[i].requestedHost[0] = '\0';
            clients[i].state = 0;
            clients[i].remoteConnecting = 0;
            clients[i].initialLen = 0;
            clients[i].connectStartTick = GetTickCount64();
            clients[i].lastRemoteSendTick = 0;
            clients[i].lastPingMs = 0;
            clients[i].pendingToRemoteLen = 0;
            clients[i].pendingToRemotePos = 0;
            clients[i].pendingToClientLen = 0;
            clients[i].pendingToClientPos = 0;
            setSocketNonBlocking(client);
            return i;
        }
    }
    if (!ensureClientCapacity(clientCapacity + 1)) return -1;
    int index = clientCapacity - 1;
    clients[index].clientSock = client;
    clients[index].remoteSock = INVALID_SOCKET;
    safeCopy(clients[index].clientIp, sizeof(clients[index].clientIp), inet_ntoa(addr->sin_addr));
    clients[index].clientPort = bindPort;
    clients[index].requestedHost[0] = '\0';
    clients[index].state = 0;
    clients[index].remoteConnecting = 0;
    clients[index].initialLen = 0;
    clients[index].connectStartTick = GetTickCount64();
    clients[index].lastRemoteSendTick = 0;
    clients[index].lastPingMs = 0;
    clients[index].pendingToRemoteLen = 0;
    clients[index].pendingToRemotePos = 0;
    clients[index].pendingToClientLen = 0;
    clients[index].pendingToClientPos = 0;
    setSocketNonBlocking(client);
    return index;
}

static void closeClient(int index) {
    if (index < 0 || index >= clientCapacity) return;
    if (clients[index].clientSock != INVALID_SOCKET) {
        closesocket(clients[index].clientSock);
        clients[index].clientSock = INVALID_SOCKET;
    }
    if (clients[index].remoteSock != INVALID_SOCKET) {
        closesocket(clients[index].remoteSock);
        clients[index].remoteSock = INVALID_SOCKET;
    }
    clients[index].requestedHost[0] = '\0';
    clients[index].state = 0;
    clients[index].remoteConnecting = 0;
    clients[index].initialLen = 0;
    clients[index].connectStartTick = 0;
    clients[index].lastRemoteSendTick = 0;
    clients[index].lastPingMs = 0;
    clients[index].clientPort = 0;
    clients[index].pendingToRemoteLen = 0;
    clients[index].pendingToRemotePos = 0;
    clients[index].pendingToClientLen = 0;
    clients[index].pendingToClientPos = 0;
}

static int connectRemote(int index, const char* host, int port, const char* initialRequest) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%d", port);
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, portStr, &hints, &res) != 0) return 0;
    SOCKET remote = INVALID_SOCKET;
    int connResult = SOCKET_ERROR;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
        remote = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (remote == INVALID_SOCKET) continue;
        if (!setSocketNonBlocking(remote)) {
            closesocket(remote);
            remote = INVALID_SOCKET;
            continue;
        }
        connResult = connect(remote, p->ai_addr, (int)p->ai_addrlen);
        if (connResult == 0) break;
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) break;
        closesocket(remote);
        remote = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (remote == INVALID_SOCKET) return 0;
    clients[index].remoteSock = remote;
    if (initialRequest && !queueToRemote(index, initialRequest, (int)strlen(initialRequest))) {
        closesocket(remote);
        clients[index].remoteSock = INVALID_SOCKET;
        return 0;
    }
    if (initialRequest) {
        clients[index].lastRemoteSendTick = GetTickCount();
    }
    clients[index].remoteConnecting = (connResult != 0);
    return 1;
}

static int completeRemoteConnect(int index) {
    ClientInfo* c = &clients[index];
    if (c->remoteSock == INVALID_SOCKET) return 0;
    int err = 0;
    int errLen = sizeof(err);
    if (getsockopt(c->remoteSock, SOL_SOCKET, SO_ERROR, (char*)&err, &errLen) == SOCKET_ERROR) {
        return 0;
    }
    if (err != 0) return 0;
    c->remoteConnecting = 0;
    return 1;
}

static void handleClientData(int index) {
    ClientInfo* c = &clients[index];
    if (c->pendingToRemoteLen > 0) {
        if (!flushPendingRemote(index)) return;
    }
    char buffer[MAX_BUFFER];
    int received = recv(c->clientSock, buffer, sizeof(buffer), 0);
    if (received == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return;
        closeClient(index);
        return;
    }
    if (received == 0) {
        closeClient(index);
        return;
    }
    if (c->state == 0) {
        if (c->initialLen + received >= MAX_BUFFER - 1) {
            closeClient(index);
            return;
        }
        memcpy(c->initialBuffer + c->initialLen, buffer, received);
        c->initialLen += received;
        c->initialBuffer[c->initialLen] = '\0';
        if (!strstr(c->initialBuffer, "\r\n\r\n")) return;
        if (!checkProxyAuth(c->initialBuffer)) {
            const char* authFail = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nContent-Length: 0\r\n\r\n";
            send(c->clientSock, authFail, (int)strlen(authFail), 0);
            closeClient(index);
            return;
        }
        char host[256] = {0};
        int port = 80;
        int isConnect = 0;
        parseHostPort(c->initialBuffer, host, sizeof(host), &port, &isConnect);
        if (host[0] == '\0') {
            const char* badReq = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            send(c->clientSock, badReq, (int)strlen(badReq), 0);
            closeClient(index);
            return;
        }
        safeCopy(c->requestedHost, sizeof(c->requestedHost), host);
        if (isBlockedHost(host)) {
            const char* forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            send(c->clientSock, forbidden, (int)strlen(forbidden), 0);
            closeClient(index);
            return;
        }
        char remoteRequest[MAX_BUFFER];
        const char* requestToSend = c->initialBuffer;
        if (!isConnect) {
            if (!buildRemoteRequest(c->initialBuffer, remoteRequest, sizeof(remoteRequest))) {
                const char* badRequest = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                send(c->clientSock, badRequest, (int)strlen(badRequest), 0);
                closeClient(index);
                return;
            }
            requestToSend = remoteRequest;
        }
        if (!connectRemote(index, host, port, isConnect ? NULL : requestToSend)) {
            const char* badGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            send(c->clientSock, badGateway, (int)strlen(badGateway), 0);
            closeClient(index);
            return;
        }
        if (isConnect) {
            const char* success = "HTTP/1.1 200 Connection established\r\n\r\n";
            send(c->clientSock, success, (int)strlen(success), 0);
        }
        c->state = 1;
        return;
    }
    if (c->remoteSock != INVALID_SOCKET) {
        if (!queueToRemote(index, buffer, received)) {
            closeClient(index);
        } else {
            c->lastRemoteSendTick = GetTickCount();
        }
    }
}

static void handleRemoteData(int index) {
    ClientInfo* c = &clients[index];
    if (c->pendingToClientLen > 0) {
        if (!flushPendingClient(index)) return;
    }
    if (c->remoteSock == INVALID_SOCKET) return;
    char buffer[MAX_BUFFER];
    int received = recv(c->remoteSock, buffer, sizeof(buffer), 0);
    if (received == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return;
        closeClient(index);
        return;
    }
    if (received == 0) {
        closeClient(index);
        return;
    }
    if (c->lastRemoteSendTick != 0) {
        DWORD now = GetTickCount();
        c->lastPingMs = (int)(now - c->lastRemoteSendTick);
        c->lastRemoteSendTick = 0;
    }
    if (!queueToClient(index, buffer, received)) {
        closeClient(index);
    }
}

static void clearConsole(void) {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

static void logInfo(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    printf("[INFO] %s\n", buffer);
    logMessage("[INFO] %s", buffer);
}

static void printBanner(void) {
    printf("\n");
}

static void formatDuration(ULONGLONG ms, char* buffer, size_t bufferSize) {
    ULONGLONG seconds = ms / 1000;
    ULONGLONG hours = seconds / 3600;
    ULONGLONG minutes = (seconds % 3600) / 60;
    ULONGLONG secs = seconds % 60;
    if (hours > 0) {
        snprintf(buffer, bufferSize, "%02llu:%02llu:%02llu", hours, minutes, secs);
    } else {
        snprintf(buffer, bufferSize, "%02llu:%02llu", minutes, secs);
    }
}

static void printStatus(void) {
    EnterCriticalSection(&consoleLock);
    clearConsole();
    printf("=== Proxy Server ===\n");
    printf("Listening on %s:%d\n", bindIp, bindPort);
    printf("Auth user=%s password=%s\n", authUser, authPass);
    printf("Stats refresh interval: %d s\n", statusReloadSec);
    printf("IP check interval: %d s\n", ipCheckIntervalSec);
    printf("IP blacklist enabled: %s\n", ipBlacklistEnabled ? "true" : "false");
    printf("IP whitelist enabled: %s\n", ipWhitelistEnabled ? "true" : "false");
    printf("Command 'clear' available to refresh stats\n");
    int connected = 0;
    for (int i = 0; i < clientCapacity; i++) {
        if (clients[i].clientSock != INVALID_SOCKET) connected++;
    }
    printf("Connected clients: %d\n", connected);
    printf("Blocked entries: %d\n", blockedCount);
    printf("Client IP blacklist: %d entries\n", ipBlacklistCount);
    printf("Client IP whitelist: %d entries%s\n", ipWhitelistCount, ipWhitelistCount > 0 ? " (active)" : "");
    printf("Commands: help | stats | list | clear | listblocked | addblocked <site> | rmblocked <site> | addipblack <ip> | rmipblack <ip> | listipblack | addipwhite <ip> | rmipwhite <ip> | listipwhite | enableipblack | disableipblack | enableipwhite | disableipwhite | setuser <user> | setpass <password> | setip <ip> | setport <port> | setstats <s> | setkick <s> | reload | resetconfig | exit\n");
    printf("---------------------------------------------------------------\n");
    printf("Index | IP:Port             | Ping   | Connected | Host\n");
    printf("---------------------------------------------------------------\n");
    ULONGLONG now = GetTickCount64();
    for (int i = 0; i < clientCapacity; i++) {
        if (clients[i].clientSock == INVALID_SOCKET) continue;
        char address[64];
        char duration[16];
        snprintf(address, sizeof(address), "%s:%d", clients[i].clientIp, clients[i].clientPort);
        if (clients[i].connectStartTick != 0) {
            formatDuration(now - clients[i].connectStartTick, duration, sizeof(duration));
        } else {
            strcpy(duration, "00:00");
        }
        printf("%5d | %-21s | %5dms | %9s | %s\n", i, address, clients[i].lastPingMs, duration,
               clients[i].requestedHost[0] ? clients[i].requestedHost : "waiting...");
    }
    printf("---------------------------------------------------------------\n");
    fflush(stdout);
    LeaveCriticalSection(&consoleLock);
}

static void printStatusMessage(const char* format, ...) {
    printStatus();
    if (!format) return;
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

static void processCommand(const char* line) {
    if (!line || *line == '\0') return;
    char cmd[64] = {0};
    char arg[128] = {0};
    const char* space = strchr(line, ' ');
    if (space) {
        size_t len = (size_t)(space - line);
        if (len >= sizeof(cmd)) len = sizeof(cmd) - 1;
        memcpy(cmd, line, len);
        cmd[len] = '\0';
        safeCopy(arg, sizeof(arg), space + 1);
        trimWhitespace(arg);
    } else {
        safeCopy(cmd, sizeof(cmd), line);
    }
    if (_stricmp(cmd, "help") == 0) {
        printStatus();
        printf("Commands:\n");
        printf("  help               - show this help\n");
        printf("  stats              - show stats\n");
        printf("  list               - list connections\n");
        printf("  clear              - clear console and refresh stats\n");
        printf("  addblocked <host>  - add a blocked domain/IP/site\n");
        printf("  rmblocked <host>   - remove a blocked domain/IP/site\n");
        printf("  listblocked        - show blocked entries\n");
        printf("  addipblack <ip>    - add a client IP to blacklist\n");
        printf("  rmipblack <ip>     - remove a client IP from blacklist\n");
        printf("  listipblack        - show client IP blacklist\n");
        printf("  addipwhite <ip>    - add a client IP to whitelist\n");
        printf("  rmipwhite <ip>     - remove a client IP from whitelist\n");
        printf("  listipwhite        - show client IP whitelist\n");
        printf("  enableipblack       - enable client IP blacklist\n");
        printf("  disableipblack      - disable client IP blacklist\n");
        printf("  enableipwhite       - enable client IP whitelist\n");
        printf("  disableipwhite      - disable client IP whitelist\n");
        printf("  setuser <name>       - set proxy username\n");
        printf("  setpass <password>   - set proxy password\n");
        printf("  setip <ip>           - change bind IP\n");
        printf("  setport <port>       - change bind port\n");
        printf("  setstats <s>        - set stats refresh interval in seconds\n");
        printf("  setkick <s>         - set IP rule enforcement interval in seconds\n");
        printf("  reload              - reload config and blocked list from files\n");
        printf("  resetconfig         - restore all config and blocked list to defaults\n");
        printf("  exit                 - stop the server\n");
        return;
    }
    if (_stricmp(cmd, "stats") == 0 || _stricmp(cmd, "status") == 0 || _stricmp(cmd, "list") == 0 || _stricmp(cmd, "clear") == 0) {
        printStatus();
        return;
    }
    if (_stricmp(cmd, "addblocked") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: addblocked <host>");
            return;
        }
        if (findBlockedEntry(arg) >= 0) {
            printStatusMessage("Entry already blocked: %s", arg);
            return;
        }
        if (!ensureBlockedCapacity(blockedCount + 1)) {
            printStatusMessage("Failed to allocate blocked list entry");
            return;
        }
        blockedEntries[blockedCount] = (char*)malloc(strlen(arg) + 1);
        if (!blockedEntries[blockedCount]) {
            printStatusMessage("Failed to allocate blocked list entry");
            return;
        }
        strcpy(blockedEntries[blockedCount], arg);
        blockedCount++;
        saveBlockedList();
        printStatusMessage("Blocked entry added: %s", arg);
        return;
    }
    if (_stricmp(cmd, "rmblocked") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: rmblocked <host>");
            return;
        }
        int index = findBlockedEntry(arg);
        if (index < 0) {
            printStatusMessage("Blocked entry not found: %s", arg);
            return;
        }
        free(blockedEntries[index]);
        for (int i = index; i < blockedCount - 1; i++) {
            blockedEntries[i] = blockedEntries[i + 1];
        }
        blockedEntries[blockedCount - 1] = NULL;
        blockedCount--;
        saveBlockedList();
        printStatusMessage("Blocked entry removed: %s", arg);
        return;
    }
    if (_stricmp(cmd, "listblocked") == 0) {
        printStatus();
        if (blockedCount == 0) {
            printf("No blocked entries.\n");
            return;
        }
        printf("Blocked entries (%d):\n", blockedCount);
        for (int i = 0; i < blockedCount; i++) {
            printf("  %d: %s\n", i + 1, blockedEntries[i]);
        }
        return;
    }
    if (_stricmp(cmd, "addipblack") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: addipblack <ip>");
            return;
        }
        if (findStringEntry(ipBlacklistEntries, ipBlacklistCount, arg) >= 0) {
            printStatusMessage("Client IP already blacklisted: %s", arg);
            return;
        }
        if (!ensureIpBlacklistCapacity(ipBlacklistCount + 1)) {
            printStatusMessage("Failed to allocate IP blacklist entry");
            return;
        }
        ipBlacklistEntries[ipBlacklistCount] = (char*)malloc(strlen(arg) + 1);
        if (!ipBlacklistEntries[ipBlacklistCount]) {
            printStatusMessage("Failed to allocate IP blacklist entry");
            return;
        }
        strcpy(ipBlacklistEntries[ipBlacklistCount], arg);
        ipBlacklistCount++;
        saveIpList(IP_BLACKLIST_FILE, ipBlacklistEntries, ipBlacklistCount, "Client IP blacklist");
        printStatusMessage("Client IP blacklisted: %s", arg);
        return;
    }
    if (_stricmp(cmd, "rmipblack") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: rmipblack <ip>");
            return;
        }
        int index = findStringEntry(ipBlacklistEntries, ipBlacklistCount, arg);
        if (index < 0) {
            printStatusMessage("Client IP not found in blacklist: %s", arg);
            return;
        }
        free(ipBlacklistEntries[index]);
        for (int i = index; i < ipBlacklistCount - 1; i++) {
            ipBlacklistEntries[i] = ipBlacklistEntries[i + 1];
        }
        ipBlacklistEntries[ipBlacklistCount - 1] = NULL;
        ipBlacklistCount--;
        saveIpList(IP_BLACKLIST_FILE, ipBlacklistEntries, ipBlacklistCount, "Client IP blacklist");
        printStatusMessage("Client IP removed from blacklist: %s", arg);
        return;
    }
    if (_stricmp(cmd, "listipblack") == 0) {
        printStatus();
        if (ipBlacklistCount == 0) {
            printf("No client IPs blacklisted.\n");
            return;
        }
        printf("Client IP blacklist (%d):\n", ipBlacklistCount);
        for (int i = 0; i < ipBlacklistCount; i++) {
            printf("  %d: %s\n", i + 1, ipBlacklistEntries[i]);
        }
        return;
    }
    if (_stricmp(cmd, "addipwhite") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: addipwhite <ip>");
            return;
        }
        if (findStringEntry(ipWhitelistEntries, ipWhitelistCount, arg) >= 0) {
            printStatusMessage("Client IP already whitelisted: %s", arg);
            return;
        }
        if (!ensureIpWhitelistCapacity(ipWhitelistCount + 1)) {
            printStatusMessage("Failed to allocate IP whitelist entry");
            return;
        }
        ipWhitelistEntries[ipWhitelistCount] = (char*)malloc(strlen(arg) + 1);
        if (!ipWhitelistEntries[ipWhitelistCount]) {
            printStatusMessage("Failed to allocate IP whitelist entry");
            return;
        }
        strcpy(ipWhitelistEntries[ipWhitelistCount], arg);
        ipWhitelistCount++;
        saveIpList(IP_WHITELIST_FILE, ipWhitelistEntries, ipWhitelistCount, "Client IP whitelist");
        printStatusMessage("Client IP whitelisted: %s", arg);
        return;
    }
    if (_stricmp(cmd, "rmipwhite") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: rmipwhite <ip>");
            return;
        }
        int index = findStringEntry(ipWhitelistEntries, ipWhitelistCount, arg);
        if (index < 0) {
            printStatusMessage("Client IP not found in whitelist: %s", arg);
            return;
        }
        free(ipWhitelistEntries[index]);
        for (int i = index; i < ipWhitelistCount - 1; i++) {
            ipWhitelistEntries[i] = ipWhitelistEntries[i + 1];
        }
        ipWhitelistEntries[ipWhitelistCount - 1] = NULL;
        ipWhitelistCount--;
        saveIpList(IP_WHITELIST_FILE, ipWhitelistEntries, ipWhitelistCount, "Client IP whitelist");
        printStatusMessage("Client IP removed from whitelist: %s", arg);
        return;
    }
    if (_stricmp(cmd, "listipwhite") == 0) {
        printStatus();
        if (ipWhitelistCount == 0) {
            printf("No client IPs whitelisted.\n");
            return;
        }
        printf("Client IP whitelist (%d):\n", ipWhitelistCount);
        for (int i = 0; i < ipWhitelistCount; i++) {
            printf("  %d: %s\n", i + 1, ipWhitelistEntries[i]);
        }
        return;
    }
    if (_stricmp(cmd, "enableipblack") == 0) {
        ipBlacklistEnabled = 1;
        saveConfig();
        printStatusMessage("IP blacklist enabled");
        return;
    }
    if (_stricmp(cmd, "disableipblack") == 0) {
        ipBlacklistEnabled = 0;
        saveConfig();
        printStatusMessage("IP blacklist disabled");
        return;
    }
    if (_stricmp(cmd, "enableipwhite") == 0) {
        ipWhitelistEnabled = 1;
        saveConfig();
        printStatusMessage("IP whitelist enabled");
        return;
    }
    if (_stricmp(cmd, "disableipwhite") == 0) {
        ipWhitelistEnabled = 0;
        saveConfig();
        printStatusMessage("IP whitelist disabled");
        return;
    }
    if (_stricmp(cmd, "setuser") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: setuser <name>");
            return;
        }
        safeCopy(authUser, sizeof(authUser), arg);
        saveConfig();
        printStatusMessage("Username set");
        return;
    }
    if (_stricmp(cmd, "setpass") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: setpass <password>");
            return;
        }
        safeCopy(authPass, sizeof(authPass), arg);
        saveConfig();
        printStatusMessage("Password set");
        return;
    }
    if (_stricmp(cmd, "setip") == 0) {
        if (!arg[0]) {
            printStatusMessage("Usage: setip <ip>");
            return;
        }
        safeCopy(bindIp, sizeof(bindIp), arg);
        saveConfig();
        SOCKET newSock = createListener(bindIp, bindPort);
        if (newSock == INVALID_SOCKET) {
            printStatusMessage("Failed to bind %s:%d", bindIp, bindPort);
            return;
        }
        closesocket(listenSock);
        listenSock = newSock;
        printStatusMessage("Bind IP updated");
        return;
    }
    if (_stricmp(cmd, "setport") == 0) {
        int newPort = atoi(arg);
        if (newPort <= 0 || newPort > 65535) {
            printStatusMessage("Usage: setport <port>");
            return;
        }
        bindPort = newPort;
        saveConfig();
        SOCKET newSock = createListener(bindIp, bindPort);
        if (newSock == INVALID_SOCKET) {
            printStatusMessage("Failed to bind %s:%d", bindIp, bindPort);
            return;
        }
        closesocket(listenSock);
        listenSock = newSock;
        for (int i = 0; i < clientCapacity; i++) {
            if (clients[i].clientSock != INVALID_SOCKET) {
                clients[i].clientPort = bindPort;
            }
        }
        printStatusMessage("Bind port updated");
        return;
    }
    if (_stricmp(cmd, "setstats") == 0 || _stricmp(cmd, "setstatus") == 0) {
        int newStatusSec = atoi(arg);
        if (newStatusSec < 0) {
            printStatusMessage("Usage: setstats <s>");
            return;
        }
        statusReloadSec = newStatusSec;
        saveConfig();
        printStatusMessage("Stats refresh interval set to %d s", statusReloadSec);
        return;
    }
    if (_stricmp(cmd, "setkick") == 0) {
        int newKickSec = atoi(arg);
        if (newKickSec < 1) {
            printStatusMessage("Usage: setkick <s> (must be 1 or greater)");
            return;
        }
        ipCheckIntervalSec = newKickSec;
        saveConfig();
        printStatusMessage("IP check interval set to %d s", ipCheckIntervalSec);
        enforceClientIpRules();
        return;
    }
    if (_stricmp(cmd, "reload") == 0) {
        if (reloadConfig()) {
            printStatusMessage("Reload successful.");
        } else {
            printStatusMessage("Reload failed, keeping current configuration");
        }
        return;
    }
    if (_stricmp(cmd, "resetconfig") == 0) {
        if (resetConfigToDefaults()) {
            printStatusMessage("All configuration reverted to defaults.");
        } else {
            printStatusMessage("Failed to reset to default configuration.");
        }
        return;
    }
    if (_stricmp(cmd, "exit") == 0) {
        printStatus();
        running = 0;
        return;
    }
    printStatusMessage("Unknown command '%s'", cmd);
}

static volatile int stdinAvailable = 1;

static DWORD WINAPI commandThread(LPVOID param) {
    char line[256];
    while (running && stdinAvailable) {
        EnterCriticalSection(&consoleLock);
        printf("\n> ");
        fflush(stdout);
        LeaveCriticalSection(&consoleLock);
        if (!fgets(line, sizeof(line), stdin)) {
            stdinAvailable = 0;
            break;
        }
        trimWhitespace(line);
        if (*line == '\0') continue;
        EnterCriticalSection(&commandLock);
        safeCopy(commandBuffer, sizeof(commandBuffer), line);
        commandReady = 1;
        LeaveCriticalSection(&commandLock);
        if (_stricmp(line, "exit") == 0) break;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    InitializeCriticalSection(&commandLock);
    InitializeCriticalSection(&consoleLock);
    createReadmeFile();
    loadConfig();
    loadBlockedList();
    loadIpList(IP_BLACKLIST_FILE, &ipBlacklistEntries, &ipBlacklistCount, &ipBlacklistCapacity, "Client IP blacklist");
    loadIpList(IP_WHITELIST_FILE, &ipWhitelistEntries, &ipWhitelistCount, &ipWhitelistCapacity, "Client IP whitelist");
    ensureFileExists(LOG_FILE);
    if (argc >= 2) {
        const char* arg = argv[1];
        if (_strnicmp(arg, "--status=", 9) == 0) {
            statusReloadSec = atoi(arg + 9);
        }
    }
    printBanner();
    listenSock = createListener(bindIp, bindPort);
    if (listenSock == INVALID_SOCKET) {
        printf("Unable to bind %s:%d\n", bindIp, bindPort);
        WSACleanup();
        return 1;
    }
    logInfo("Proxy listening on %s:%d", bindIp, bindPort);
    initClients();
    DWORD lastStatusTick = GetTickCount();
    DWORD lastHourlyClearTick = lastStatusTick;
    DWORD lastIpCheckTick = lastStatusTick;
    HANDLE thread = NULL;
    if (isInputInteractive()) {
        thread = CreateThread(NULL, 0, commandThread, NULL, 0, NULL);
    }
    while (running) {
        fd_set readSet;
        fd_set writeSet;
        FD_ZERO(&readSet);
        FD_ZERO(&writeSet);
        FD_SET(listenSock, &readSet);
        SOCKET maxSock = listenSock;
        for (int i = 0; i < clientCapacity; i++) {
            if (clients[i].clientSock != INVALID_SOCKET) {
                FD_SET(clients[i].clientSock, &readSet);
                if (clients[i].clientSock > maxSock) maxSock = clients[i].clientSock;
                if (clients[i].pendingToClientLen > 0) FD_SET(clients[i].clientSock, &writeSet);
            }
            if (clients[i].remoteSock != INVALID_SOCKET) {
                FD_SET(clients[i].remoteSock, &readSet);
                if (clients[i].pendingToRemoteLen > 0 || clients[i].remoteConnecting) FD_SET(clients[i].remoteSock, &writeSet);
                if (clients[i].remoteSock > maxSock) maxSock = clients[i].remoteSock;
            }
        }
        TIMEVAL timeout = {1, 0};
        int ready = select((int)maxSock + 1, &readSet, &writeSet, NULL, &timeout);
        if (ready == SOCKET_ERROR) break;
        if (FD_ISSET(listenSock, &readSet)) {
            struct sockaddr_in addr;
            int addrLen = sizeof(addr);
            SOCKET client = accept(listenSock, (struct sockaddr*)&addr, &addrLen);
            if (client != INVALID_SOCKET) {
                if (addClient(client, &addr) < 0) closesocket(client);
            }
        }
        for (int i = 0; i < clientCapacity; i++) {
            if (clients[i].clientSock == INVALID_SOCKET) continue;
            if (clients[i].clientSock != INVALID_SOCKET && FD_ISSET(clients[i].clientSock, &writeSet)) flushPendingClient(i);
            if (clients[i].remoteSock != INVALID_SOCKET && FD_ISSET(clients[i].remoteSock, &writeSet)) {
                if (clients[i].remoteConnecting) {
                    if (!completeRemoteConnect(i)) {
                        closeClient(i);
                        continue;
                    }
                }
                flushPendingRemote(i);
            }
            if (clients[i].clientSock != INVALID_SOCKET && FD_ISSET(clients[i].clientSock, &readSet)) handleClientData(i);
            if (clients[i].remoteSock != INVALID_SOCKET && FD_ISSET(clients[i].remoteSock, &readSet)) handleRemoteData(i);
        }
        if (commandReady) {
            char line[256];
            EnterCriticalSection(&commandLock);
            safeCopy(line, sizeof(line), commandBuffer);
            commandReady = 0;
            LeaveCriticalSection(&commandLock);
            processCommand(line);
            enforceClientIpRules();
            lastStatusTick = GetTickCount();
            lastIpCheckTick = lastStatusTick;
        }
        DWORD currentTick = GetTickCount();
        if (ipCheckIntervalSec > 0 && currentTick - lastIpCheckTick >= (DWORD)ipCheckIntervalSec * 1000) {
            enforceClientIpRules();
            lastIpCheckTick = currentTick;
        }
        if (statusReloadSec > 0 && currentTick - lastStatusTick >= (DWORD)statusReloadSec * 1000) {
            printStatus();
            fflush(stdout);
            lastStatusTick = currentTick;
        }
        if (currentTick - lastHourlyClearTick >= 3600000) {
            printStatus();
            fflush(stdout);
            lastHourlyClearTick = currentTick;
        }
    }
    for (int i = 0; i < clientCapacity; i++) {
        if (clients[i].clientSock != INVALID_SOCKET) closesocket(clients[i].clientSock);
        if (clients[i].remoteSock != INVALID_SOCKET) closesocket(clients[i].remoteSock);
    }
    free(clients);
    resetBlockedList();
    free(blockedEntries);
    if (listenSock != INVALID_SOCKET) closesocket(listenSock);
    if (thread) {
        WaitForSingleObject(thread, 1000);
        CloseHandle(thread);
    }
    DeleteCriticalSection(&consoleLock);
    DeleteCriticalSection(&commandLock);
    WSACleanup();
    printf("Proxy stopped\n");
    return 0;
}
