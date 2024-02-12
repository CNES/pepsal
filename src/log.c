#include "log.h"
#include "pepdefs.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int DEBUG = 0;

void __pep_error(const char* function, int line, const char* fmt, ...)
{
    va_list ap;
    char buf[PEP_ERRBUF_SZ];
    int err = errno;
    size_t len;

    va_start(ap, fmt);

    len = snprintf(buf, PEP_ERRBUF_SZ, "[ERROR]: ");
    len += vsnprintf(buf + len, PEP_ERRBUF_SZ - len, fmt, ap);
    if (err && (PEP_ERRBUF_SZ - len) > 1) {
        snprintf(buf + len,
            PEP_ERRBUF_SZ - len,
            "\n      ERRNO: [%s:%d]",
            strerror(err),
            err);
    }

    fprintf(stderr, "%s\n         AT: %s:%d\n", buf, function, line);
    va_end(ap);
#ifndef DISABLE_SYSLOG
    closelog();
#endif
    exit(EXIT_FAILURE);
}

void __pep_warning(const char* function, int line, const char* fmt, ...)
{
    va_list ap;
    char buf[PEP_ERRBUF_SZ];
    size_t len;

    va_start(ap, fmt);
    len = snprintf(buf, PEP_ERRBUF_SZ, "[WARNING]: ");
    if (PEP_ERRBUF_SZ - len > 1) {
        len += vsnprintf(buf + len, PEP_ERRBUF_SZ - len, fmt, ap);
    }

    fprintf(stderr, "%s\n       AT: %s:%d\n", buf, function, line);
    va_end(ap);
}

/*
 * Secure routine to translate a hex address in a
 * readable ip number:
 */
void toip(char* ret, const int address)
{
    int a, b, c, d;
    a = (0xFF000000 & address) >> 24;
    b = (0x00FF0000 & address) >> 16;
    c = (0x0000FF00 & address) >> 8;
    d = 0x000000FF & address;

    snprintf(ret, 16, "%d.%d.%d.%d", a, b, c, d);
}

void toip6(char* ret, const uint16_t addr[8])
{
    snprintf(ret,
        IP_ADDR_LEN,
        "%x:%x:%x:%x:%x:%x:%x:%x",
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        addr[4],
        addr[5],
        addr[6],
        addr[7]);
}

void tomac(char* ret, const uint8_t addr[6])
{
    snprintf(ret,
        MAC_ADDR_LEN,
        "%02x:%02x:%02x:%02x:%02x:%02x",
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        addr[4],
        addr[5]);
}
