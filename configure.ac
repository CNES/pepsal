#!/bin/bash

# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59e)
AC_INIT(PEPSal, 2.0.0)
AC_CONFIG_SRCDIR(src)
AC_CONFIG_HEADER(include/config.h)
AM_INIT_AUTOMAKE

#
# defines the required versions of libraries
#

# By default, generate static libraries
#AC_DISABLE_SHARED
#AC_DISABLE_STATIC

# Disable default CFLAGS set by AC_PROG_CC
: ${CFLAGS="-g3 -O0"}
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET                                                                                        
AC_PROG_RANLIB

# Checks for libraries
# if test x${check_nfqueue} = xno; then 
#    AC_MSG_RESULT([ERROR: libnetfilter-queue required])
#    exit 1
# fi
# AC_CHECK_LIB([nfnetlink], [nfnl_open],,check_nfnetlink="no")
# if test x${check_nfnetlink} = xno; then
#    AC_MSG_RESULT([ERROR: libnfnetlink required])
#    exit 1
# fi
AC_CHECK_LIB([pthread], [pthread_create],,check_pthread="no")
if test x${check_pthread} = xno; then
   AC_MSG_RESULT([ERROR: libpthread required])
   exit 1
fi
AC_CHECK_LIB([rt], [timer_create],,check_rt="no")
if test x${check_rt} = xno; then
   AC_MSG_RESULT([ERROR: librt required])
   exit 1
fi
AC_CHECK_LIB([m], [ceil],,check_m="no")
if test x${check_m} = xno; then
   AC_MSG_RESULT([ERROR: libm required])
   exit 1
fi

# Add required libraries to LDFLAGS
# [ LDFLAGS="$LDFLAGS -lnfnetlink -lpthread -lrt -lm" ]
[ LDFLAGS="$LDFLAGS -lpthread -lrt -lm" ]

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h time.h ])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname memset socket timer_create timer_settime])

AC_ARG_ENABLE(syslog,
        AC_HELP_STRING([--enable-syslog], [enable syslog logging: yes|no (default=no)]),
        [enable_syslog=$enableval],
        [enable_syslog="no"])

AC_ARG_ENABLE(stderr_logging,
        AC_HELP_STRING([--enable-stderr-logging], [enable stderr logging: yes|no (default=no)]),
        [enable_stderr=$enableval],
        [enable_stderr="no"])

AC_ARG_ENABLE(dst_in_key,
        AC_HELP_STRING([--enable-dst-in-key], [enable using dst addr:port pair in key : yes|no (default=yes)]),
        [enable_dst_in_key=$enableval],
        [enable_dst_in_key="yes"])

AC_ARG_ENABLE(debug,
        AC_HELP_STRING([--enable-debug], [enable debugging: yes|no (default=no)]),
        [enable_debug=$enableval],
        [enable_debug="no"])

AC_ARG_ENABLE(fail_on_warning,
        AC_HELP_STRING([--enable-fail-on-warning], [build fails on warnings if enabled (default=no)]),
        fail_on_warning=$enableval,
        fail_on_warning=no)
if test "x$fail_on_warning" != "xno"; then
    WERROR="-Werror"
fi

if test x${enable_debug} = xno; then
    AC_DEFINE([NDEBUG], 1, "Disable assertions")
fi

if test x${enable_syslog} != xno; then
    AC_DEFINE([ENABLE_SYSLOG], 1, "Enable using syslog for logs")
fi

if test x${enable_stderr} != xno; then
    AC_DEFINE([ENABLE_STDERR], 1, "Enable using stderr for logs")
fi

if test x${enable_dst_in_key} != xno; then
    AC_DEFINE([ENABLE_DST_IN_KEY], 1, "Enable dst in key")
fi

AC_SUBST(CFLAGS, "$CFLAGS -Wall -Wno-address-of-packed-member ${WERROR}")


AC_CONFIG_FILES(Makefile 
                src/Makefile)
AC_OUTPUT
