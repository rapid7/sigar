dnl ... hmm ... we have to duplicate the data below again
AC_INIT(libsigar, 1.6.2)
AC_CONFIG_SRCDIR(src/sigar.c)
dnl AC_CONFIG_HEADERS(src/config.h)
AM_INIT_AUTOMAKE([foreign])
AC_CANONICAL_HOST

dnl for sigar_version_autoconf.c.in
VERSION_MAJOR=1
VERSION_MINOR=6
VERSION_MAINT=2
VERSION_BUILD=0

AC_SUBST(VERSION_MAJOR)
AC_SUBST(VERSION_MINOR)
AC_SUBST(VERSION_MAINT)
AC_SUBST(VERSION_BUILD)

AC_PROG_CC
AC_PROG_CXX
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

CFLAGS="$CFLAGS -Wall"

AC_MSG_CHECKING([for os type ($host_os)])
FRAMEWORK=
case $host_os in
     *aix*)
     SRC_OS="aix"
     AC_DEFINE(SIGAR_TEST_OS_AIX, [1], [for the tests])
     LIBS="-lodm -lcfg -lperfstat -lpthreads"
     ;;
     *darwin*)
     SRC_OS="darwin"
     AC_DEFINE(DARWIN,[],[running on MacOS X])
     AC_DEFINE(SIGAR_TEST_OS_DARWIN, [1], [for the tests])
     SIGAR_LIBS="-framework IOKit -framework CoreServices"
     ;;
     *netbsd*)
     SRC_OS="netbsd"
     AC_DEFINE(SIGAR_TEST_OS_DARWIN, [1], [for the tests])
     SIGAR_LIBS="-lkvm"
     ;;
     *openbsd*)
     SRC_OS="openbsd"
     AC_DEFINE(SIGAR_TEST_OS_DARWIN, [1], [for the tests])
     SIGAR_LIBS="-lkvm"
     ;;
     *freebsd*)
     SRC_OS="freebsd"
     AC_DEFINE(SIGAR_TEST_OS_DARWIN, [1], [for the tests])
     SIGAR_LIBS="-lkvm"
     ;;
     *hpux*)
     AC_DEFINE(SIGAR_HPUX,[],[running on HPUX])
     SRC_OS="hpux"
     AC_DEFINE(SIGAR_TEST_OS_HPUX, [1], [for the tests])
     SIGAR_LIBS="-lnm -lnsl"
     ;;
     *linux*)
     SRC_OS="linux"
     AC_DEFINE(SIGAR_TEST_OS_LINUX, [1], [for the tests])
      CFLAGS="$CFLAGS -D_DEFAULT_SOURCE -D_GNU_SOURCE"
     ;;
     *solaris*)
     AC_DEFINE(SOLARIS,[],[running on Solaris])
     SRC_OS="solaris"
     AC_DEFINE(SIGAR_TEST_OS_SOLARIS, [1], [for the tests])
     SIGAR_LIBS="-lkstat -lsocket -lnsl"
     ;;
     *mingw*)
     SRC_OS="win32"
     AC_DEFINE(SIGAR_TEST_OS_WIN32, [1], [for the tests])
     SIGAR_LIBS="-lws2_32 -liphlpapi -lnetapi32 -lversion -lole32 -loleaut32"
	 AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <windows.h>
#include <ole2.h>
#include <initguid.h>
#include <wbemcli.h>
]], [[
GUID i = {0}, j = CLSID_WbemLocator; return memcmp(&i, &j, sizeof(i));
]])],
        [ AC_DEFINE([HAVE_WBEMLOCATOR], [1], []) ],
        [],
     )
     ;;
     *)
     ac_system="unknown"
esac
AC_MSG_RESULT([$SRC_OS])

AC_CHECK_HEADERS(utmp.h utmpx.h libproc.h valgrind/valgrind.h libdlpi.h rpc/rpc.h)
if test $ac_cv_header_libproc_h = yes; then
        AC_DEFINE(DARWIN_HAS_LIBPROC_H, [1], [sigar named them DARWIN_HAS_... instead of HAVE_])
fi

AC_SEARCH_LIBS(dlpi_open, dlpi)

AM_CPPFLAGS="-I\$(top_srcdir)/include -I\$(top_srcdir)/src/os/$SRC_OS $SIGAR_AM_CPPFLAGS"

AC_SUBST(SRC_OS)
AC_SUBST(AM_CPPFLAGS)
AC_SUBST(SIGAR_LIBS)

AM_CONDITIONAL(OS_WIN32, test x$SRC_OS = xwin32)
AM_CONDITIONAL(OS_MACOSX, test x$SRC_OS = xdarwin)
AM_CONDITIONAL(OS_NETBSD, test x$SRC_OS = xnetbsd)
AM_CONDITIONAL(OS_OPENBSD, test x$SRC_OS = xopenbsd)
AM_CONDITIONAL(OS_FREEBSD, test x$SRC_OS = xfreebsd)
AM_CONDITIONAL(OS_LINUX, test x$SRC_OS = xlinux)
AM_CONDITIONAL(OS_HPUX, test x$SRC_OS = xhpux)
AM_CONDITIONAL(OS_AIX, test x$SRC_OS = xaix)
AM_CONDITIONAL(OS_SOLARIS, test x$SRC_OS = xsolaris)

AC_ARG_WITH(valgrind, [AC_HELP_STRING(
		       [--with-valgrind[=binary]],
		       [run the tests in valgrind to check for mem-leaks]
		       )],
	     [],
	     [with_valgrind=no])
AS_IF([test "x$with_valgrind" != xno],
      [AS_IF([test "x$with_valgrind" = xyes],
	     [AC_CHECK_PROG(VALGRIND, valgrind)
	      AS_IF([test "x$VALGRIND" = x],
		    [AC_MSG_ERROR("--with-valgrind ... but no valgrind found")])
	     ],
	     [VALGRIND="$with_valgrind"
	      AC_SUBST(VALGRIND)])
      ])
AM_CONDITIONAL(USE_VALGRIND, test "x$VALGRIND" != x)

dnl Check for lua
AC_ARG_WITH(lua, AC_HELP_STRING([--with-lua],[lua]),
[WITH_LUA=$withval],[WITH_LUA=no])
AC_MSG_CHECKING(if with lua)
AS_IF([ test "x$WITH_LUA" != "xno" ],
      [ AC_MSG_ERROR([Building with LUA is disabled])
if test "$WITH_LUA" != "no"; then
 # try pkgconfig
 if test "$WITH_LUA" = "yes"; then
    LUAPC=lua
  else
    LUAPC=$WITH_LUA
  fi
# PKG_CHECK_MODULES(LUA, $LUAPC >= 5.1, [
#   AC_DEFINE([HAVE_LUA], [1], [liblua])
#   AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
# ],[
#   PKG_CHECK_MODULES(LUA, lua5.1 >= 5.1, [
#     AC_DEFINE([HAVE_LUA], [1], [liblua])
#     AC_DEFINE([HAVE_LUA_H], [1], [lua.h])
#   ],[WITH_LUA=no])
# ])
fi
])
AC_MSG_RESULT($WITH_LUA)
AC_SUBST(LUA_CFLAGS)
AC_SUBST(LUA_LIBS)
AM_CONDITIONAL([BUILD_LUA],[test "$WITH_LUA" != "no"])

AC_CONFIG_FILES([
Makefile
include/Makefile
src/Makefile
src/os/Makefile
src/os/aix/Makefile
src/os/darwin/Makefile
src/os/freebsd/Makefile
src/os/netbsd/Makefile
src/os/openbsd/Makefile
src/os/hpux/Makefile
src/os/linux/Makefile
src/os/solaris/Makefile
src/os/win32/Makefile
examples/Makefile
src/sigar_version_autoconf.c
tests/Makefile
bindings/Makefile
bindings/lua/Makefile
])

AC_OUTPUT
