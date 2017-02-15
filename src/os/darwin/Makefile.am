AM_CPPFLAGS = @AM_CPPFLAGS@

SIGAR_OS_SRCS=\
	darwin_sigar.c
SIGAR_OS_HDRS=\
	sigar_os.h \
	if_types.h \
	tcp_fsm.h

if OS_MACOSX
noinst_LTLIBRARIES = libsigar_os.la

libsigar_os_la_SOURCES = ${SIGAR_OS_SRCS}

noinst_HEADERS = ${SIGAR_OS_HDRS}
else
EXTRA_DIST=\
	${SIGAR_OS_SRCS} \
	${SIGAR_OS_HDRS}
endif
