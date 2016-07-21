LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@

AM_CPPFLAGS = @AM_CPPFLAGS@

noinst_PROGRAMS = cpuinfo diskinfo sysinfo sigar_ps

cpuinfo_SOURCES = cpuinfo.c
cpuinfo_LDADD = $(top_builddir)/src/libsigar.la

diskinfo_SOURCES = diskinfo.c
diskinfo_LDADD = $(top_builddir)/src/libsigar.la

sysinfo_SOURCES = sysinfo.c
sysinfo_LDADD = $(top_builddir)/src/libsigar.la

sigar_ps_SOURCES = sigar_ps.c
sigar_ps_LDADD = $(top_builddir)/src/libsigar.la
