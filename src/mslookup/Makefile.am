# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=1:1:1

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -fPIC -Wall $(PCSC_CFLAGS) $(TALLOC_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

if ENABLE_MSLOOKUP

noinst_HEADERS = \
	mdns_internal.h \
	$(NULL)

lib_LTLIBRARIES = libosmomslookup.la

libosmomslookup_la_SOURCES = \
	mdns.c \
	mdns_sock.c \
	mslookup.c \
	mslookup_client.c \
	mslookup_client_mdns.c \
	mslookup_client_fake.c \
	mslookup_client_simple_api.c \
	$(NULL)

libosmomslookup_la_LDFLAGS = -version-info $(LIBVERSION)
libosmomslookup_la_LIBADD = \
	$(top_builddir)/src/libosmocore.la \
	$(top_builddir)/src/gsm/libosmogsm.la \
	$(TALLOC_LIBS)
endif
