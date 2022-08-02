# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=0:0:0

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

lib_LTLIBRARIES = \
	libosmo-csn1.la \
	$(NULL)

libosmo_csn1_la_SOURCES = \
	csn1.c \
	csn1_enc.c \
	csn1_dec.c \
	$(NULL)

# TODO: -export-symbols-regex '^osmo_'
libosmo_csn1_la_LDFLAGS = \
	-version-info $(LIBVERSION) \
	-no-undefined \
	$(NULL)

libosmo_csn1_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)
