AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

SUBDIRS = \
	include \
	src \
	tests \
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	libosmo-csn1.pc \
	libosmo-gprs-gmm.pc \
	libosmo-gprs-llc.pc \
	libosmo-gprs-rlcmac.pc \
	libosmo-gprs-sm.pc \
	libosmo-gprs-sndcp.pc \
	$(NULL)

BUILT_SOURCES = $(top_srcdir)/.version
EXTRA_DIST = \
	.version \
	README.md \
	git-version-gen \
	debian \
	$(NULL)

@RELMAKE@

$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
