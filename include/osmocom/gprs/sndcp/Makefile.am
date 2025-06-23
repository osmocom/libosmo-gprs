noinst_HEADERS = \
	comp.h \
	dcomp.h \
	pcomp.h \
	slhc.h \
	sndcp_private.h \
	xid.h \
	v42bis.h \
	v42bis_private.h \
	$(NULL)

version.h: version.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed \
		-e "s/{{VERSION}}/$$(echo '@VERSION@' | cut -d. -f1-3)/g" \
		-e "s/{{VERSION_MAJOR}}/$$(echo '@VERSION@' | cut -d. -f1)/g" \
		-e "s/{{VERSION_MINOR}}/$$(echo '@VERSION@' | cut -d. -f2)/g" \
		-e "s/{{VERSION_PATCH}}/$$(echo '@VERSION@' | cut -d. -f3)/g" \
		$< > $@

EXTRA_DIST = \
	version.h.tpl \
	$(NULL)

sndcp_HEADERS = \
	sndcp.h \
	sndcp_prim.h \
	version.h \
	$(NULL)

sndcpdir = $(includedir)/osmocom/gprs/sndcp
