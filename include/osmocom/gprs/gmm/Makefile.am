noinst_HEADERS = \
	gmm_ms_fsm.h \
	gmm_private.h \
	gmm_pdu.h \
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

gmm_HEADERS = \
	gmm.h \
	gmm_prim.h \
	version.h \
	$(NULL)

gmmdir = $(includedir)/osmocom/gprs/gmm
