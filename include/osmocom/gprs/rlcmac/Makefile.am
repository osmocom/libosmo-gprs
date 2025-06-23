noinst_HEADERS = \
	codel.h \
	coding_scheme.h \
	gre.h \
	llc_queue.h \
	pdch_ul_controller.h \
	rlc.h \
	rlc_window.h \
	rlc_window_dl.h \
	rlc_window_ul.h \
	rlcmac_dec.h \
	rlcmac_enc.h \
	rlcmac_private.h \
	sched.h \
	tbf.h \
	tbf_dl.h \
	tbf_dl_fsm.h \
	tbf_ul.h \
	tbf_ul_fsm.h \
	tbf_ul_ass_fsm.h \
	tbf_dl_ass_fsm.h \
	types_private.h \
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

rlcmac_HEADERS = \
	csn1_defs.h \
	rlcmac.h \
	rlcmac_prim.h \
	types.h \
	version.h \
	$(NULL)

rlcmacdir = $(includedir)/osmocom/gprs/rlcmac
