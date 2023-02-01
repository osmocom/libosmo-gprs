/* TBF, 3GPP TS 44.060 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

struct gprs_rlcmac_entity;

enum gprs_rlcmac_tbf_direction {
	GPRS_RLCMAC_TBF_DIR_DL,
	GPRS_RLCMAC_TBF_DIR_UL
};

struct gprs_rlcmac_tbf {
	struct gprs_rlcmac_entity *gre; /* backpointer */
	enum gprs_rlcmac_tbf_direction direction;
	const char *name;
	uint8_t nr; /* TBF number, separate address space for DL and UL, used to identify TBF. */

	/* Whether the TBF is EGPRS or not */
	bool is_egprs;
};

void gprs_rlcmac_tbf_constructor(struct gprs_rlcmac_tbf *tbf,
				 enum gprs_rlcmac_tbf_direction direction,
				 struct gprs_rlcmac_entity *gre);
void gprs_rlcmac_tbf_destructor(struct gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_tbf_free(struct gprs_rlcmac_tbf *tbf);
