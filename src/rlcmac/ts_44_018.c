/*
 * CSN.1 definitions from 3GPP TS 44.018.
 *
 * By Vincent Helfre, based on original code by Jari Sassi
 * with the gracious authorization of STE
 * Copyright (c) 2011 ST-Ericsson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <assert.h>
#include <arpa/inet.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/logging.h>

#include <osmocom/csn1/csn1.h>
#include <osmocom/gprs/rlcmac/gprs_rlcmac.h>

extern int g_log_cat;

CSN_DESCR_EXTERN(GPRS_Mobile_Allocation_t);
CSN_DESCR_EXTERN(PBCCH_Not_present_t);
CSN_DESCR_EXTERN(PBCCH_present_t);
CSN_DESCR_EXTERN(StartingTime_t);

/*<P1 Rest Octets>*/
/*<P2 Rest Octets>*/
#if 0
static const
CSN_DESCR_BEGIN(MobileAllocationIE_t)
  M_UINT       (MobileAllocationIE_t,  Length,  8),
  M_VAR_ARRAY  (MobileAllocationIE_t, MA, Length, 0),
CSN_DESCR_END  (MobileAllocationIE_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(SingleRFChannel_t)
  M_UINT       (SingleRFChannel_t,  spare,  2),
  M_UINT       (SingleRFChannel_t,  ARFCN,  10),
CSN_DESCR_END  (SingleRFChannel_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(RFHoppingChannel_t)
  M_UINT       (RFHoppingChannel_t,  MAIO,  6),
  M_UINT       (RFHoppingChannel_t,  HSN,  6),
CSN_DESCR_END  (RFHoppingChannel_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(MobileAllocation_or_Frequency_Short_List_t)
  M_UNION      (MobileAllocation_or_Frequency_Short_List_t, 2),
  M_BITMAP     (MobileAllocation_or_Frequency_Short_List_t, u.Frequency_Short_List, 64),
  M_TYPE       (MobileAllocation_or_Frequency_Short_List_t, u.MA, MobileAllocationIE_t),
CSN_DESCR_END  (MobileAllocation_or_Frequency_Short_List_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(Channel_Description_t)
  M_UINT       (Channel_Description_t,  Channel_type_and_TDMA_offset,  5),
  M_UINT       (Channel_Description_t,  TN,  3),
  M_UINT       (Channel_Description_t,  TSC,  3),

  M_UNION      (Channel_Description_t, 2),
  M_TYPE       (Channel_Description_t, u.SingleRFChannel, SingleRFChannel_t),
  M_TYPE       (Channel_Description_t, u.RFHoppingChannel, RFHoppingChannel_t),
CSN_DESCR_END(Channel_Description_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(Group_Channel_Description_t)
  M_TYPE       (Group_Channel_Description_t, Channel_Description, Channel_Description_t),

  M_NEXT_EXIST (Group_Channel_Description_t, Exist_Hopping, 1),
  M_TYPE       (Group_Channel_Description_t, MA_or_Frequency_Short_List, MobileAllocation_or_Frequency_Short_List_t),
CSN_DESCR_END  (Group_Channel_Description_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(Group_Call_Reference_t)
  M_UINT       (Group_Call_Reference_t,  value,  27),
  M_UINT       (Group_Call_Reference_t,  SF, 1),
  M_UINT       (Group_Call_Reference_t,  AF, 1),
  M_UINT       (Group_Call_Reference_t,  call_priority,  3),
  M_UINT       (Group_Call_Reference_t,  Ciphering_information,  4),
CSN_DESCR_END  (Group_Call_Reference_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(Group_Call_information_t)
  M_TYPE       (Group_Call_information_t, Group_Call_Reference, Group_Call_Reference_t),

  M_NEXT_EXIST (Group_Call_information_t, Exist_Group_Channel_Description, 1),
  M_TYPE       (Group_Call_information_t, Group_Channel_Description, Group_Channel_Description_t),
CSN_DESCR_END (Group_Call_information_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN  (P1_Rest_Octets_t)
  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_NLN_PCH_and_NLN_status, 2),
  M_UINT         (P1_Rest_Octets_t,  NLN_PCH,  2),
  M_UINT         (P1_Rest_Octets_t,  NLN_status,  1),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Priority1, 1),
  M_UINT         (P1_Rest_Octets_t,  Priority1,  3),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Priority2, 1),
  M_UINT         (P1_Rest_Octets_t,  Priority2,  3),

  M_NEXT_EXIST_LH(P1_Rest_Octets_t, Exist_Group_Call_information, 1),
  M_TYPE         (P1_Rest_Octets_t, Group_Call_information, Group_Call_information_t),

  M_UINT_LH      (P1_Rest_Octets_t,  Packet_Page_Indication_1,  1),
  M_UINT_LH      (P1_Rest_Octets_t,  Packet_Page_Indication_2,  1),
CSN_DESCR_END    (P1_Rest_Octets_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN  (P2_Rest_Octets_t)
  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_CN3, 1),
  M_UINT         (P2_Rest_Octets_t,  CN3,  2),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_NLN_and_status, 2),
  M_UINT         (P2_Rest_Octets_t,  NLN,  2),
  M_UINT         (P2_Rest_Octets_t,  NLN_status,  1),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority1, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority1,  3),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority2, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority2,  3),

  M_NEXT_EXIST_LH(P2_Rest_Octets_t, Exist_Priority3, 1),
  M_UINT         (P2_Rest_Octets_t,  Priority3,  3),

  M_UINT_LH      (P2_Rest_Octets_t,  Packet_Page_Indication_3,  1),
CSN_DESCR_END    (P2_Rest_Octets_t)
#endif

static const
CSN_DESCR_BEGIN(DynamicAllocation_t)
  M_UINT       (DynamicAllocation_t,  USF,  3),
  M_UINT       (DynamicAllocation_t,  USF_GRANULARITY,  1),

  M_NEXT_EXIST (DynamicAllocation_t, Exist_P0_PR_MODE, 2),
  M_UINT       (DynamicAllocation_t,  P0,  4),
  M_UINT       (DynamicAllocation_t,  PR_MODE,  1),
CSN_DESCR_END  (DynamicAllocation_t)

static const
CSN_DESCR_BEGIN(EGPRS_TwoPhaseAccess_t)
  M_NEXT_EXIST (EGPRS_TwoPhaseAccess_t, Exist_ALPHA, 1),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  ALPHA,  4),

  M_UINT       (EGPRS_TwoPhaseAccess_t,  GAMMA,  5),
  M_TYPE       (EGPRS_TwoPhaseAccess_t, TBF_STARTING_TIME, StartingTime_t),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  NR_OF_RADIO_BLOCKS_ALLOCATED,  2),

  M_NEXT_EXIST (EGPRS_TwoPhaseAccess_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  P0,  4),
  M_UINT       (EGPRS_TwoPhaseAccess_t,  BTS_PWR_CTRL_MODE,  1), /* shall be 0 */
  M_UINT       (EGPRS_TwoPhaseAccess_t,  PR_MODE,  1),
CSN_DESCR_END  (EGPRS_TwoPhaseAccess_t)

static const
CSN_DESCR_BEGIN(EGPRS_OnePhaseAccess_t)
  M_UINT       (EGPRS_OnePhaseAccess_t,  TFI_ASSIGNMENT,  5),
  M_UINT       (EGPRS_OnePhaseAccess_t,  POLLING,  1),

  M_UNION      (EGPRS_OnePhaseAccess_t, 2),
  M_TYPE       (EGPRS_OnePhaseAccess_t, Allocation.DynamicAllocation, DynamicAllocation_t),
  CSN_ERROR    (EGPRS_OnePhaseAccess_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_UINT       (EGPRS_OnePhaseAccess_t,  EGPRS_CHANNEL_CODING_COMMAND,  4),
  M_UINT       (EGPRS_OnePhaseAccess_t,  TLLI_BLOCK_CHANNEL_CODING,  1),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_BEP_PERIOD2, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  BEP_PERIOD2,  4),

  M_UINT       (EGPRS_OnePhaseAccess_t,  RESEGMENT,  1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  EGPRS_WindowSize,  5),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_ALPHA, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  ALPHA,  4),

  M_UINT       (EGPRS_OnePhaseAccess_t,  GAMMA,  5),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT       (EGPRS_OnePhaseAccess_t,  TIMING_ADVANCE_INDEX,  4),

  M_NEXT_EXIST (EGPRS_OnePhaseAccess_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE       (EGPRS_OnePhaseAccess_t, TBF_STARTING_TIME, StartingTime_t),
CSN_DESCR_END  (EGPRS_OnePhaseAccess_t)

/* < EGPRS Packet Uplink Assignment > */
static const
CSN_DESCR_BEGIN(IA_EGPRS_PktUlAss_t)
  M_UINT       (IA_EGPRS_PktUlAss_t,  ExtendedRA,  5),

  M_REC_ARRAY  (IA_EGPRS_PktUlAss_t, AccessTechnologyType, NrOfAccessTechnologies, 4),

  M_UNION      (IA_EGPRS_PktUlAss_t, 2),
  M_TYPE       (IA_EGPRS_PktUlAss_t, Access.TwoPhaseAccess, EGPRS_TwoPhaseAccess_t),
  M_TYPE       (IA_EGPRS_PktUlAss_t, Access.OnePhaseAccess, EGPRS_OnePhaseAccess_t),
CSN_DESCR_END  (IA_EGPRS_PktUlAss_t)

/* < Multiple Blocks Packet Downlink Assignment > */
static const
CSN_DESCR_BEGIN(IA_MultiBlock_PktDlAss_t)
  M_TYPE       (IA_MultiBlock_PktDlAss_t, TBF_STARTING_TIME, StartingTime_t),
  M_UINT       (IA_MultiBlock_PktDlAss_t, NOF_BLOCKS, 4),

#if 1 /* TODO: 0 -- Reserved for future use */
  M_FIXED      (IA_MultiBlock_PktDlAss_t, 1, 0x00),
#else /* | 1 ... */
  M_UNION      (IA_MultiBlock_PktDlAss_t, 2),
  M_TYPE       (IA_MultiBlock_PktDlAss_t, u.Distribution, ),
  M_TYPE       (IA_MultiBlock_PktDlAss_t, u.NonDistribution),
#endif
CSN_DESCR_END  (IA_MultiBlock_PktDlAss_t)

static const
CSN_DESCR_BEGIN(IA_FreqParamsBeforeTime_t)
  M_UINT       (IA_FreqParamsBeforeTime_t,  Length,  6),
  M_UINT       (IA_FreqParamsBeforeTime_t,  MAIO,  6),
  M_VAR_ARRAY  (IA_FreqParamsBeforeTime_t, MobileAllocation, Length, 8),
CSN_DESCR_END  (IA_FreqParamsBeforeTime_t)

static const
CSN_DESCR_BEGIN  (GPRS_SingleBlockAllocation_t)
  M_NEXT_EXIST   (GPRS_SingleBlockAllocation_t, Exist_ALPHA, 1),
  M_UINT         (GPRS_SingleBlockAllocation_t,  ALPHA,  4),

  M_UINT         (GPRS_SingleBlockAllocation_t,  GAMMA,  5),
  M_FIXED        (GPRS_SingleBlockAllocation_t, 2, 0x01),
  M_TYPE         (GPRS_SingleBlockAllocation_t, TBF_STARTING_TIME, StartingTime_t), /*bit(16)*/

  M_NEXT_EXIST_LH(GPRS_SingleBlockAllocation_t, Exist_P0_BTS_PWR_CTRL_PR_MODE, 3),
  M_UINT         (GPRS_SingleBlockAllocation_t,  P0,  4),
  M_UINT         (GPRS_SingleBlockAllocation_t,  BTS_PWR_CTRL_MODE,  1), /* shall be 0 */
  M_UINT         (GPRS_SingleBlockAllocation_t,  PR_MODE,  1),
CSN_DESCR_END    (GPRS_SingleBlockAllocation_t)

static const
CSN_DESCR_BEGIN  (GPRS_DynamicOrFixedAllocation_t)
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TFI_ASSIGNMENT,  5),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  POLLING,  1),

  M_UNION        (GPRS_DynamicOrFixedAllocation_t, 2),
  M_TYPE         (GPRS_DynamicOrFixedAllocation_t, Allocation.DynamicAllocation, DynamicAllocation_t),
  CSN_ERROR      (GPRS_DynamicOrFixedAllocation_t, "1 <Fixed Allocation>", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  CHANNEL_CODING_COMMAND,  2),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TLLI_BLOCK_CHANNEL_CODING,  1),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_ALPHA, 1),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  ALPHA,  4),

  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  GAMMA,  5),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT         (GPRS_DynamicOrFixedAllocation_t,  TIMING_ADVANCE_INDEX,  4),

  M_NEXT_EXIST   (GPRS_DynamicOrFixedAllocation_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE         (GPRS_DynamicOrFixedAllocation_t, TBF_STARTING_TIME, StartingTime_t),
CSN_DESCR_END    (GPRS_DynamicOrFixedAllocation_t)

static const
CSN_DESCR_BEGIN(PU_IA_AdditionsR99_t)
  M_NEXT_EXIST (PU_IA_AdditionsR99_t, Exist_ExtendedRA, 1),
  M_UINT       (PU_IA_AdditionsR99_t,  ExtendedRA,  5),
CSN_DESCR_END  (PU_IA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN          (Packet_Uplink_ImmAssignment_t)
  M_UNION                (Packet_Uplink_ImmAssignment_t, 2),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, Access.SingleBlockAllocation, GPRS_SingleBlockAllocation_t),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, Access.DynamicOrFixedAllocation, GPRS_DynamicOrFixedAllocation_t),

  M_NEXT_EXIST_OR_NULL_LH(Packet_Uplink_ImmAssignment_t, Exist_AdditionsR99, 1),
  M_TYPE                 (Packet_Uplink_ImmAssignment_t, AdditionsR99, PU_IA_AdditionsR99_t),
CSN_DESCR_END            (Packet_Uplink_ImmAssignment_t)

static const
CSN_DESCR_BEGIN(PD_IA_AdditionsR99_t)
  M_UINT       (PD_IA_AdditionsR99_t,  EGPRS_WindowSize,  5),
  M_UINT       (PD_IA_AdditionsR99_t,  LINK_QUALITY_MEASUREMENT_MODE,  2),

  M_NEXT_EXIST (PD_IA_AdditionsR99_t, Exist_BEP_PERIOD2, 1),
  M_UINT       (PD_IA_AdditionsR99_t,  BEP_PERIOD2,  4),
CSN_DESCR_END  (PD_IA_AdditionsR99_t)

static const
CSN_DESCR_BEGIN(Packet_Downlink_ImmAssignment_t)
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TLLI,  32),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TFI_to_TA_VALID, 6 + 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TFI_ASSIGNMENT,  5),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  RLC_MODE,  1),
  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_ALPHA, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  ALPHA,  4),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  GAMMA,  5),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  POLLING,  1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TA_VALID,  1),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TIMING_ADVANCE_INDEX, 1),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  TIMING_ADVANCE_INDEX,  4),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_TBF_STARTING_TIME, 1),
  M_TYPE       (Packet_Downlink_ImmAssignment_t, TBF_STARTING_TIME, StartingTime_t),

  M_NEXT_EXIST (Packet_Downlink_ImmAssignment_t, Exist_P0_PR_MODE, 3),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  P0,  4),
  M_UINT       (Packet_Downlink_ImmAssignment_t,  BTS_PWR_CTRL_MODE,  1), /* shall be 0 */
  M_UINT       (Packet_Downlink_ImmAssignment_t,  PR_MODE,  1),

  M_NEXT_EXIST_OR_NULL_LH(Packet_Downlink_ImmAssignment_t, Exist_AdditionsR99, 1),
  M_TYPE       (Packet_Downlink_ImmAssignment_t, AdditionsR99, PD_IA_AdditionsR99_t),
CSN_DESCR_END  (Packet_Downlink_ImmAssignment_t)

static const
CSN_DESCR_BEGIN          (Second_Part_Packet_Assignment_t)
  M_NEXT_EXIST_OR_NULL_LH(Second_Part_Packet_Assignment_t, Exist_SecondPart, 2),
  M_NEXT_EXIST           (Second_Part_Packet_Assignment_t, Exist_ExtendedRA, 1),
  M_UINT                 (Second_Part_Packet_Assignment_t,  ExtendedRA,  5),
CSN_DESCR_END            (Second_Part_Packet_Assignment_t)

static const
CSN_DESCR_BEGIN(IA_PacketAssignment_UL_DL_t)
  M_UNION      (IA_PacketAssignment_UL_DL_t, 2),
  M_TYPE       (IA_PacketAssignment_UL_DL_t, ul_dl.Packet_Uplink_ImmAssignment, Packet_Uplink_ImmAssignment_t),
  M_TYPE       (IA_PacketAssignment_UL_DL_t, ul_dl.Packet_Downlink_ImmAssignment, Packet_Downlink_ImmAssignment_t),
CSN_DESCR_END  (IA_PacketAssignment_UL_DL_t)

static const
CSN_DESCR_BEGIN    (IA_AdditionsR13_t)
  M_NEXT_EXIST_LH  (IA_AdditionsR13_t, Exist_AdditionsR13, 3),
  M_UINT           (IA_AdditionsR13_t, ImplicitRejectPS, 1),
  M_UINT           (IA_AdditionsR13_t, PEO_BCCH_CHANGE_MARK, 2),
  M_UINT           (IA_AdditionsR13_t, RCC, 3),
CSN_DESCR_END      (IA_AdditionsR13_t)

static const
CSN_DESCR_BEGIN    (IA_RestOctetsLL_t)
  M_UINT_LH        (IA_RestOctetsLL_t, Compressed_Inter_RAT_HO_INFO_IND, 1),
  M_TYPE_OR_NULL   (IA_RestOctetsLL_t, AdditionsR13, IA_AdditionsR13_t),
CSN_DESCR_END      (IA_RestOctetsLL_t)

static const
CSN_DESCR_BEGIN    (IA_RestOctetsLH0x_t)
  M_UNION          (IA_RestOctetsLH0x_t, 2),
  M_TYPE           (IA_RestOctetsLH0x_t, u.EGPRS_PktUlAss, IA_EGPRS_PktUlAss_t),
  M_TYPE           (IA_RestOctetsLH0x_t, u.MultiBlock_PktDlAss, IA_MultiBlock_PktDlAss_t),
CSN_DESCR_END      (IA_RestOctetsLH0x_t)

static const
CSN_DESCR_BEGIN    (IA_RestOctetsLH_t)
  M_UNION          (IA_RestOctetsLH_t, 2),
  M_TYPE           (IA_RestOctetsLH_t, lh0x, IA_RestOctetsLH0x_t),
  CSN_ERROR        (IA_RestOctetsLH_t, "1 -- reserved for future use", CSN_ERROR_STREAM_NOT_SUPPORTED),

  M_TYPE_OR_NULL   (IA_RestOctetsLH_t, AdditionsR13, IA_AdditionsR13_t),
CSN_DESCR_END      (IA_RestOctetsLH_t)

static const
CSN_DESCR_BEGIN    (IA_RestOctetsHL_t)
  M_TYPE           (IA_RestOctetsHL_t, IA_FrequencyParams, IA_FreqParamsBeforeTime_t),
  M_UINT_LH        (IA_RestOctetsHL_t, Compressed_Inter_RAT_HO_INFO_IND, 1),
  M_TYPE_OR_NULL   (IA_RestOctetsHL_t, AdditionsR13, IA_AdditionsR13_t),
CSN_DESCR_END      (IA_RestOctetsHL_t)

static const
CSN_DESCR_BEGIN           (IA_RestOctetsHH_t)
  M_UNION                 (IA_RestOctetsHH_t, 2),
  M_TYPE                  (IA_RestOctetsHH_t, u.UplinkDownlinkAssignment, IA_PacketAssignment_UL_DL_t),
  M_TYPE                  (IA_RestOctetsHH_t, u.SecondPartPacketAssignment, Second_Part_Packet_Assignment_t),

  M_NEXT_EXIST_OR_NULL_LH (IA_RestOctetsHH_t, Exist_AdditionsR10, 2),
  M_UINT                  (IA_RestOctetsHH_t, ImplicitRejectCS, 1),
  M_UINT                  (IA_RestOctetsHH_t, ImplicitRejectPS, 1),

  M_NEXT_EXIST_OR_NULL_LH (IA_RestOctetsHH_t, Exist_AdditionsR13, 2),
  M_UINT                  (IA_RestOctetsHH_t, PEO_BCCH_CHANGE_MARK, 2),
  M_UINT                  (IA_RestOctetsHH_t, RCC, 3),
CSN_DESCR_END             (IA_RestOctetsHH_t)

/* 10.5.2.16 IA Rest Octets */
static const
CSN_DESCR_BEGIN  (IA_RestOctets_t)
  M_UNION_LH     (IA_RestOctets_t, 4),
  M_TYPE         (IA_RestOctets_t, u.ll, IA_RestOctetsLL_t),
  M_TYPE         (IA_RestOctets_t, u.lh, IA_RestOctetsLH_t),
  M_TYPE         (IA_RestOctets_t, u.hl, IA_RestOctetsHL_t),
  M_TYPE         (IA_RestOctets_t, u.hh, IA_RestOctetsHH_t),

  /* TODO: Additions for Rel-14 and Rel-15 */
  M_PADDING_BITS (IA_RestOctets_t),
CSN_DESCR_END    (IA_RestOctets_t)

static const
CSN_DESCR_BEGIN(SI13_AdditionsR6)
  M_NEXT_EXIST (SI13_AdditionsR6, Exist_LB_MS_TXPWR_MAX_CCH, 1),
  M_UINT       (SI13_AdditionsR6,  LB_MS_TXPWR_MAX_CCH,  5),
  M_UINT       (SI13_AdditionsR6,  SI2n_SUPPORT,  2),
CSN_DESCR_END  (SI13_AdditionsR6)

static const
CSN_DESCR_BEGIN(SI13_AdditionsR4)
  M_UINT       (SI13_AdditionsR4,  SI_STATUS_IND,  1),
  M_NEXT_EXIST_OR_NULL_LH (SI13_AdditionsR4, Exist_AdditionsR6, 1),
  M_TYPE       (SI13_AdditionsR4,  AdditionsR6, SI13_AdditionsR6),
CSN_DESCR_END  (SI13_AdditionsR4)

static const
CSN_DESCR_BEGIN(SI13_AdditionR99)
  M_UINT       (SI13_AdditionR99,  SGSNR,  1),
  M_NEXT_EXIST_OR_NULL_LH (SI13_AdditionR99, Exist_AdditionsR4, 1),
  M_TYPE       (SI13_AdditionR99,  AdditionsR4, SI13_AdditionsR4),
CSN_DESCR_END  (SI13_AdditionR99)

static const
CSN_DESCR_BEGIN          (SI_13_t)
  M_THIS_EXIST_LH        (SI_13_t),

  M_UINT                 (SI_13_t,  BCCH_CHANGE_MARK,  3),
  M_UINT                 (SI_13_t,  SI_CHANGE_FIELD,  4),

  M_NEXT_EXIST           (SI_13_t, Exist_MA, 2),
  M_UINT                 (SI_13_t,  SI13_CHANGE_MARK,  2),
  M_TYPE                 (SI_13_t, GPRS_Mobile_Allocation, GPRS_Mobile_Allocation_t),

  M_UNION                (SI_13_t, 2),
  M_TYPE                 (SI_13_t, u.PBCCH_Not_present, PBCCH_Not_present_t),
  M_TYPE                 (SI_13_t, u.PBCCH_present, PBCCH_present_t),

  M_NEXT_EXIST_OR_NULL_LH(SI_13_t, Exist_AdditionsR99, 1),
  M_TYPE                 (SI_13_t, AdditionsR99, SI13_AdditionR99),
  M_PADDING_BITS         (SI_13_t),
CSN_DESCR_END            (SI_13_t)

/* Enhanced Measurement Report */
#if 0
static const
CSN_DESCR_BEGIN (ServingCellData_t)
  M_UINT        (ServingCellData_t,  RXLEV_SERVING_CELL,  6),
  M_FIXED       (ServingCellData_t, 1, 0),
CSN_DESCR_END   (ServingCellData_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN (Repeated_Invalid_BSIC_Info_t)
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  BCCH_FREQ_NCELL,  5),
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  BSIC,  6),
  M_UINT        (Repeated_Invalid_BSIC_Info_t,  RXLEV_NCELL,  5),
CSN_DESCR_END   (Repeated_Invalid_BSIC_Info_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN (REPORTING_QUANTITY_t)
  M_NEXT_EXIST  (REPORTING_QUANTITY_t, Exist_REPORTING_QUANTITY, 1),
  M_UINT        (REPORTING_QUANTITY_t,  REPORTING_QUANTITY,  6),
CSN_DESCR_END   (REPORTING_QUANTITY_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN (NC_MeasurementReport_t)
  M_UINT        (NC_MeasurementReport_t, NC_MODE, 1),
  M_UNION       (NC_MeasurementReport_t, 2),
  M_TYPE        (NC_MeasurementReport_t, u.BA_USED, BA_USED_t),
  M_UINT        (NC_MeasurementReport_t, u.PSI3_CHANGE_MARK,  2),
  M_UINT        (NC_MeasurementReport_t, PMO_USED, 1),
  M_UINT        (NC_MeasurementReport_t, SCALE, 1),

  M_NEXT_EXIST  (NC_MeasurementReport_t, Exist_ServingCellData, 1),
  M_TYPE        (NC_MeasurementReport_t, ServingCellData, ServingCellData_t),

  M_REC_TARRAY  (NC_MeasurementReport_t, Repeated_Invalid_BSIC_Info, Repeated_Invalid_BSIC_Info_t, Count_Repeated_Invalid_BSIC_Info),

  M_NEXT_EXIST  (NC_MeasurementReport_t, Exist_Repeated_REPORTING_QUANTITY, 1),
  M_VAR_TARRAY  (NC_MeasurementReport_t, Repeated_REPORTING_QUANTITY, REPORTING_QUANTITY_t, Count_Repeated_Reporting_Quantity),
CSN_DESCR_END   (NC_MeasurementReport_t)
#endif

/* SI1_RestOctet_t */
#if 0
static const
CSN_DESCR_BEGIN  (SI1_RestOctet_t)
  M_NEXT_EXIST_LH(SI1_RestOctet_t, Exist_NCH_Position, 1),
  M_UINT         (SI1_RestOctet_t,  NCH_Position,  5),

  M_UINT_LH      (SI1_RestOctet_t,  BandIndicator,  1),
CSN_DESCR_END    (SI1_RestOctet_t)
#endif

/* SI3_Rest_Octet_t */
#if 0
static const
CSN_DESCR_BEGIN(Selection_Parameters_t)
  M_UINT       (Selection_Parameters_t,  CBQ,  1),
  M_UINT       (Selection_Parameters_t,  CELL_RESELECT_OFFSET,  6),
  M_UINT       (Selection_Parameters_t,  TEMPORARY_OFFSET,  3),
  M_UINT       (Selection_Parameters_t,  PENALTY_TIME,  5),
CSN_DESCR_END  (Selection_Parameters_t)

static const
CSN_DESCR_BEGIN  (SI3_Rest_Octet_t)
  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_Selection_Parameters, 1),
  M_TYPE         (SI3_Rest_Octet_t, Selection_Parameters, Selection_Parameters_t),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_Power_Offset, 1),
  M_UINT         (SI3_Rest_Octet_t,  Power_Offset,  2),

  M_UINT_LH      (SI3_Rest_Octet_t,  System_Information_2ter_Indicator,  1),
  M_UINT_LH      (SI3_Rest_Octet_t,  Early_Classmark_Sending_Control,  1),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_WHERE, 1),
  M_UINT         (SI3_Rest_Octet_t,  WHERE,  3),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, Exist_GPRS_Indicator, 2),
  M_UINT         (SI3_Rest_Octet_t,  RA_COLOUR,  3),
  M_UINT         (SI3_Rest_Octet_t,  SI13_POSITION,  1),

  M_UINT_LH      (SI3_Rest_Octet_t,  ECS_Restriction3G,  1),

  M_NEXT_EXIST_LH(SI3_Rest_Octet_t, ExistSI2quaterIndicator, 1),
  M_UINT         (SI3_Rest_Octet_t,  SI2quaterIndicator,  1),
CSN_DESCR_END    (SI3_Rest_Octet_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN  (SI4_Rest_Octet_t)
  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_Selection_Parameters, 1),
  M_TYPE         (SI4_Rest_Octet_t, Selection_Parameters, Selection_Parameters_t),

  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_Power_Offset, 1),
  M_UINT         (SI4_Rest_Octet_t,  Power_Offset,  2),

  M_NEXT_EXIST_LH(SI4_Rest_Octet_t, Exist_GPRS_Indicator, 2),
  M_UINT         (SI4_Rest_Octet_t,  RA_COLOUR,  3),
  M_UINT         (SI4_Rest_Octet_t,  SI13_POSITION,  1),
CSN_DESCR_END    (SI4_Rest_Octet_t)
#endif

/* SI6_RestOctet_t */

#if 0
static const
CSN_DESCR_BEGIN(PCH_and_NCH_Info_t)
  M_UINT       (PCH_and_NCH_Info_t,  PagingChannelRestructuring,  1),
  M_UINT       (PCH_and_NCH_Info_t,  NLN_SACCH,  2),

  M_NEXT_EXIST (PCH_and_NCH_Info_t, Exist_CallPriority, 1),
  M_UINT       (PCH_and_NCH_Info_t,  CallPriority,  3),

  M_UINT       (PCH_and_NCH_Info_t,  NLN_Status,  1),
CSN_DESCR_END  (PCH_and_NCH_Info_t)

static const
CSN_DESCR_BEGIN  (SI6_RestOctet_t)
  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_PCH_and_NCH_Info, 1),
  M_TYPE         (SI6_RestOctet_t, PCH_and_NCH_Info, PCH_and_NCH_Info_t),

  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_VBS_VGCS_Options, 1),
  M_UINT         (SI6_RestOctet_t,  VBS_VGCS_Options,  2),

  M_NEXT_EXIST_LH(SI6_RestOctet_t, Exist_DTM_Support, 2),
  M_UINT         (SI6_RestOctet_t,  RAC,  8),
  M_UINT         (SI6_RestOctet_t,  MAX_LAPDm,  3),

  M_UINT_LH      (SI6_RestOctet_t,  BandIndicator,  1),
CSN_DESCR_END    (SI6_RestOctet_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(EMR_ServingCell_t)
  /*CSN_MEMBER_BIT (EMR_ServingCell_t, DTX_USED),*/
  M_UINT         (EMR_ServingCell_t,  DTX_USED, 1),
  M_UINT         (EMR_ServingCell_t,  RXLEV_VAL,        6),
  M_UINT         (EMR_ServingCell_t,  RX_QUAL_FULL,     3),
  M_UINT         (EMR_ServingCell_t,  MEAN_BEP,         5),
  M_UINT         (EMR_ServingCell_t,  CV_BEP,           3),
  M_UINT         (EMR_ServingCell_t,  NBR_RCVD_BLOCKS,  5),
CSN_DESCR_END(EMR_ServingCell_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN   (EnhancedMeasurementReport_t)
  M_UINT          (EnhancedMeasurementReport_t,  RR_Short_PD,  1),
  M_UINT          (EnhancedMeasurementReport_t,  MESSAGE_TYPE,  5),
  M_UINT          (EnhancedMeasurementReport_t,  ShortLayer2_Header,  2),
  M_TYPE          (EnhancedMeasurementReport_t, BA_USED, BA_USED_t),
  M_UINT          (EnhancedMeasurementReport_t,  BSIC_Seen,  1),
  M_UINT          (EnhancedMeasurementReport_t,  SCALE,  1),
  M_NEXT_EXIST    (EnhancedMeasurementReport_t, Exist_ServingCellData, 1),
  M_TYPE          (EnhancedMeasurementReport_t, ServingCellData, EMR_ServingCell_t),
  M_REC_TARRAY    (EnhancedMeasurementReport_t, RepeatedInvalid_BSIC_Info, RepeatedInvalid_BSIC_Info_t,
                    Count_RepeatedInvalid_BSIC_Info),
  M_NEXT_EXIST    (EnhancedMeasurementReport_t, Exist_ReportBitmap, 1),
  M_VAR_TARRAY    (EnhancedMeasurementReport_t, REPORTING_QUANTITY_Instances, REPORTING_QUANTITY_Instance_t, Count_REPORTING_QUANTITY_Instances),
CSN_DESCR_END     (EnhancedMeasurementReport_t)
#endif

static int _osmo_gprs_rlcmac_decode(void *storage,
				    const CSN_DESCR *descr,
				    const char *descr_name,
				    const uint8_t *data,
				    size_t data_len)
{
	unsigned int readIndex = 0;
	csnStream_t ar;
	int ret;

	osmo_csn1_stream_init(&ar, 0, 8 * data_len);

	struct bitvec bv = {
		.data = (uint8_t *)data,
		.data_len = data_len,
	};

	LOGP(DLCSN1, LOGL_INFO, "osmo_csn1_stream_decode (%s): ", descr_name);
	ret = osmo_csn1_stream_decode(&ar, descr, &bv, &readIndex, storage);
	LOGPC(DLCSN1, LOGL_INFO, "\n");

	if (ret > 0) {
		LOGP(g_log_cat, LOGL_NOTICE,
		     "%s: %d remaining bits unhandled by decoder\n",
		     descr_name, ret);
		ret = 0;
	}

	return ret;
}

int osmo_gprs_rlcmac_decode_si13ro(SI_13_t *storage,
				   const uint8_t *data, size_t data_len)
{
	return _osmo_gprs_rlcmac_decode(storage,
					CSNDESCR(SI_13_t),
					"SI13 Rest Octets",
					data, data_len);
}

int osmo_gprs_rlcmac_decode_imm_ass_ro(IA_RestOctets_t *storage,
				       const uint8_t *data, size_t data_len)
{
	return _osmo_gprs_rlcmac_decode(storage,
					CSNDESCR(IA_RestOctets_t),
					"IA Rest Octets",
					data, data_len);
}
