/*
 * CSN.1 definitions from 3GPP TS 24.008.
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

#include <osmocom/core/utils.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/logging.h>

#include <osmocom/csn1/csn1.h>
#include <osmocom/gprs/rlcmac/csn1_defs.h>
#include <osmocom/gprs/rlcmac/rlcmac_private.h>

/*< MS Classmark 3 IE >*/
#if 0
static const
CSN_DESCR_BEGIN(ARC_t)
  M_UINT       (ARC_t,  A5_Bits,  4),
  M_UINT       (ARC_t,  Arc2_Spare,  4),
  M_UINT       (ARC_t,  Arc1,  4),
CSN_DESCR_END  (ARC_t)
#endif

#if 0
static const
CSN_ChoiceElement_t MultibandChoice[] =
{
  {3, 0x00, 0, M_UINT(Multiband_t, u.A5_Bits, 4)},
  {3, 0x05, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x06, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x01, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x02, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
  {3, 0x04, 0, M_TYPE(Multiband_t, u.ARC, ARC_t)},
};
#endif

#if 0
static const
CSN_DESCR_BEGIN(Multiband_t)
  M_CHOICE     (Multiband_t, Multiband, MultibandChoice, ElementsOf(MultibandChoice)),
CSN_DESCR_END  (Multiband_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(EDGE_RF_Pwr_t)
  M_NEXT_EXIST (EDGE_RF_Pwr_t, ExistEDGE_RF_PwrCap1, 1),
  M_UINT       (EDGE_RF_Pwr_t,  EDGE_RF_PwrCap1,  2),

  M_NEXT_EXIST (EDGE_RF_Pwr_t, ExistEDGE_RF_PwrCap2, 1),
  M_UINT       (EDGE_RF_Pwr_t,  EDGE_RF_PwrCap2,  2),
CSN_DESCR_END  (EDGE_RF_Pwr_t)
#endif

#if 0
static const
CSN_DESCR_BEGIN(MS_Class3_Unpacked_t)
  M_UINT       (MS_Class3_Unpacked_t,  Spare1,  1),
  M_TYPE       (MS_Class3_Unpacked_t, Multiband, Multiband_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_R_Support, 1),
  M_UINT       (MS_Class3_Unpacked_t,  R_GSM_Arc,  3),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MultiSlotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  MultiSlotClass,  5),

  M_UINT       (MS_Class3_Unpacked_t,  UCS2,  1),
  M_UINT       (MS_Class3_Unpacked_t,  ExtendedMeasurementCapability,  1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MS_MeasurementCapability, 2),
  M_UINT       (MS_Class3_Unpacked_t,  SMS_VALUE,  4),
  M_UINT       (MS_Class3_Unpacked_t,  SM_VALUE,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_MS_PositioningMethodCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  MS_PositioningMethod,  5),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_EDGE_MultiSlotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  EDGE_MultiSlotClass,  5),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_EDGE_Struct, 2),
  M_UINT       (MS_Class3_Unpacked_t,  ModulationCapability,  1),
  M_TYPE       (MS_Class3_Unpacked_t, EDGE_RF_PwrCaps, EDGE_RF_Pwr_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM400_Info, 2),
  M_UINT       (MS_Class3_Unpacked_t,  GSM400_Bands,  2),
  M_UINT       (MS_Class3_Unpacked_t,  GSM400_Arc,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM850_Arc, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM850_Arc,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_PCS1900_Arc, 1),
  M_UINT       (MS_Class3_Unpacked_t,  PCS1900_Arc,  4),

  M_UINT       (MS_Class3_Unpacked_t,  UMTS_FDD_Radio_Access_Technology_Capability,  1),
  M_UINT       (MS_Class3_Unpacked_t,  UMTS_384_TDD_Radio_Access_Technology_Capability,  1),
  M_UINT       (MS_Class3_Unpacked_t,  CDMA2000_Radio_Access_Technology_Capability,  1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_DTM_GPRS_multislot_class, 3),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_GPRS_multislot_class,  2),
  M_UINT       (MS_Class3_Unpacked_t,  Single_Slot_DTM,  1),
  M_TYPE       (MS_Class3_Unpacked_t, DTM_EGPRS_Params, DTM_EGPRS_t),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_SingleBandSupport, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM_Band,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GSM_700_Associated_Radio_Capability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GSM_700_Associated_Radio_Capability,  4),

  M_UINT       (MS_Class3_Unpacked_t,  UMTS_128_TDD_Radio_Access_Technology_Capability,  1),
  M_UINT       (MS_Class3_Unpacked_t,  GERAN_Feature_Package_1,  1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_Extended_DTM_multislot_class, 2),
  M_UINT       (MS_Class3_Unpacked_t,  Extended_DTM_GPRS_multislot_class,  2),
  M_UINT       (MS_Class3_Unpacked_t,  Extended_DTM_EGPRS_multislot_class,  2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_HighMultislotCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  HighMultislotCapability,  2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_GERAN_lu_ModeCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  GERAN_lu_ModeCapability,  4),

  M_UINT       (MS_Class3_Unpacked_t,  GERAN_FeaturePackage_2,  1),

  M_UINT       (MS_Class3_Unpacked_t,  GMSK_MultislotPowerProfile,  2),
  M_UINT       (MS_Class3_Unpacked_t,  EightPSK_MultislotProfile,  2),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_TGSM_400_Bands, 2),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_400_BandsSupported,  2),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_400_AssociatedRadioCapability,  4),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_TGSM_900_AssociatedRadioCapability, 1),
  M_UINT       (MS_Class3_Unpacked_t,  TGSM_900_AssociatedRadioCapability,  4),

  M_UINT       (MS_Class3_Unpacked_t,  DownlinkAdvancedReceiverPerformance,  2),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_EnhancementsCapability,  1),

  M_NEXT_EXIST (MS_Class3_Unpacked_t, Exist_DTM_GPRS_HighMultislotClass, 3),
  M_UINT       (MS_Class3_Unpacked_t,  DTM_GPRS_HighMultislotClass,  3),
  M_UINT       (MS_Class3_Unpacked_t,  OffsetRequired,  1),
  M_TYPE       (MS_Class3_Unpacked_t, DTM_EGPRS_HighMultislotClass, DTM_EGPRS_HighMultislotClass_t),

  M_UINT       (MS_Class3_Unpacked_t,  RepeatedSACCH_Capability,  1),
  M_UINT       (MS_Class3_Unpacked_t,  Spare2,  1),
CSN_DESCR_END  (MS_Class3_Unpacked_t)
#endif

/*< MS Radio Access capability IE >*/
static const
CSN_DESCR_BEGIN       (DTM_EGPRS_t)
  M_NEXT_EXIST        (DTM_EGPRS_t, Exist_DTM_EGPRS_multislot_class, 1),
  M_UINT              (DTM_EGPRS_t,  DTM_EGPRS_multislot_class,  2),
CSN_DESCR_END         (DTM_EGPRS_t)

static const
CSN_DESCR_BEGIN       (DTM_EGPRS_HighMultislotClass_t)
  M_NEXT_EXIST        (DTM_EGPRS_HighMultislotClass_t, Exist_DTM_EGPRS_HighMultislotClass, 1),
  M_UINT              (DTM_EGPRS_HighMultislotClass_t,  DTM_EGPRS_HighMultislotClass,  3),
CSN_DESCR_END         (DTM_EGPRS_HighMultislotClass_t)

static const
CSN_DESCR_BEGIN       (DownlinkDualCarrierCapability_r7_t)
  M_UINT              (DownlinkDualCarrierCapability_r7_t, MultislotCapabilityReductionForDL_DualCarrier, 3),
  M_UINT              (DownlinkDualCarrierCapability_r7_t, DL_DualCarrierForDTM,  1),
CSN_DESCR_END         (DownlinkDualCarrierCapability_r7_t)

static const
CSN_DESCR_BEGIN       (Multislot_capability_t)
  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_HSCSD_multislot_class, 1),
  M_UINT              (Multislot_capability_t,  HSCSD_multislot_class,  5),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_GPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t,  GPRS_multislot_class,  5),
  M_UINT              (Multislot_capability_t,  GPRS_Extended_Dynamic_Allocation_Capability,  1),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_SM, 2),
  M_UINT              (Multislot_capability_t,  SMS_VALUE,  4),
  M_UINT              (Multislot_capability_t,  SM_VALUE,  4),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_ECSD_multislot_class, 1),
  M_UINT              (Multislot_capability_t,  ECSD_multislot_class,  5),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_EGPRS_multislot_class, 2),
  M_UINT              (Multislot_capability_t,  EGPRS_multislot_class,  5),
  M_UINT              (Multislot_capability_t,  EGPRS_Extended_Dynamic_Allocation_Capability,  1),

  M_NEXT_EXIST_OR_NULL(Multislot_capability_t, Exist_DTM_GPRS_multislot_class, 3),
  M_UINT              (Multislot_capability_t,  DTM_GPRS_multislot_class,  2),
  M_UINT              (Multislot_capability_t,  Single_Slot_DTM,  1),
  M_TYPE              (Multislot_capability_t, DTM_EGPRS_Params, DTM_EGPRS_t),
CSN_DESCR_END         (Multislot_capability_t)

static const
CSN_DESCR_BEGIN       (Content_t)
  M_UINT              (Content_t,  RF_Power_Capability,  3),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_A5_bits, 1),
  M_UINT_OR_NULL      (Content_t,  A5_bits,  7),

  M_UINT_OR_NULL      (Content_t,  ES_IND,  1),
  M_UINT_OR_NULL      (Content_t,  PS,  1),
  M_UINT_OR_NULL      (Content_t,  VGCS,  1),
  M_UINT_OR_NULL      (Content_t,  VBS,  1),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_Multislot_capability, 1),
  M_TYPE              (Content_t, Multislot_capability, Multislot_capability_t),

  M_NEXT_EXIST_OR_NULL(Content_t,  Exist_Eight_PSK_Power_Capability, 1),
  M_UINT              (Content_t,  Eight_PSK_Power_Capability,  2),

  M_UINT_OR_NULL      (Content_t,  COMPACT_Interference_Measurement_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  Revision_Level_Indicator,  1),
  M_UINT_OR_NULL      (Content_t,  UMTS_FDD_Radio_Access_Technology_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  UMTS_384_TDD_Radio_Access_Technology_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  CDMA2000_Radio_Access_Technology_Capability,  1),

  M_UINT_OR_NULL      (Content_t,  UMTS_128_TDD_Radio_Access_Technology_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  GERAN_Feature_Package_1,  1),

  M_NEXT_EXIST_OR_NULL(Content_t,  Exist_Extended_DTM_multislot_class, 2),
  M_UINT              (Content_t,  Extended_DTM_GPRS_multislot_class,  2),
  M_UINT              (Content_t,  Extended_DTM_EGPRS_multislot_class,  2),

  M_UINT_OR_NULL      (Content_t,  Modulation_based_multislot_class_support,  1),

  M_NEXT_EXIST_OR_NULL(Content_t,  Exist_HighMultislotCapability, 1),
  M_UINT              (Content_t,  HighMultislotCapability,  2),

  M_NEXT_EXIST_OR_NULL(Content_t,  Exist_GERAN_lu_ModeCapability, 1),
  M_UINT              (Content_t,  GERAN_lu_ModeCapability,  4),

  M_UINT_OR_NULL      (Content_t,  GMSK_MultislotPowerProfile,  2),
  M_UINT_OR_NULL      (Content_t,  EightPSK_MultislotProfile,  2),

  M_UINT_OR_NULL      (Content_t,  MultipleTBF_Capability,  1),
  M_UINT_OR_NULL      (Content_t,  DownlinkAdvancedReceiverPerformance,  2),
  M_UINT_OR_NULL      (Content_t,  ExtendedRLC_MAC_ControlMessageSegmentionsCapability,  1),
  M_UINT_OR_NULL      (Content_t,  DTM_EnhancementsCapability,  1),

  M_NEXT_EXIST_OR_NULL(Content_t, Exist_DTM_GPRS_HighMultislotClass, 2),
  M_UINT              (Content_t,  DTM_GPRS_HighMultislotClass,  3),
  M_TYPE              (Content_t, DTM_EGPRS_HighMultislotClass, DTM_EGPRS_HighMultislotClass_t),

  M_UINT_OR_NULL      (Content_t,  PS_HandoverCapability,  1),

  /* additions in release 7 */
  M_UINT_OR_NULL      (Content_t,  DTM_Handover_Capability,  1),
  M_NEXT_EXIST_OR_NULL(Content_t, Exist_DownlinkDualCarrierCapability_r7, 1),
  M_TYPE_OR_NULL      (Content_t, DownlinkDualCarrierCapability_r7, DownlinkDualCarrierCapability_r7_t),

  M_UINT_OR_NULL      (Content_t,  FlexibleTimeslotAssignment,  1),
  M_UINT_OR_NULL      (Content_t,  GAN_PS_HandoverCapability,  1),
  M_UINT_OR_NULL      (Content_t,  RLC_Non_persistentMode,  1),
  M_UINT_OR_NULL      (Content_t,  ReducedLatencyCapability,  1),
  M_UINT_OR_NULL      (Content_t,  UplinkEGPRS2,  2),
  M_UINT_OR_NULL      (Content_t,  DownlinkEGPRS2,  2),

  /* additions in release 8 */
  M_UINT_OR_NULL      (Content_t,  EUTRA_FDD_Support,  1),
  M_UINT_OR_NULL      (Content_t,  EUTRA_TDD_Support,  1),
  M_UINT_OR_NULL      (Content_t,  GERAN_To_EUTRAN_supportInGERAN_PTM,  2),
  M_UINT_OR_NULL      (Content_t,  PriorityBasedReselectionSupport,  1),

CSN_DESCR_END         (Content_t)

static gint16 Content_Dissector(csnStream_t* ar, struct bitvec *vector, unsigned *readIndex, void* data)
{
  if (ar->direction == CSN_DIRECTION_ENC)
    {
      return osmo_csn1_stream_encode(ar, CSNDESCR(Content_t), vector, readIndex, data);
    }
  else
    {
      return osmo_csn1_stream_decode(ar, CSNDESCR(Content_t), vector, readIndex, data);
    }
}

static const
CSN_DESCR_BEGIN       (Additional_access_technologies_struct_t)
  M_UINT              (Additional_access_technologies_struct_t,  Access_Technology_Type,  4),
  M_UINT              (Additional_access_technologies_struct_t,  GMSK_Power_class,  3),
  M_UINT              (Additional_access_technologies_struct_t,  Eight_PSK_Power_class,  2),
CSN_DESCR_END         (Additional_access_technologies_struct_t)

static const
CSN_DESCR_BEGIN       (Additional_access_technologies_t)
  M_REC_TARRAY        (Additional_access_technologies_t, Additional_access_technologies, Additional_access_technologies_struct_t, Count_additional_access_technologies),
CSN_DESCR_END         (Additional_access_technologies_t)

static gint16 Additional_access_technologies_Dissector(csnStream_t* ar, struct bitvec *vector, unsigned *readIndex, void* data)
{
  if (ar->direction == CSN_DIRECTION_ENC)
  {
    return osmo_csn1_stream_encode(ar, CSNDESCR(Additional_access_technologies_t), vector, readIndex, data);
  }
  else
  {
    return osmo_csn1_stream_decode(ar, CSNDESCR(Additional_access_technologies_t), vector, readIndex, data);
  }
}

static const
CSN_ChoiceElement_t MS_RA_capability_value_Choice[] =
{
  {4, AccTech_GSMP,     0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSME,     0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMR,     0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM1800,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM1900,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM450,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM480,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM850,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM750,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMT830,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMT410,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMT900,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSM710,   0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMT810,  0, M_SERIALIZE (MS_RA_capability_value_t, u.Content, 7, Content_Dissector)}, /* Long Form */
  {4, AccTech_GSMOther, 0, M_SERIALIZE (MS_RA_capability_value_t, u.Additional_access_technologies, 7, Additional_access_technologies_Dissector)}, /* Short Form */
};

const
CSN_DESCR_BEGIN(MS_RA_capability_value_t)
  M_CHOICE     (MS_RA_capability_value_t, IndexOfAccTech, MS_RA_capability_value_Choice, ElementsOf(MS_RA_capability_value_Choice)),
CSN_DESCR_END  (MS_RA_capability_value_t)

static const
CSN_DESCR_BEGIN (MS_Radio_Access_capability_t)
  M_REC_TARRAY_1(MS_Radio_Access_capability_t, MS_RA_capability_value, MS_RA_capability_value_t, Count_MS_RA_capability_value),
  M_PADDING_BITS(MS_Radio_Access_capability_t),
CSN_DESCR_END   (MS_Radio_Access_capability_t)

int osmo_gprs_rlcmac_decode_ms_ra_cap(struct bitvec *vector, MS_Radio_Access_capability_t *data)
{
  csnStream_t      ar;
  int ret;
  unsigned readIndex = 0;

  osmo_csn1_stream_init(&ar, 0, 8 * vector->data_len);

  /* recursive osmo_csn1_stream_decode call uses LOGPC everywhere, so we need to start the log somewhere... */
  LOGP(DLCSN1, LOGL_INFO, "osmo_csn1_stream_decode (RAcap): ");
  ret = osmo_csn1_stream_decode(&ar, CSNDESCR(MS_Radio_Access_capability_t), vector, &readIndex, data);

  /* recursive osmo_csn1_stream_decode call uses LOGPC everywhere without trailing
     newline, so as a caller we are responisble for submitting it */
  LOGPC(DLCSN1, LOGL_INFO, "\n");

  if (ret > 0) {
    LOGRLCMAC(LOGL_NOTICE, "RAcap: Got %d remaining bits unhandled by decoder at the end of bitvec\n", ret);
    ret = 0;
  }
  return ret;
}

int osmo_gprs_rlcmac_encode_ms_ra_cap(struct bitvec *vector, MS_Radio_Access_capability_t *data)
{
  unsigned writeIndex = 0;
  csnStream_t ar;
  int ret;

  osmo_csn1_stream_init(&ar, 0, vector->data_len * 8);

  /* recursive osmo_csn1_stream_encode call uses LOGPC everywhere, so we need to start the log somewhere... */
  LOGP(DLCSN1, LOGL_INFO, "osmo_csn1_stream_encode (RAcap): ");
  ret = osmo_csn1_stream_encode(&ar, CSNDESCR(MS_Radio_Access_capability_t), vector, &writeIndex, data);
  LOGPC(DLCSN1, LOGL_INFO, "\n");

  if (ret > 0 || ret == CSN_ERROR_NEED_MORE_BITS_TO_UNPACK) {
    LOGRLCMAC(LOGL_ERROR, "Failed to encode MS RA Capability IE: not enough bits "
                          "in the output buffer (rc=%d)\n", ret);
    ret = CSN_ERROR_NEED_MORE_BITS_TO_UNPACK;
  }

  return ret;
}
