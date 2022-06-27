/* SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2020 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

/************************************
 ** This is an auto-generated file **
 **       DO NOT EDIT BELOW        **
 ************************************/

#ifndef ASIC_REG_PDMA0_QM_REGS_H_
#define ASIC_REG_PDMA0_QM_REGS_H_

/*
 *****************************************
 *   PDMA0_QM
 *   (Prototype: QMAN)
 *****************************************
 */

#define mmPDMA0_QM_GLBL_CFG0 0x4C8A000

#define mmPDMA0_QM_GLBL_CFG1 0x4C8A004

#define mmPDMA0_QM_GLBL_CFG2 0x4C8A008

#define mmPDMA0_QM_GLBL_ERR_CFG 0x4C8A00C

#define mmPDMA0_QM_GLBL_ERR_CFG1 0x4C8A010

#define mmPDMA0_QM_GLBL_ERR_ARC_HALT_EN 0x4C8A014

#define mmPDMA0_QM_GLBL_AXCACHE 0x4C8A018

#define mmPDMA0_QM_GLBL_STS0 0x4C8A01C

#define mmPDMA0_QM_GLBL_STS1 0x4C8A020

#define mmPDMA0_QM_GLBL_ERR_STS_0 0x4C8A024

#define mmPDMA0_QM_GLBL_ERR_STS_1 0x4C8A028

#define mmPDMA0_QM_GLBL_ERR_STS_2 0x4C8A02C

#define mmPDMA0_QM_GLBL_ERR_STS_3 0x4C8A030

#define mmPDMA0_QM_GLBL_ERR_STS_4 0x4C8A034

#define mmPDMA0_QM_GLBL_ERR_MSG_EN_0 0x4C8A038

#define mmPDMA0_QM_GLBL_ERR_MSG_EN_1 0x4C8A03C

#define mmPDMA0_QM_GLBL_ERR_MSG_EN_2 0x4C8A040

#define mmPDMA0_QM_GLBL_ERR_MSG_EN_3 0x4C8A044

#define mmPDMA0_QM_GLBL_ERR_MSG_EN_4 0x4C8A048

#define mmPDMA0_QM_GLBL_PROT 0x4C8A04C

#define mmPDMA0_QM_PQ_BASE_LO_0 0x4C8A050

#define mmPDMA0_QM_PQ_BASE_LO_1 0x4C8A054

#define mmPDMA0_QM_PQ_BASE_LO_2 0x4C8A058

#define mmPDMA0_QM_PQ_BASE_LO_3 0x4C8A05C

#define mmPDMA0_QM_PQ_BASE_HI_0 0x4C8A060

#define mmPDMA0_QM_PQ_BASE_HI_1 0x4C8A064

#define mmPDMA0_QM_PQ_BASE_HI_2 0x4C8A068

#define mmPDMA0_QM_PQ_BASE_HI_3 0x4C8A06C

#define mmPDMA0_QM_PQ_SIZE_0 0x4C8A070

#define mmPDMA0_QM_PQ_SIZE_1 0x4C8A074

#define mmPDMA0_QM_PQ_SIZE_2 0x4C8A078

#define mmPDMA0_QM_PQ_SIZE_3 0x4C8A07C

#define mmPDMA0_QM_PQ_PI_0 0x4C8A080

#define mmPDMA0_QM_PQ_PI_1 0x4C8A084

#define mmPDMA0_QM_PQ_PI_2 0x4C8A088

#define mmPDMA0_QM_PQ_PI_3 0x4C8A08C

#define mmPDMA0_QM_PQ_CI_0 0x4C8A090

#define mmPDMA0_QM_PQ_CI_1 0x4C8A094

#define mmPDMA0_QM_PQ_CI_2 0x4C8A098

#define mmPDMA0_QM_PQ_CI_3 0x4C8A09C

#define mmPDMA0_QM_PQ_CFG0_0 0x4C8A0A0

#define mmPDMA0_QM_PQ_CFG0_1 0x4C8A0A4

#define mmPDMA0_QM_PQ_CFG0_2 0x4C8A0A8

#define mmPDMA0_QM_PQ_CFG0_3 0x4C8A0AC

#define mmPDMA0_QM_PQ_CFG1_0 0x4C8A0B0

#define mmPDMA0_QM_PQ_CFG1_1 0x4C8A0B4

#define mmPDMA0_QM_PQ_CFG1_2 0x4C8A0B8

#define mmPDMA0_QM_PQ_CFG1_3 0x4C8A0BC

#define mmPDMA0_QM_PQ_STS0_0 0x4C8A0C0

#define mmPDMA0_QM_PQ_STS0_1 0x4C8A0C4

#define mmPDMA0_QM_PQ_STS0_2 0x4C8A0C8

#define mmPDMA0_QM_PQ_STS0_3 0x4C8A0CC

#define mmPDMA0_QM_PQ_STS1_0 0x4C8A0D0

#define mmPDMA0_QM_PQ_STS1_1 0x4C8A0D4

#define mmPDMA0_QM_PQ_STS1_2 0x4C8A0D8

#define mmPDMA0_QM_PQ_STS1_3 0x4C8A0DC

#define mmPDMA0_QM_CQ_CFG0_0 0x4C8A0E0

#define mmPDMA0_QM_CQ_CFG0_1 0x4C8A0E4

#define mmPDMA0_QM_CQ_CFG0_2 0x4C8A0E8

#define mmPDMA0_QM_CQ_CFG0_3 0x4C8A0EC

#define mmPDMA0_QM_CQ_CFG0_4 0x4C8A0F0

#define mmPDMA0_QM_CQ_STS0_0 0x4C8A0F4

#define mmPDMA0_QM_CQ_STS0_1 0x4C8A0F8

#define mmPDMA0_QM_CQ_STS0_2 0x4C8A0FC

#define mmPDMA0_QM_CQ_STS0_3 0x4C8A100

#define mmPDMA0_QM_CQ_STS0_4 0x4C8A104

#define mmPDMA0_QM_CQ_CFG1_0 0x4C8A108

#define mmPDMA0_QM_CQ_CFG1_1 0x4C8A10C

#define mmPDMA0_QM_CQ_CFG1_2 0x4C8A110

#define mmPDMA0_QM_CQ_CFG1_3 0x4C8A114

#define mmPDMA0_QM_CQ_CFG1_4 0x4C8A118

#define mmPDMA0_QM_CQ_STS1_0 0x4C8A11C

#define mmPDMA0_QM_CQ_STS1_1 0x4C8A120

#define mmPDMA0_QM_CQ_STS1_2 0x4C8A124

#define mmPDMA0_QM_CQ_STS1_3 0x4C8A128

#define mmPDMA0_QM_CQ_STS1_4 0x4C8A12C

#define mmPDMA0_QM_CQ_PTR_LO_0 0x4C8A150

#define mmPDMA0_QM_CQ_PTR_HI_0 0x4C8A154

#define mmPDMA0_QM_CQ_TSIZE_0 0x4C8A158

#define mmPDMA0_QM_CQ_CTL_0 0x4C8A15C

#define mmPDMA0_QM_CQ_PTR_LO_1 0x4C8A160

#define mmPDMA0_QM_CQ_PTR_HI_1 0x4C8A164

#define mmPDMA0_QM_CQ_TSIZE_1 0x4C8A168

#define mmPDMA0_QM_CQ_CTL_1 0x4C8A16C

#define mmPDMA0_QM_CQ_PTR_LO_2 0x4C8A170

#define mmPDMA0_QM_CQ_PTR_HI_2 0x4C8A174

#define mmPDMA0_QM_CQ_TSIZE_2 0x4C8A178

#define mmPDMA0_QM_CQ_CTL_2 0x4C8A17C

#define mmPDMA0_QM_CQ_PTR_LO_3 0x4C8A180

#define mmPDMA0_QM_CQ_PTR_HI_3 0x4C8A184

#define mmPDMA0_QM_CQ_TSIZE_3 0x4C8A188

#define mmPDMA0_QM_CQ_CTL_3 0x4C8A18C

#define mmPDMA0_QM_CQ_PTR_LO_4 0x4C8A190

#define mmPDMA0_QM_CQ_PTR_HI_4 0x4C8A194

#define mmPDMA0_QM_CQ_TSIZE_4 0x4C8A198

#define mmPDMA0_QM_CQ_CTL_4 0x4C8A19C

#define mmPDMA0_QM_CQ_TSIZE_STS_0 0x4C8A1A0

#define mmPDMA0_QM_CQ_TSIZE_STS_1 0x4C8A1A4

#define mmPDMA0_QM_CQ_TSIZE_STS_2 0x4C8A1A8

#define mmPDMA0_QM_CQ_TSIZE_STS_3 0x4C8A1AC

#define mmPDMA0_QM_CQ_TSIZE_STS_4 0x4C8A1B0

#define mmPDMA0_QM_CQ_PTR_LO_STS_0 0x4C8A1B4

#define mmPDMA0_QM_CQ_PTR_LO_STS_1 0x4C8A1B8

#define mmPDMA0_QM_CQ_PTR_LO_STS_2 0x4C8A1BC

#define mmPDMA0_QM_CQ_PTR_LO_STS_3 0x4C8A1C0

#define mmPDMA0_QM_CQ_PTR_LO_STS_4 0x4C8A1C4

#define mmPDMA0_QM_CQ_PTR_HI_STS_0 0x4C8A1C8

#define mmPDMA0_QM_CQ_PTR_HI_STS_1 0x4C8A1CC

#define mmPDMA0_QM_CQ_PTR_HI_STS_2 0x4C8A1D0

#define mmPDMA0_QM_CQ_PTR_HI_STS_3 0x4C8A1D4

#define mmPDMA0_QM_CQ_PTR_HI_STS_4 0x4C8A1D8

#define mmPDMA0_QM_CQ_IFIFO_STS_0 0x4C8A1DC

#define mmPDMA0_QM_CQ_IFIFO_STS_1 0x4C8A1E0

#define mmPDMA0_QM_CQ_IFIFO_STS_2 0x4C8A1E4

#define mmPDMA0_QM_CQ_IFIFO_STS_3 0x4C8A1E8

#define mmPDMA0_QM_CQ_IFIFO_STS_4 0x4C8A1EC

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_LO_0 0x4C8A1F0

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_LO_1 0x4C8A1F4

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_LO_2 0x4C8A1F8

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_LO_3 0x4C8A1FC

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_LO_4 0x4C8A200

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_HI_0 0x4C8A204

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_HI_1 0x4C8A208

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_HI_2 0x4C8A20C

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_HI_3 0x4C8A210

#define mmPDMA0_QM_CP_MSG_BASE0_ADDR_HI_4 0x4C8A214

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_LO_0 0x4C8A218

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_LO_1 0x4C8A21C

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_LO_2 0x4C8A220

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_LO_3 0x4C8A224

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_LO_4 0x4C8A228

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_HI_0 0x4C8A22C

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_HI_1 0x4C8A230

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_HI_2 0x4C8A234

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_HI_3 0x4C8A238

#define mmPDMA0_QM_CP_MSG_BASE1_ADDR_HI_4 0x4C8A23C

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_LO_0 0x4C8A240

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_LO_1 0x4C8A244

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_LO_2 0x4C8A248

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_LO_3 0x4C8A24C

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_LO_4 0x4C8A250

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_HI_0 0x4C8A254

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_HI_1 0x4C8A258

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_HI_2 0x4C8A25C

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_HI_3 0x4C8A260

#define mmPDMA0_QM_CP_MSG_BASE2_ADDR_HI_4 0x4C8A264

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_LO_0 0x4C8A268

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_LO_1 0x4C8A26C

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_LO_2 0x4C8A270

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_LO_3 0x4C8A274

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_LO_4 0x4C8A278

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_HI_0 0x4C8A27C

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_HI_1 0x4C8A280

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_HI_2 0x4C8A284

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_HI_3 0x4C8A288

#define mmPDMA0_QM_CP_MSG_BASE3_ADDR_HI_4 0x4C8A28C

#define mmPDMA0_QM_CP_FENCE0_RDATA_0 0x4C8A290

#define mmPDMA0_QM_CP_FENCE0_RDATA_1 0x4C8A294

#define mmPDMA0_QM_CP_FENCE0_RDATA_2 0x4C8A298

#define mmPDMA0_QM_CP_FENCE0_RDATA_3 0x4C8A29C

#define mmPDMA0_QM_CP_FENCE0_RDATA_4 0x4C8A2A0

#define mmPDMA0_QM_CP_FENCE1_RDATA_0 0x4C8A2A4

#define mmPDMA0_QM_CP_FENCE1_RDATA_1 0x4C8A2A8

#define mmPDMA0_QM_CP_FENCE1_RDATA_2 0x4C8A2AC

#define mmPDMA0_QM_CP_FENCE1_RDATA_3 0x4C8A2B0

#define mmPDMA0_QM_CP_FENCE1_RDATA_4 0x4C8A2B4

#define mmPDMA0_QM_CP_FENCE2_RDATA_0 0x4C8A2B8

#define mmPDMA0_QM_CP_FENCE2_RDATA_1 0x4C8A2BC

#define mmPDMA0_QM_CP_FENCE2_RDATA_2 0x4C8A2C0

#define mmPDMA0_QM_CP_FENCE2_RDATA_3 0x4C8A2C4

#define mmPDMA0_QM_CP_FENCE2_RDATA_4 0x4C8A2C8

#define mmPDMA0_QM_CP_FENCE3_RDATA_0 0x4C8A2CC

#define mmPDMA0_QM_CP_FENCE3_RDATA_1 0x4C8A2D0

#define mmPDMA0_QM_CP_FENCE3_RDATA_2 0x4C8A2D4

#define mmPDMA0_QM_CP_FENCE3_RDATA_3 0x4C8A2D8

#define mmPDMA0_QM_CP_FENCE3_RDATA_4 0x4C8A2DC

#define mmPDMA0_QM_CP_FENCE0_CNT_0 0x4C8A2E0

#define mmPDMA0_QM_CP_FENCE0_CNT_1 0x4C8A2E4

#define mmPDMA0_QM_CP_FENCE0_CNT_2 0x4C8A2E8

#define mmPDMA0_QM_CP_FENCE0_CNT_3 0x4C8A2EC

#define mmPDMA0_QM_CP_FENCE0_CNT_4 0x4C8A2F0

#define mmPDMA0_QM_CP_FENCE1_CNT_0 0x4C8A2F4

#define mmPDMA0_QM_CP_FENCE1_CNT_1 0x4C8A2F8

#define mmPDMA0_QM_CP_FENCE1_CNT_2 0x4C8A2FC

#define mmPDMA0_QM_CP_FENCE1_CNT_3 0x4C8A300

#define mmPDMA0_QM_CP_FENCE1_CNT_4 0x4C8A304

#define mmPDMA0_QM_CP_FENCE2_CNT_0 0x4C8A308

#define mmPDMA0_QM_CP_FENCE2_CNT_1 0x4C8A30C

#define mmPDMA0_QM_CP_FENCE2_CNT_2 0x4C8A310

#define mmPDMA0_QM_CP_FENCE2_CNT_3 0x4C8A314

#define mmPDMA0_QM_CP_FENCE2_CNT_4 0x4C8A318

#define mmPDMA0_QM_CP_FENCE3_CNT_0 0x4C8A31C

#define mmPDMA0_QM_CP_FENCE3_CNT_1 0x4C8A320

#define mmPDMA0_QM_CP_FENCE3_CNT_2 0x4C8A324

#define mmPDMA0_QM_CP_FENCE3_CNT_3 0x4C8A328

#define mmPDMA0_QM_CP_FENCE3_CNT_4 0x4C8A32C

#define mmPDMA0_QM_CP_BARRIER_CFG 0x4C8A330

#define mmPDMA0_QM_CP_LDMA_SRC_BASE_LO_OFFSET 0x4C8A334

#define mmPDMA0_QM_CP_LDMA_DST_BASE_LO_OFFSET 0x4C8A338

#define mmPDMA0_QM_CP_LDMA_TSIZE_OFFSET 0x4C8A33C

#define mmPDMA0_QM_CP_CQ_PTR_LO_OFFSET_0 0x4C8A340

#define mmPDMA0_QM_CP_CQ_PTR_LO_OFFSET_1 0x4C8A344

#define mmPDMA0_QM_CP_CQ_PTR_LO_OFFSET_2 0x4C8A348

#define mmPDMA0_QM_CP_CQ_PTR_LO_OFFSET_3 0x4C8A34C

#define mmPDMA0_QM_CP_CQ_PTR_LO_OFFSET_4 0x4C8A350

#define mmPDMA0_QM_CP_STS_0 0x4C8A368

#define mmPDMA0_QM_CP_STS_1 0x4C8A36C

#define mmPDMA0_QM_CP_STS_2 0x4C8A370

#define mmPDMA0_QM_CP_STS_3 0x4C8A374

#define mmPDMA0_QM_CP_STS_4 0x4C8A378

#define mmPDMA0_QM_CP_CURRENT_INST_LO_0 0x4C8A37C

#define mmPDMA0_QM_CP_CURRENT_INST_LO_1 0x4C8A380

#define mmPDMA0_QM_CP_CURRENT_INST_LO_2 0x4C8A384

#define mmPDMA0_QM_CP_CURRENT_INST_LO_3 0x4C8A388

#define mmPDMA0_QM_CP_CURRENT_INST_LO_4 0x4C8A38C

#define mmPDMA0_QM_CP_CURRENT_INST_HI_0 0x4C8A390

#define mmPDMA0_QM_CP_CURRENT_INST_HI_1 0x4C8A394

#define mmPDMA0_QM_CP_CURRENT_INST_HI_2 0x4C8A398

#define mmPDMA0_QM_CP_CURRENT_INST_HI_3 0x4C8A39C

#define mmPDMA0_QM_CP_CURRENT_INST_HI_4 0x4C8A3A0

#define mmPDMA0_QM_CP_PRED_0 0x4C8A3A4

#define mmPDMA0_QM_CP_PRED_1 0x4C8A3A8

#define mmPDMA0_QM_CP_PRED_2 0x4C8A3AC

#define mmPDMA0_QM_CP_PRED_3 0x4C8A3B0

#define mmPDMA0_QM_CP_PRED_4 0x4C8A3B4

#define mmPDMA0_QM_CP_PRED_UPEN_0 0x4C8A3B8

#define mmPDMA0_QM_CP_PRED_UPEN_1 0x4C8A3BC

#define mmPDMA0_QM_CP_PRED_UPEN_2 0x4C8A3C0

#define mmPDMA0_QM_CP_PRED_UPEN_3 0x4C8A3C4

#define mmPDMA0_QM_CP_PRED_UPEN_4 0x4C8A3C8

#define mmPDMA0_QM_CP_DBG_0_0 0x4C8A3CC

#define mmPDMA0_QM_CP_DBG_0_1 0x4C8A3D0

#define mmPDMA0_QM_CP_DBG_0_2 0x4C8A3D4

#define mmPDMA0_QM_CP_DBG_0_3 0x4C8A3D8

#define mmPDMA0_QM_CP_DBG_0_4 0x4C8A3DC

#define mmPDMA0_QM_CP_CPDMA_UP_CRED_0 0x4C8A3E0

#define mmPDMA0_QM_CP_CPDMA_UP_CRED_1 0x4C8A3E4

#define mmPDMA0_QM_CP_CPDMA_UP_CRED_2 0x4C8A3E8

#define mmPDMA0_QM_CP_CPDMA_UP_CRED_3 0x4C8A3EC

#define mmPDMA0_QM_CP_CPDMA_UP_CRED_4 0x4C8A3F0

#define mmPDMA0_QM_CP_IN_DATA_LO_0 0x4C8A3F4

#define mmPDMA0_QM_CP_IN_DATA_LO_1 0x4C8A3F8

#define mmPDMA0_QM_CP_IN_DATA_LO_2 0x4C8A3FC

#define mmPDMA0_QM_CP_IN_DATA_LO_3 0x4C8A400

#define mmPDMA0_QM_CP_IN_DATA_LO_4 0x4C8A404

#define mmPDMA0_QM_CP_IN_DATA_HI_0 0x4C8A408

#define mmPDMA0_QM_CP_IN_DATA_HI_1 0x4C8A40C

#define mmPDMA0_QM_CP_IN_DATA_HI_2 0x4C8A410

#define mmPDMA0_QM_CP_IN_DATA_HI_3 0x4C8A414

#define mmPDMA0_QM_CP_IN_DATA_HI_4 0x4C8A418

#define mmPDMA0_QM_PQC_HBW_BASE_LO_0 0x4C8A41C

#define mmPDMA0_QM_PQC_HBW_BASE_LO_1 0x4C8A420

#define mmPDMA0_QM_PQC_HBW_BASE_LO_2 0x4C8A424

#define mmPDMA0_QM_PQC_HBW_BASE_LO_3 0x4C8A428

#define mmPDMA0_QM_PQC_HBW_BASE_HI_0 0x4C8A42C

#define mmPDMA0_QM_PQC_HBW_BASE_HI_1 0x4C8A430

#define mmPDMA0_QM_PQC_HBW_BASE_HI_2 0x4C8A434

#define mmPDMA0_QM_PQC_HBW_BASE_HI_3 0x4C8A438

#define mmPDMA0_QM_PQC_SIZE_0 0x4C8A43C

#define mmPDMA0_QM_PQC_SIZE_1 0x4C8A440

#define mmPDMA0_QM_PQC_SIZE_2 0x4C8A444

#define mmPDMA0_QM_PQC_SIZE_3 0x4C8A448

#define mmPDMA0_QM_PQC_PI_0 0x4C8A44C

#define mmPDMA0_QM_PQC_PI_1 0x4C8A450

#define mmPDMA0_QM_PQC_PI_2 0x4C8A454

#define mmPDMA0_QM_PQC_PI_3 0x4C8A458

#define mmPDMA0_QM_PQC_LBW_WDATA_0 0x4C8A45C

#define mmPDMA0_QM_PQC_LBW_WDATA_1 0x4C8A460

#define mmPDMA0_QM_PQC_LBW_WDATA_2 0x4C8A464

#define mmPDMA0_QM_PQC_LBW_WDATA_3 0x4C8A468

#define mmPDMA0_QM_PQC_LBW_BASE_LO_0 0x4C8A46C

#define mmPDMA0_QM_PQC_LBW_BASE_LO_1 0x4C8A470

#define mmPDMA0_QM_PQC_LBW_BASE_LO_2 0x4C8A474

#define mmPDMA0_QM_PQC_LBW_BASE_LO_3 0x4C8A478

#define mmPDMA0_QM_PQC_LBW_BASE_HI_0 0x4C8A47C

#define mmPDMA0_QM_PQC_LBW_BASE_HI_1 0x4C8A480

#define mmPDMA0_QM_PQC_LBW_BASE_HI_2 0x4C8A484

#define mmPDMA0_QM_PQC_LBW_BASE_HI_3 0x4C8A488

#define mmPDMA0_QM_PQC_CFG 0x4C8A48C

#define mmPDMA0_QM_PQC_SECURE_PUSH_IND 0x4C8A490

#define mmPDMA0_QM_ARB_MASK 0x4C8A4A0

#define mmPDMA0_QM_ARB_CFG_0 0x4C8A4A4

#define mmPDMA0_QM_ARB_CHOICE_Q_PUSH 0x4C8A4A8

#define mmPDMA0_QM_ARB_WRR_WEIGHT_0 0x4C8A4AC

#define mmPDMA0_QM_ARB_WRR_WEIGHT_1 0x4C8A4B0

#define mmPDMA0_QM_ARB_WRR_WEIGHT_2 0x4C8A4B4

#define mmPDMA0_QM_ARB_WRR_WEIGHT_3 0x4C8A4B8

#define mmPDMA0_QM_ARB_CFG_1 0x4C8A4BC

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_0 0x4C8A4C0

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_1 0x4C8A4C4

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_2 0x4C8A4C8

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_3 0x4C8A4CC

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_4 0x4C8A4D0

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_5 0x4C8A4D4

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_6 0x4C8A4D8

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_7 0x4C8A4DC

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_8 0x4C8A4E0

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_9 0x4C8A4E4

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_10 0x4C8A4E8

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_11 0x4C8A4EC

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_12 0x4C8A4F0

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_13 0x4C8A4F4

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_14 0x4C8A4F8

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_15 0x4C8A4FC

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_16 0x4C8A500

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_17 0x4C8A504

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_18 0x4C8A508

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_19 0x4C8A50C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_20 0x4C8A510

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_21 0x4C8A514

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_22 0x4C8A518

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_23 0x4C8A51C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_24 0x4C8A520

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_25 0x4C8A524

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_26 0x4C8A528

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_27 0x4C8A52C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_28 0x4C8A530

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_29 0x4C8A534

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_30 0x4C8A538

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_31 0x4C8A53C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_32 0x4C8A540

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_33 0x4C8A544

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_34 0x4C8A548

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_35 0x4C8A54C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_36 0x4C8A550

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_37 0x4C8A554

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_38 0x4C8A558

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_39 0x4C8A55C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_40 0x4C8A560

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_41 0x4C8A564

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_42 0x4C8A568

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_43 0x4C8A56C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_44 0x4C8A570

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_45 0x4C8A574

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_46 0x4C8A578

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_47 0x4C8A57C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_48 0x4C8A580

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_49 0x4C8A584

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_50 0x4C8A588

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_51 0x4C8A58C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_52 0x4C8A590

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_53 0x4C8A594

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_54 0x4C8A598

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_55 0x4C8A59C

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_56 0x4C8A5A0

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_57 0x4C8A5A4

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_58 0x4C8A5A8

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_59 0x4C8A5AC

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_60 0x4C8A5B0

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_61 0x4C8A5B4

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_62 0x4C8A5B8

#define mmPDMA0_QM_ARB_MST_AVAIL_CRED_63 0x4C8A5BC

#define mmPDMA0_QM_ARB_MST_CRED_INC 0x4C8A5E0

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_0 0x4C8A5E4

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_1 0x4C8A5E8

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_2 0x4C8A5EC

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_3 0x4C8A5F0

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_4 0x4C8A5F4

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_5 0x4C8A5F8

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_6 0x4C8A5FC

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_7 0x4C8A600

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_8 0x4C8A604

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_9 0x4C8A608

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_10 0x4C8A60C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_11 0x4C8A610

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_12 0x4C8A614

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_13 0x4C8A618

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_14 0x4C8A61C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_15 0x4C8A620

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_16 0x4C8A624

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_17 0x4C8A628

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_18 0x4C8A62C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_19 0x4C8A630

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_20 0x4C8A634

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_21 0x4C8A638

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_22 0x4C8A63C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_23 0x4C8A640

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_24 0x4C8A644

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_25 0x4C8A648

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_26 0x4C8A64C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_27 0x4C8A650

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_28 0x4C8A654

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_29 0x4C8A658

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_30 0x4C8A65C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_31 0x4C8A660

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_32 0x4C8A664

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_33 0x4C8A668

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_34 0x4C8A66C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_35 0x4C8A670

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_36 0x4C8A674

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_37 0x4C8A678

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_38 0x4C8A67C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_39 0x4C8A680

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_40 0x4C8A684

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_41 0x4C8A688

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_42 0x4C8A68C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_43 0x4C8A690

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_44 0x4C8A694

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_45 0x4C8A698

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_46 0x4C8A69C

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_47 0x4C8A6A0

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_48 0x4C8A6A4

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_49 0x4C8A6A8

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_50 0x4C8A6AC

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_51 0x4C8A6B0

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_52 0x4C8A6B4

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_53 0x4C8A6B8

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_54 0x4C8A6BC

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_55 0x4C8A6C0

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_56 0x4C8A6C4

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_57 0x4C8A6C8

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_58 0x4C8A6CC

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_59 0x4C8A6D0

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_60 0x4C8A6D4

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_61 0x4C8A6D8

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_62 0x4C8A6DC

#define mmPDMA0_QM_ARB_MST_CHOICE_PUSH_OFST_63 0x4C8A6E0

#define mmPDMA0_QM_ARB_SLV_MASTER_INC_CRED_OFST 0x4C8A704

#define mmPDMA0_QM_ARB_MST_SLAVE_EN 0x4C8A708

#define mmPDMA0_QM_ARB_MST_SLAVE_EN_1 0x4C8A70C

#define mmPDMA0_QM_ARB_SLV_CHOICE_WDT 0x4C8A710

#define mmPDMA0_QM_ARB_SLV_ID 0x4C8A714

#define mmPDMA0_QM_ARB_MST_QUIET_PER 0x4C8A718

#define mmPDMA0_QM_ARB_MSG_MAX_INFLIGHT 0x4C8A744

#define mmPDMA0_QM_ARB_BASE_LO 0x4C8A754

#define mmPDMA0_QM_ARB_BASE_HI 0x4C8A758

#define mmPDMA0_QM_ARB_STATE_STS 0x4C8A780

#define mmPDMA0_QM_ARB_CHOICE_FULLNESS_STS 0x4C8A784

#define mmPDMA0_QM_ARB_MSG_STS 0x4C8A788

#define mmPDMA0_QM_ARB_SLV_CHOICE_Q_HEAD 0x4C8A78C

#define mmPDMA0_QM_ARB_ERR_CAUSE 0x4C8A79C

#define mmPDMA0_QM_ARB_ERR_MSG_EN 0x4C8A7A0

#define mmPDMA0_QM_ARB_ERR_STS_DRP 0x4C8A7A8

#define mmPDMA0_QM_ARB_MST_CRED_STS 0x4C8A7B0

#define mmPDMA0_QM_ARB_MST_CRED_STS_1 0x4C8A7B4

#define mmPDMA0_QM_CSMR_STRICT_PRIO_CFG 0x4C8A7FC

#define mmPDMA0_QM_ARC_CQ_CFG0 0x4C8A800

#define mmPDMA0_QM_ARC_CQ_CFG1 0x4C8A804

#define mmPDMA0_QM_ARC_CQ_PTR_LO 0x4C8A808

#define mmPDMA0_QM_ARC_CQ_PTR_HI 0x4C8A80C

#define mmPDMA0_QM_ARC_CQ_TSIZE 0x4C8A810

#define mmPDMA0_QM_ARC_CQ_CTL 0x4C8A814

#define mmPDMA0_QM_ARC_CQ_IFIFO_STS 0x4C8A81C

#define mmPDMA0_QM_ARC_CQ_STS0 0x4C8A820

#define mmPDMA0_QM_ARC_CQ_STS1 0x4C8A824

#define mmPDMA0_QM_ARC_CQ_TSIZE_STS 0x4C8A828

#define mmPDMA0_QM_ARC_CQ_PTR_LO_STS 0x4C8A82C

#define mmPDMA0_QM_ARC_CQ_PTR_HI_STS 0x4C8A830

#define mmPDMA0_QM_CP_WR_ARC_ADDR_HI 0x4C8A834

#define mmPDMA0_QM_CP_WR_ARC_ADDR_LO 0x4C8A838

#define mmPDMA0_QM_ARC_CQ_IFIFO_MSG_BASE_HI 0x4C8A83C

#define mmPDMA0_QM_ARC_CQ_IFIFO_MSG_BASE_LO 0x4C8A840

#define mmPDMA0_QM_ARC_CQ_CTL_MSG_BASE_HI 0x4C8A844

#define mmPDMA0_QM_ARC_CQ_CTL_MSG_BASE_LO 0x4C8A848

#define mmPDMA0_QM_CQ_IFIFO_MSG_BASE_HI 0x4C8A84C

#define mmPDMA0_QM_CQ_IFIFO_MSG_BASE_LO 0x4C8A850

#define mmPDMA0_QM_CQ_CTL_MSG_BASE_HI 0x4C8A854

#define mmPDMA0_QM_CQ_CTL_MSG_BASE_LO 0x4C8A858

#define mmPDMA0_QM_ADDR_OVRD 0x4C8A85C

#define mmPDMA0_QM_CQ_IFIFO_CI_0 0x4C8A860

#define mmPDMA0_QM_CQ_IFIFO_CI_1 0x4C8A864

#define mmPDMA0_QM_CQ_IFIFO_CI_2 0x4C8A868

#define mmPDMA0_QM_CQ_IFIFO_CI_3 0x4C8A86C

#define mmPDMA0_QM_CQ_IFIFO_CI_4 0x4C8A870

#define mmPDMA0_QM_ARC_CQ_IFIFO_CI 0x4C8A874

#define mmPDMA0_QM_CQ_CTL_CI_0 0x4C8A878

#define mmPDMA0_QM_CQ_CTL_CI_1 0x4C8A87C

#define mmPDMA0_QM_CQ_CTL_CI_2 0x4C8A880

#define mmPDMA0_QM_CQ_CTL_CI_3 0x4C8A884

#define mmPDMA0_QM_CQ_CTL_CI_4 0x4C8A888

#define mmPDMA0_QM_ARC_CQ_CTL_CI 0x4C8A88C

#define mmPDMA0_QM_CP_CFG 0x4C8A890

#define mmPDMA0_QM_CP_EXT_SWITCH 0x4C8A894

#define mmPDMA0_QM_CP_SWITCH_WD_SET 0x4C8A898

#define mmPDMA0_QM_CP_SWITCH_WD 0x4C8A89C

#define mmPDMA0_QM_ARC_LB_ADDR_BASE_LO 0x4C8A8A4

#define mmPDMA0_QM_ARC_LB_ADDR_BASE_HI 0x4C8A8A8

#define mmPDMA0_QM_ENGINE_BASE_ADDR_HI 0x4C8A8AC

#define mmPDMA0_QM_ENGINE_BASE_ADDR_LO 0x4C8A8B0

#define mmPDMA0_QM_ENGINE_ADDR_RANGE_SIZE 0x4C8A8B4

#define mmPDMA0_QM_QM_ARC_AUX_BASE_ADDR_HI 0x4C8A8B8

#define mmPDMA0_QM_QM_ARC_AUX_BASE_ADDR_LO 0x4C8A8BC

#define mmPDMA0_QM_QM_BASE_ADDR_HI 0x4C8A8C0

#define mmPDMA0_QM_QM_BASE_ADDR_LO 0x4C8A8C4

#define mmPDMA0_QM_ARC_PQC_SECURE_PUSH_IND 0x4C8A8C8

#define mmPDMA0_QM_PQC_STS_0_0 0x4C8A8D0

#define mmPDMA0_QM_PQC_STS_0_1 0x4C8A8D4

#define mmPDMA0_QM_PQC_STS_0_2 0x4C8A8D8

#define mmPDMA0_QM_PQC_STS_0_3 0x4C8A8DC

#define mmPDMA0_QM_PQC_STS_1_0 0x4C8A8E0

#define mmPDMA0_QM_PQC_STS_1_1 0x4C8A8E4

#define mmPDMA0_QM_PQC_STS_1_2 0x4C8A8E8

#define mmPDMA0_QM_PQC_STS_1_3 0x4C8A8EC

#define mmPDMA0_QM_SEI_STATUS 0x4C8A8F0

#define mmPDMA0_QM_SEI_MASK 0x4C8A8F4

#define mmPDMA0_QM_GLBL_ERR_ADDR_LO 0x4C8AD00

#define mmPDMA0_QM_GLBL_ERR_ADDR_HI 0x4C8AD04

#define mmPDMA0_QM_GLBL_ERR_WDATA 0x4C8AD08

#define mmPDMA0_QM_L2H_MASK_LO 0x4C8AD14

#define mmPDMA0_QM_L2H_MASK_HI 0x4C8AD18

#define mmPDMA0_QM_L2H_CMPR_LO 0x4C8AD1C

#define mmPDMA0_QM_L2H_CMPR_HI 0x4C8AD20

#define mmPDMA0_QM_LOCAL_RANGE_BASE 0x4C8AD24

#define mmPDMA0_QM_LOCAL_RANGE_SIZE 0x4C8AD28

#define mmPDMA0_QM_HBW_RD_RATE_LIM_CFG_1 0x4C8AD30

#define mmPDMA0_QM_LBW_WR_RATE_LIM_CFG_0 0x4C8AD34

#define mmPDMA0_QM_LBW_WR_RATE_LIM_CFG_1 0x4C8AD38

#define mmPDMA0_QM_HBW_RD_RATE_LIM_CFG_0 0x4C8AD3C

#define mmPDMA0_QM_IND_GW_APB_CFG 0x4C8AD40

#define mmPDMA0_QM_IND_GW_APB_WDATA 0x4C8AD44

#define mmPDMA0_QM_IND_GW_APB_RDATA 0x4C8AD48

#define mmPDMA0_QM_IND_GW_APB_STATUS 0x4C8AD4C

#define mmPDMA0_QM_PERF_CNT_FREE_LO 0x4C8AD60

#define mmPDMA0_QM_PERF_CNT_FREE_HI 0x4C8AD64

#define mmPDMA0_QM_PERF_CNT_IDLE_LO 0x4C8AD68

#define mmPDMA0_QM_PERF_CNT_IDLE_HI 0x4C8AD6C

#define mmPDMA0_QM_PERF_CNT_CFG 0x4C8AD70

#endif /* ASIC_REG_PDMA0_QM_REGS_H_ */