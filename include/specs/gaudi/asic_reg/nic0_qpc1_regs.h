/* SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2018 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

/************************************
 ** This is an auto-generated file **
 **       DO NOT EDIT BELOW        **
 ************************************/

#ifndef ASIC_REG_NIC0_QPC1_REGS_H_
#define ASIC_REG_NIC0_QPC1_REGS_H_

/*
 *****************************************
 *   NIC0_QPC1 (Prototype: NIC_QPC)
 *****************************************
 */

#define mmNIC0_QPC1_REQ_QPC_CACHE_INVALIDATE                         0xCE5000

#define mmNIC0_QPC1_REQ_QPC_CACHE_INV_STATUS                         0xCE5004

#define mmNIC0_QPC1_REQ_STATIC_CONFIG                                0xCE5008

#define mmNIC0_QPC1_REQ_BASE_ADDRESS_49_18                           0xCE500C

#define mmNIC0_QPC1_REQ_BASE_ADDRESS_17_7                            0xCE5010

#define mmNIC0_QPC1_REQ_CLEAN_LINK_LIST                              0xCE5014

#define mmNIC0_QPC1_REQ_ERR_FIFO_PUSH_63_32                          0xCE5018

#define mmNIC0_QPC1_REQ_ERR_FIFO_PUSH_31_0                           0xCE501C

#define mmNIC0_QPC1_REQ_ERR_QP_STATE_63_32                           0xCE5020

#define mmNIC0_QPC1_REQ_ERR_QP_STATE_31_0                            0xCE5024

#define mmNIC0_QPC1_RETRY_COUNT_MAX                                  0xCE5028

#define mmNIC0_QPC1_AXI_USER                                         0xCE502C

#define mmNIC0_QPC1_AXI_PROT                                         0xCE5030

#define mmNIC0_QPC1_RES_QPC_CACHE_INVALIDATE                         0xCE5034

#define mmNIC0_QPC1_RES_QPC_CACHE_INV_STATUS                         0xCE5038

#define mmNIC0_QPC1_RES_STATIC_CONFIG                                0xCE503C

#define mmNIC0_QPC1_RES_BASE_ADDRESS_49_18                           0xCE5040

#define mmNIC0_QPC1_RES_BASE_ADDRESS_17_7                            0xCE5044

#define mmNIC0_QPC1_RES_CLEAN_LINK_LIST                              0xCE5048

#define mmNIC0_QPC1_ERR_FIFO_WRITE_INDEX                             0xCE5050

#define mmNIC0_QPC1_ERR_FIFO_PRODUCER_INDEX                          0xCE5054

#define mmNIC0_QPC1_ERR_FIFO_CONSUMER_INDEX                          0xCE5058

#define mmNIC0_QPC1_ERR_FIFO_MASK                                    0xCE505C

#define mmNIC0_QPC1_ERR_FIFO_CREDIT                                  0xCE5060

#define mmNIC0_QPC1_ERR_FIFO_CFG                                     0xCE5064

#define mmNIC0_QPC1_ERR_FIFO_INTR_MASK                               0xCE5068

#define mmNIC0_QPC1_ERR_FIFO_BASE_ADDR_49_18                         0xCE506C

#define mmNIC0_QPC1_ERR_FIFO_BASE_ADDR_17_7                          0xCE5070

#define mmNIC0_QPC1_GW_BUSY                                          0xCE5080

#define mmNIC0_QPC1_GW_CTRL                                          0xCE5084

#define mmNIC0_QPC1_GW_DATA_0                                        0xCE508C

#define mmNIC0_QPC1_GW_DATA_1                                        0xCE5090

#define mmNIC0_QPC1_GW_DATA_2                                        0xCE5094

#define mmNIC0_QPC1_GW_DATA_3                                        0xCE5098

#define mmNIC0_QPC1_GW_DATA_4                                        0xCE509C

#define mmNIC0_QPC1_GW_DATA_5                                        0xCE50A0

#define mmNIC0_QPC1_GW_DATA_6                                        0xCE50A4

#define mmNIC0_QPC1_GW_DATA_7                                        0xCE50A8

#define mmNIC0_QPC1_GW_DATA_8                                        0xCE50AC

#define mmNIC0_QPC1_GW_DATA_9                                        0xCE50B0

#define mmNIC0_QPC1_GW_DATA_10                                       0xCE50B4

#define mmNIC0_QPC1_GW_DATA_11                                       0xCE50B8

#define mmNIC0_QPC1_GW_DATA_12                                       0xCE50BC

#define mmNIC0_QPC1_GW_DATA_13                                       0xCE50C0

#define mmNIC0_QPC1_GW_DATA_14                                       0xCE50C4

#define mmNIC0_QPC1_GW_DATA_15                                       0xCE50C8

#define mmNIC0_QPC1_GW_MASK_0                                        0xCE5124

#define mmNIC0_QPC1_GW_MASK_1                                        0xCE5128

#define mmNIC0_QPC1_GW_MASK_2                                        0xCE512C

#define mmNIC0_QPC1_GW_MASK_3                                        0xCE5130

#define mmNIC0_QPC1_GW_MASK_4                                        0xCE5134

#define mmNIC0_QPC1_GW_MASK_5                                        0xCE5138

#define mmNIC0_QPC1_GW_MASK_6                                        0xCE513C

#define mmNIC0_QPC1_GW_MASK_7                                        0xCE5140

#define mmNIC0_QPC1_GW_MASK_8                                        0xCE5144

#define mmNIC0_QPC1_GW_MASK_9                                        0xCE5148

#define mmNIC0_QPC1_GW_MASK_10                                       0xCE514C

#define mmNIC0_QPC1_GW_MASK_11                                       0xCE5150

#define mmNIC0_QPC1_GW_MASK_12                                       0xCE5154

#define mmNIC0_QPC1_GW_MASK_13                                       0xCE5158

#define mmNIC0_QPC1_GW_MASK_14                                       0xCE515C

#define mmNIC0_QPC1_GW_MASK_15                                       0xCE5160

#define mmNIC0_QPC1_CC_WINDOW_INC_EN                                 0xCE51FC

#define mmNIC0_QPC1_CC_TICK_WRAP                                     0xCE5200

#define mmNIC0_QPC1_CC_ROLLBACK                                      0xCE5204

#define mmNIC0_QPC1_CC_MAX_WINDOW_SIZE                               0xCE5208

#define mmNIC0_QPC1_CC_MIN_WINDOW_SIZE                               0xCE520C

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_0                                0xCE5210

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_1                                0xCE5214

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_2                                0xCE5218

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_3                                0xCE521C

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_4                                0xCE5220

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_5                                0xCE5224

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_6                                0xCE5228

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_7                                0xCE522C

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_8                                0xCE5230

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_9                                0xCE5234

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_10                               0xCE5238

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_11                               0xCE523C

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_12                               0xCE5240

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_13                               0xCE5244

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_14                               0xCE5248

#define mmNIC0_QPC1_CC_ALPHA_LINEAR_15                               0xCE524C

#define mmNIC0_QPC1_CC_ALPHA_LOG_0                                   0xCE5250

#define mmNIC0_QPC1_CC_ALPHA_LOG_1                                   0xCE5254

#define mmNIC0_QPC1_CC_ALPHA_LOG_2                                   0xCE5258

#define mmNIC0_QPC1_CC_ALPHA_LOG_3                                   0xCE525C

#define mmNIC0_QPC1_CC_ALPHA_LOG_4                                   0xCE5260

#define mmNIC0_QPC1_CC_ALPHA_LOG_5                                   0xCE5264

#define mmNIC0_QPC1_CC_ALPHA_LOG_6                                   0xCE5268

#define mmNIC0_QPC1_CC_ALPHA_LOG_7                                   0xCE526C

#define mmNIC0_QPC1_CC_ALPHA_LOG_8                                   0xCE5270

#define mmNIC0_QPC1_CC_ALPHA_LOG_9                                   0xCE5274

#define mmNIC0_QPC1_CC_ALPHA_LOG_10                                  0xCE5278

#define mmNIC0_QPC1_CC_ALPHA_LOG_11                                  0xCE527C

#define mmNIC0_QPC1_CC_ALPHA_LOG_12                                  0xCE5280

#define mmNIC0_QPC1_CC_ALPHA_LOG_13                                  0xCE5284

#define mmNIC0_QPC1_CC_ALPHA_LOG_14                                  0xCE5288

#define mmNIC0_QPC1_CC_ALPHA_LOG_15                                  0xCE528C

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_0                         0xCE5290

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_1                         0xCE5294

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_2                         0xCE5298

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_3                         0xCE529C

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_4                         0xCE52A0

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_5                         0xCE52A4

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_6                         0xCE52A8

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_7                         0xCE52AC

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_8                         0xCE52B0

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_9                         0xCE52B4

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_10                        0xCE52B8

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_11                        0xCE52BC

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_12                        0xCE52C0

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_13                        0xCE52C4

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_14                        0xCE52C8

#define mmNIC0_QPC1_CC_ALPHA_LOG_THRESHOLD_15                        0xCE52CC

#define mmNIC0_QPC1_CC_WINDOW_INC_0                                  0xCE52D0

#define mmNIC0_QPC1_CC_WINDOW_INC_1                                  0xCE52D4

#define mmNIC0_QPC1_CC_WINDOW_INC_2                                  0xCE52D8

#define mmNIC0_QPC1_CC_WINDOW_INC_3                                  0xCE52DC

#define mmNIC0_QPC1_CC_WINDOW_INC_4                                  0xCE52E0

#define mmNIC0_QPC1_CC_WINDOW_INC_5                                  0xCE52E4

#define mmNIC0_QPC1_CC_WINDOW_INC_6                                  0xCE52E8

#define mmNIC0_QPC1_CC_WINDOW_INC_7                                  0xCE52EC

#define mmNIC0_QPC1_CC_WINDOW_INC_8                                  0xCE52F0

#define mmNIC0_QPC1_CC_WINDOW_INC_9                                  0xCE52F4

#define mmNIC0_QPC1_CC_WINDOW_INC_10                                 0xCE52F8

#define mmNIC0_QPC1_CC_WINDOW_INC_11                                 0xCE52FC

#define mmNIC0_QPC1_CC_WINDOW_INC_12                                 0xCE5300

#define mmNIC0_QPC1_CC_WINDOW_INC_13                                 0xCE5304

#define mmNIC0_QPC1_CC_WINDOW_INC_14                                 0xCE5308

#define mmNIC0_QPC1_CC_WINDOW_INC_15                                 0xCE530C

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_0                         0xCE5310

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_1                         0xCE5314

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_2                         0xCE5318

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_3                         0xCE531C

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_4                         0xCE5320

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_5                         0xCE5324

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_6                         0xCE5328

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_7                         0xCE532C

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_8                         0xCE5330

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_9                         0xCE5334

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_10                        0xCE5338

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_11                        0xCE533C

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_12                        0xCE5340

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_13                        0xCE5344

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_14                        0xCE5348

#define mmNIC0_QPC1_CC_WINDOW_IN_THRESHOLD_15                        0xCE534C

#define mmNIC0_QPC1_CC_LOG_QPC_0                                     0xCE5350

#define mmNIC0_QPC1_CC_LOG_QPC_1                                     0xCE5354

#define mmNIC0_QPC1_CC_LOG_QPC_2                                     0xCE5358

#define mmNIC0_QPC1_CC_LOG_QPC_3                                     0xCE535C

#define mmNIC0_QPC1_CC_LOG_QPC_4                                     0xCE5360

#define mmNIC0_QPC1_CC_LOG_QPC_5                                     0xCE5364

#define mmNIC0_QPC1_CC_LOG_QPC_6                                     0xCE5368

#define mmNIC0_QPC1_CC_LOG_QPC_7                                     0xCE536C

#define mmNIC0_QPC1_CC_LOG_QPC_8                                     0xCE5370

#define mmNIC0_QPC1_CC_LOG_QPC_9                                     0xCE5374

#define mmNIC0_QPC1_CC_LOG_QPC_10                                    0xCE5378

#define mmNIC0_QPC1_CC_LOG_QPC_11                                    0xCE537C

#define mmNIC0_QPC1_CC_LOG_QPC_12                                    0xCE5380

#define mmNIC0_QPC1_CC_LOG_QPC_13                                    0xCE5384

#define mmNIC0_QPC1_CC_LOG_QPC_14                                    0xCE5388

#define mmNIC0_QPC1_CC_LOG_QPC_15                                    0xCE538C

#define mmNIC0_QPC1_CC_LOG_QPC_16                                    0xCE5390

#define mmNIC0_QPC1_CC_LOG_QPC_17                                    0xCE5394

#define mmNIC0_QPC1_CC_LOG_QPC_18                                    0xCE5398

#define mmNIC0_QPC1_CC_LOG_QPC_19                                    0xCE539C

#define mmNIC0_QPC1_CC_LOG_QPC_20                                    0xCE53A0

#define mmNIC0_QPC1_CC_LOG_QPC_21                                    0xCE53A4

#define mmNIC0_QPC1_CC_LOG_QPC_22                                    0xCE53A8

#define mmNIC0_QPC1_CC_LOG_QPC_23                                    0xCE53AC

#define mmNIC0_QPC1_CC_LOG_QPC_24                                    0xCE53B0

#define mmNIC0_QPC1_CC_LOG_QPC_25                                    0xCE53B4

#define mmNIC0_QPC1_CC_LOG_QPC_26                                    0xCE53B8

#define mmNIC0_QPC1_CC_LOG_QPC_27                                    0xCE53BC

#define mmNIC0_QPC1_CC_LOG_QPC_28                                    0xCE53C0

#define mmNIC0_QPC1_CC_LOG_QPC_29                                    0xCE53C4

#define mmNIC0_QPC1_CC_LOG_QPC_30                                    0xCE53C8

#define mmNIC0_QPC1_CC_LOG_QPC_31                                    0xCE53CC

#define mmNIC0_QPC1_CC_LOG_TX_0                                      0xCE53D0

#define mmNIC0_QPC1_CC_LOG_TX_1                                      0xCE53D4

#define mmNIC0_QPC1_CC_LOG_TX_2                                      0xCE53D8

#define mmNIC0_QPC1_CC_LOG_TX_3                                      0xCE53DC

#define mmNIC0_QPC1_CC_LOG_TX_4                                      0xCE53E0

#define mmNIC0_QPC1_CC_LOG_TX_5                                      0xCE53E4

#define mmNIC0_QPC1_CC_LOG_TX_6                                      0xCE53E8

#define mmNIC0_QPC1_CC_LOG_TX_7                                      0xCE53EC

#define mmNIC0_QPC1_CC_LOG_TX_8                                      0xCE53F0

#define mmNIC0_QPC1_CC_LOG_TX_9                                      0xCE53F4

#define mmNIC0_QPC1_CC_LOG_TX_10                                     0xCE53F8

#define mmNIC0_QPC1_CC_LOG_TX_11                                     0xCE53FC

#define mmNIC0_QPC1_CC_LOG_TX_12                                     0xCE5400

#define mmNIC0_QPC1_CC_LOG_TX_13                                     0xCE5404

#define mmNIC0_QPC1_CC_LOG_TX_14                                     0xCE5408

#define mmNIC0_QPC1_CC_LOG_TX_15                                     0xCE540C

#define mmNIC0_QPC1_CC_LOG_TX_16                                     0xCE5410

#define mmNIC0_QPC1_CC_LOG_TX_17                                     0xCE5414

#define mmNIC0_QPC1_CC_LOG_TX_18                                     0xCE5418

#define mmNIC0_QPC1_CC_LOG_TX_19                                     0xCE541C

#define mmNIC0_QPC1_CC_LOG_TX_20                                     0xCE5420

#define mmNIC0_QPC1_CC_LOG_TX_21                                     0xCE5424

#define mmNIC0_QPC1_CC_LOG_TX_22                                     0xCE5428

#define mmNIC0_QPC1_CC_LOG_TX_23                                     0xCE542C

#define mmNIC0_QPC1_CC_LOG_TX_24                                     0xCE5430

#define mmNIC0_QPC1_CC_LOG_TX_25                                     0xCE5434

#define mmNIC0_QPC1_CC_LOG_TX_26                                     0xCE5438

#define mmNIC0_QPC1_CC_LOG_TX_27                                     0xCE543C

#define mmNIC0_QPC1_CC_LOG_TX_28                                     0xCE5440

#define mmNIC0_QPC1_CC_LOG_TX_29                                     0xCE5444

#define mmNIC0_QPC1_CC_LOG_TX_30                                     0xCE5448

#define mmNIC0_QPC1_CC_LOG_TX_31                                     0xCE544C

#define mmNIC0_QPC1_CC_LOG_LATENCY_0                                 0xCE5450

#define mmNIC0_QPC1_CC_LOG_LATENCY_1                                 0xCE5454

#define mmNIC0_QPC1_CC_LOG_LATENCY_2                                 0xCE5458

#define mmNIC0_QPC1_CC_LOG_LATENCY_3                                 0xCE545C

#define mmNIC0_QPC1_CC_LOG_LATENCY_4                                 0xCE5460

#define mmNIC0_QPC1_CC_LOG_LATENCY_5                                 0xCE5464

#define mmNIC0_QPC1_CC_LOG_LATENCY_6                                 0xCE5468

#define mmNIC0_QPC1_CC_LOG_LATENCY_7                                 0xCE546C

#define mmNIC0_QPC1_CC_LOG_LATENCY_8                                 0xCE5470

#define mmNIC0_QPC1_CC_LOG_LATENCY_9                                 0xCE5474

#define mmNIC0_QPC1_CC_LOG_LATENCY_10                                0xCE5478

#define mmNIC0_QPC1_CC_LOG_LATENCY_11                                0xCE547C

#define mmNIC0_QPC1_CC_LOG_LATENCY_12                                0xCE5480

#define mmNIC0_QPC1_CC_LOG_LATENCY_13                                0xCE5484

#define mmNIC0_QPC1_CC_LOG_LATENCY_14                                0xCE5488

#define mmNIC0_QPC1_CC_LOG_LATENCY_15                                0xCE548C

#define mmNIC0_QPC1_CC_LOG_LATENCY_16                                0xCE5490

#define mmNIC0_QPC1_CC_LOG_LATENCY_17                                0xCE5494

#define mmNIC0_QPC1_CC_LOG_LATENCY_18                                0xCE5498

#define mmNIC0_QPC1_CC_LOG_LATENCY_19                                0xCE549C

#define mmNIC0_QPC1_CC_LOG_LATENCY_20                                0xCE54A0

#define mmNIC0_QPC1_CC_LOG_LATENCY_21                                0xCE54A4

#define mmNIC0_QPC1_CC_LOG_LATENCY_22                                0xCE54A8

#define mmNIC0_QPC1_CC_LOG_LATENCY_23                                0xCE54AC

#define mmNIC0_QPC1_CC_LOG_LATENCY_24                                0xCE54B0

#define mmNIC0_QPC1_CC_LOG_LATENCY_25                                0xCE54B4

#define mmNIC0_QPC1_CC_LOG_LATENCY_26                                0xCE54B8

#define mmNIC0_QPC1_CC_LOG_LATENCY_27                                0xCE54BC

#define mmNIC0_QPC1_CC_LOG_LATENCY_28                                0xCE54C0

#define mmNIC0_QPC1_CC_LOG_LATENCY_29                                0xCE54C4

#define mmNIC0_QPC1_CC_LOG_LATENCY_30                                0xCE54C8

#define mmNIC0_QPC1_CC_LOG_LATENCY_31                                0xCE54CC

#define mmNIC0_QPC1_CC_LOG_RX_0                                      0xCE54D0

#define mmNIC0_QPC1_CC_LOG_RX_1                                      0xCE54D4

#define mmNIC0_QPC1_CC_LOG_RX_2                                      0xCE54D8

#define mmNIC0_QPC1_CC_LOG_RX_3                                      0xCE54DC

#define mmNIC0_QPC1_CC_LOG_RX_4                                      0xCE54E0

#define mmNIC0_QPC1_CC_LOG_RX_5                                      0xCE54E4

#define mmNIC0_QPC1_CC_LOG_RX_6                                      0xCE54E8

#define mmNIC0_QPC1_CC_LOG_RX_7                                      0xCE54EC

#define mmNIC0_QPC1_CC_LOG_RX_8                                      0xCE54F0

#define mmNIC0_QPC1_CC_LOG_RX_9                                      0xCE54F4

#define mmNIC0_QPC1_CC_LOG_RX_10                                     0xCE54F8

#define mmNIC0_QPC1_CC_LOG_RX_11                                     0xCE54FC

#define mmNIC0_QPC1_CC_LOG_RX_12                                     0xCE5500

#define mmNIC0_QPC1_CC_LOG_RX_13                                     0xCE5504

#define mmNIC0_QPC1_CC_LOG_RX_14                                     0xCE5508

#define mmNIC0_QPC1_CC_LOG_RX_15                                     0xCE550C

#define mmNIC0_QPC1_CC_LOG_RX_16                                     0xCE5510

#define mmNIC0_QPC1_CC_LOG_RX_17                                     0xCE5514

#define mmNIC0_QPC1_CC_LOG_RX_18                                     0xCE5518

#define mmNIC0_QPC1_CC_LOG_RX_19                                     0xCE551C

#define mmNIC0_QPC1_CC_LOG_RX_20                                     0xCE5520

#define mmNIC0_QPC1_CC_LOG_RX_21                                     0xCE5524

#define mmNIC0_QPC1_CC_LOG_RX_22                                     0xCE5528

#define mmNIC0_QPC1_CC_LOG_RX_23                                     0xCE552C

#define mmNIC0_QPC1_CC_LOG_RX_24                                     0xCE5530

#define mmNIC0_QPC1_CC_LOG_RX_25                                     0xCE5534

#define mmNIC0_QPC1_CC_LOG_RX_26                                     0xCE5538

#define mmNIC0_QPC1_CC_LOG_RX_27                                     0xCE553C

#define mmNIC0_QPC1_CC_LOG_RX_28                                     0xCE5540

#define mmNIC0_QPC1_CC_LOG_RX_29                                     0xCE5544

#define mmNIC0_QPC1_CC_LOG_RX_30                                     0xCE5548

#define mmNIC0_QPC1_CC_LOG_RX_31                                     0xCE554C

#define mmNIC0_QPC1_CC_LOG_WINDOW_SIZE                               0xCE5550

#define mmNIC0_QPC1_DBG_COUNT_SELECT_0                               0xCE5600

#define mmNIC0_QPC1_DBG_COUNT_SELECT_1                               0xCE5604

#define mmNIC0_QPC1_DBG_COUNT_SELECT_2                               0xCE5608

#define mmNIC0_QPC1_DBG_COUNT_SELECT_3                               0xCE560C

#define mmNIC0_QPC1_DBG_COUNT_SELECT_4                               0xCE5610

#define mmNIC0_QPC1_DBG_COUNT_SELECT_5                               0xCE5614

#define mmNIC0_QPC1_DBG_COUNT_SELECT_6                               0xCE5618

#define mmNIC0_QPC1_DBG_COUNT_SELECT_7                               0xCE561C

#define mmNIC0_QPC1_DBG_COUNT_SELECT_8                               0xCE5620

#define mmNIC0_QPC1_DBG_COUNT_SELECT_9                               0xCE5624

#define mmNIC0_QPC1_DBG_COUNT_SELECT_10                              0xCE5628

#define mmNIC0_QPC1_DBG_COUNT_SELECT_11                              0xCE562C

#define mmNIC0_QPC1_UNSECURED_DOORBELL_QPN                           0xCE5630

#define mmNIC0_QPC1_UNSECURED_DOORBELL_PI                            0xCE5634

#define mmNIC0_QPC1_SECURED_DOORBELL_QPN                             0xCE5638

#define mmNIC0_QPC1_SECURED_DOORBELL_PI                              0xCE563C

#define mmNIC0_QPC1_PRIVILEGE_DOORBELL_QPN                           0xCE5640

#define mmNIC0_QPC1_PRIVILEGE_DOORBELL_PI                            0xCE5644

#define mmNIC0_QPC1_DOORBELL_SECURITY                                0xCE5648

#define mmNIC0_QPC1_DGB_TRIG                                         0xCE564C

#define mmNIC0_QPC1_RES_RING0_PI                                     0xCE5650

#define mmNIC0_QPC1_RES_RING0_CI                                     0xCE5654

#define mmNIC0_QPC1_RES_RING0_CFG                                    0xCE5658

#define mmNIC0_QPC1_RES_RING1_PI                                     0xCE565C

#define mmNIC0_QPC1_RES_RING1_CI                                     0xCE5660

#define mmNIC0_QPC1_RES_RING1_CFG                                    0xCE5664

#define mmNIC0_QPC1_RES_RING2_PI                                     0xCE5668

#define mmNIC0_QPC1_RES_RING2_CI                                     0xCE566C

#define mmNIC0_QPC1_RES_RING2_CFG                                    0xCE5670

#define mmNIC0_QPC1_RES_RING3_PI                                     0xCE5674

#define mmNIC0_QPC1_RES_RING3_CI                                     0xCE5678

#define mmNIC0_QPC1_RES_RING3_CFG                                    0xCE567C

#define mmNIC0_QPC1_REQ_RING0_CI                                     0xCE5680

#define mmNIC0_QPC1_REQ_RING1_CI                                     0xCE5684

#define mmNIC0_QPC1_REQ_RING2_CI                                     0xCE5688

#define mmNIC0_QPC1_REQ_RING3_CI                                     0xCE568C

#define mmNIC0_QPC1_INTERRUPT_CAUSE                                  0xCE5690

#define mmNIC0_QPC1_INTERRUPT_MASK                                   0xCE5694

#define mmNIC0_QPC1_INTERRUPT_CLR                                    0xCE5698

#define mmNIC0_QPC1_INTERRUPT_EN                                     0xCE569C

#define mmNIC0_QPC1_INTERRUPT_BASE_0                                 0xCE56A0

#define mmNIC0_QPC1_INTERRUPT_BASE_1                                 0xCE56A4

#define mmNIC0_QPC1_INTERRUPT_BASE_2                                 0xCE56A8

#define mmNIC0_QPC1_INTERRUPT_BASE_3                                 0xCE56AC

#define mmNIC0_QPC1_INTERRUPT_BASE_4                                 0xCE56B0

#define mmNIC0_QPC1_INTERRUPT_BASE_5                                 0xCE56B4

#define mmNIC0_QPC1_INTERRUPT_BASE_6                                 0xCE56B8

#define mmNIC0_QPC1_INTERRUPT_BASE_7                                 0xCE56BC

#define mmNIC0_QPC1_INTERRUPT_BASE_8                                 0xCE56C0

#define mmNIC0_QPC1_INTERRUPT_DATA_0                                 0xCE56C4

#define mmNIC0_QPC1_INTERRUPT_DATA_1                                 0xCE56C8

#define mmNIC0_QPC1_INTERRUPT_DATA_2                                 0xCE56CC

#define mmNIC0_QPC1_INTERRUPT_DATA_3                                 0xCE56D0

#define mmNIC0_QPC1_INTERRUPT_DATA_4                                 0xCE56D4

#define mmNIC0_QPC1_INTERRUPT_DATA_5                                 0xCE56D8

#define mmNIC0_QPC1_INTERRUPT_DATA_6                                 0xCE56DC

#define mmNIC0_QPC1_INTERRUPT_DATA_7                                 0xCE56E0

#define mmNIC0_QPC1_INTERRUPT_DATA_8                                 0xCE56E4

#define mmNIC0_QPC1_INTERRUPT_PROT                                   0xCE56E8

#define mmNIC0_QPC1_INTERRUPT_USER                                   0xCE56EC

#define mmNIC0_QPC1_INTERRUPT_CFG                                    0xCE56F0

#define mmNIC0_QPC1_INTERRUPT_RESP_ERR_CAUSE                         0xCE56F4

#define mmNIC0_QPC1_INTRRRUPT_RESP_ERR_MASK                          0xCE56F8

#define mmNIC0_QPC1_INTERRUPR_RESP_ERR_CLR                           0xCE5700

#define mmNIC0_QPC1_TMR_GW_VALID                                     0xCE5704

#define mmNIC0_QPC1_TMR_GW_DATA0                                     0xCE5708

#define mmNIC0_QPC1_TMR_GW_DATA1                                     0xCE570C

#define mmNIC0_QPC1_RNR_RETRY_COUNT_EN                               0xCE5710

#endif /* ASIC_REG_NIC0_QPC1_REGS_H_ */
