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

#ifndef ASIC_REG_NIC0_QPC0_REGS_H_
#define ASIC_REG_NIC0_QPC0_REGS_H_

/*
 *****************************************
 *   NIC0_QPC0 (Prototype: NIC_QPC)
 *****************************************
 */

#define mmNIC0_QPC0_REQ_QPC_CACHE_INVALIDATE                         0xCE4000

#define mmNIC0_QPC0_REQ_QPC_CACHE_INV_STATUS                         0xCE4004

#define mmNIC0_QPC0_REQ_STATIC_CONFIG                                0xCE4008

#define mmNIC0_QPC0_REQ_BASE_ADDRESS_49_18                           0xCE400C

#define mmNIC0_QPC0_REQ_BASE_ADDRESS_17_7                            0xCE4010

#define mmNIC0_QPC0_REQ_CLEAN_LINK_LIST                              0xCE4014

#define mmNIC0_QPC0_REQ_ERR_FIFO_PUSH_63_32                          0xCE4018

#define mmNIC0_QPC0_REQ_ERR_FIFO_PUSH_31_0                           0xCE401C

#define mmNIC0_QPC0_REQ_ERR_QP_STATE_63_32                           0xCE4020

#define mmNIC0_QPC0_REQ_ERR_QP_STATE_31_0                            0xCE4024

#define mmNIC0_QPC0_RETRY_COUNT_MAX                                  0xCE4028

#define mmNIC0_QPC0_AXI_USER                                         0xCE402C

#define mmNIC0_QPC0_AXI_PROT                                         0xCE4030

#define mmNIC0_QPC0_RES_QPC_CACHE_INVALIDATE                         0xCE4034

#define mmNIC0_QPC0_RES_QPC_CACHE_INV_STATUS                         0xCE4038

#define mmNIC0_QPC0_RES_STATIC_CONFIG                                0xCE403C

#define mmNIC0_QPC0_RES_BASE_ADDRESS_49_18                           0xCE4040

#define mmNIC0_QPC0_RES_BASE_ADDRESS_17_7                            0xCE4044

#define mmNIC0_QPC0_RES_CLEAN_LINK_LIST                              0xCE4048

#define mmNIC0_QPC0_ERR_FIFO_WRITE_INDEX                             0xCE4050

#define mmNIC0_QPC0_ERR_FIFO_PRODUCER_INDEX                          0xCE4054

#define mmNIC0_QPC0_ERR_FIFO_CONSUMER_INDEX                          0xCE4058

#define mmNIC0_QPC0_ERR_FIFO_MASK                                    0xCE405C

#define mmNIC0_QPC0_ERR_FIFO_CREDIT                                  0xCE4060

#define mmNIC0_QPC0_ERR_FIFO_CFG                                     0xCE4064

#define mmNIC0_QPC0_ERR_FIFO_INTR_MASK                               0xCE4068

#define mmNIC0_QPC0_ERR_FIFO_BASE_ADDR_49_18                         0xCE406C

#define mmNIC0_QPC0_ERR_FIFO_BASE_ADDR_17_7                          0xCE4070

#define mmNIC0_QPC0_GW_BUSY                                          0xCE4080

#define mmNIC0_QPC0_GW_CTRL                                          0xCE4084

#define mmNIC0_QPC0_GW_DATA_0                                        0xCE408C

#define mmNIC0_QPC0_GW_DATA_1                                        0xCE4090

#define mmNIC0_QPC0_GW_DATA_2                                        0xCE4094

#define mmNIC0_QPC0_GW_DATA_3                                        0xCE4098

#define mmNIC0_QPC0_GW_DATA_4                                        0xCE409C

#define mmNIC0_QPC0_GW_DATA_5                                        0xCE40A0

#define mmNIC0_QPC0_GW_DATA_6                                        0xCE40A4

#define mmNIC0_QPC0_GW_DATA_7                                        0xCE40A8

#define mmNIC0_QPC0_GW_DATA_8                                        0xCE40AC

#define mmNIC0_QPC0_GW_DATA_9                                        0xCE40B0

#define mmNIC0_QPC0_GW_DATA_10                                       0xCE40B4

#define mmNIC0_QPC0_GW_DATA_11                                       0xCE40B8

#define mmNIC0_QPC0_GW_DATA_12                                       0xCE40BC

#define mmNIC0_QPC0_GW_DATA_13                                       0xCE40C0

#define mmNIC0_QPC0_GW_DATA_14                                       0xCE40C4

#define mmNIC0_QPC0_GW_DATA_15                                       0xCE40C8

#define mmNIC0_QPC0_GW_MASK_0                                        0xCE4124

#define mmNIC0_QPC0_GW_MASK_1                                        0xCE4128

#define mmNIC0_QPC0_GW_MASK_2                                        0xCE412C

#define mmNIC0_QPC0_GW_MASK_3                                        0xCE4130

#define mmNIC0_QPC0_GW_MASK_4                                        0xCE4134

#define mmNIC0_QPC0_GW_MASK_5                                        0xCE4138

#define mmNIC0_QPC0_GW_MASK_6                                        0xCE413C

#define mmNIC0_QPC0_GW_MASK_7                                        0xCE4140

#define mmNIC0_QPC0_GW_MASK_8                                        0xCE4144

#define mmNIC0_QPC0_GW_MASK_9                                        0xCE4148

#define mmNIC0_QPC0_GW_MASK_10                                       0xCE414C

#define mmNIC0_QPC0_GW_MASK_11                                       0xCE4150

#define mmNIC0_QPC0_GW_MASK_12                                       0xCE4154

#define mmNIC0_QPC0_GW_MASK_13                                       0xCE4158

#define mmNIC0_QPC0_GW_MASK_14                                       0xCE415C

#define mmNIC0_QPC0_GW_MASK_15                                       0xCE4160

#define mmNIC0_QPC0_CC_WINDOW_INC_EN                                 0xCE41FC

#define mmNIC0_QPC0_CC_TICK_WRAP                                     0xCE4200

#define mmNIC0_QPC0_CC_ROLLBACK                                      0xCE4204

#define mmNIC0_QPC0_CC_MAX_WINDOW_SIZE                               0xCE4208

#define mmNIC0_QPC0_CC_MIN_WINDOW_SIZE                               0xCE420C

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_0                                0xCE4210

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_1                                0xCE4214

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_2                                0xCE4218

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_3                                0xCE421C

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_4                                0xCE4220

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_5                                0xCE4224

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_6                                0xCE4228

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_7                                0xCE422C

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_8                                0xCE4230

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_9                                0xCE4234

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_10                               0xCE4238

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_11                               0xCE423C

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_12                               0xCE4240

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_13                               0xCE4244

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_14                               0xCE4248

#define mmNIC0_QPC0_CC_ALPHA_LINEAR_15                               0xCE424C

#define mmNIC0_QPC0_CC_ALPHA_LOG_0                                   0xCE4250

#define mmNIC0_QPC0_CC_ALPHA_LOG_1                                   0xCE4254

#define mmNIC0_QPC0_CC_ALPHA_LOG_2                                   0xCE4258

#define mmNIC0_QPC0_CC_ALPHA_LOG_3                                   0xCE425C

#define mmNIC0_QPC0_CC_ALPHA_LOG_4                                   0xCE4260

#define mmNIC0_QPC0_CC_ALPHA_LOG_5                                   0xCE4264

#define mmNIC0_QPC0_CC_ALPHA_LOG_6                                   0xCE4268

#define mmNIC0_QPC0_CC_ALPHA_LOG_7                                   0xCE426C

#define mmNIC0_QPC0_CC_ALPHA_LOG_8                                   0xCE4270

#define mmNIC0_QPC0_CC_ALPHA_LOG_9                                   0xCE4274

#define mmNIC0_QPC0_CC_ALPHA_LOG_10                                  0xCE4278

#define mmNIC0_QPC0_CC_ALPHA_LOG_11                                  0xCE427C

#define mmNIC0_QPC0_CC_ALPHA_LOG_12                                  0xCE4280

#define mmNIC0_QPC0_CC_ALPHA_LOG_13                                  0xCE4284

#define mmNIC0_QPC0_CC_ALPHA_LOG_14                                  0xCE4288

#define mmNIC0_QPC0_CC_ALPHA_LOG_15                                  0xCE428C

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_0                         0xCE4290

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_1                         0xCE4294

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_2                         0xCE4298

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_3                         0xCE429C

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_4                         0xCE42A0

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_5                         0xCE42A4

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_6                         0xCE42A8

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_7                         0xCE42AC

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_8                         0xCE42B0

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_9                         0xCE42B4

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_10                        0xCE42B8

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_11                        0xCE42BC

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_12                        0xCE42C0

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_13                        0xCE42C4

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_14                        0xCE42C8

#define mmNIC0_QPC0_CC_ALPHA_LOG_THRESHOLD_15                        0xCE42CC

#define mmNIC0_QPC0_CC_WINDOW_INC_0                                  0xCE42D0

#define mmNIC0_QPC0_CC_WINDOW_INC_1                                  0xCE42D4

#define mmNIC0_QPC0_CC_WINDOW_INC_2                                  0xCE42D8

#define mmNIC0_QPC0_CC_WINDOW_INC_3                                  0xCE42DC

#define mmNIC0_QPC0_CC_WINDOW_INC_4                                  0xCE42E0

#define mmNIC0_QPC0_CC_WINDOW_INC_5                                  0xCE42E4

#define mmNIC0_QPC0_CC_WINDOW_INC_6                                  0xCE42E8

#define mmNIC0_QPC0_CC_WINDOW_INC_7                                  0xCE42EC

#define mmNIC0_QPC0_CC_WINDOW_INC_8                                  0xCE42F0

#define mmNIC0_QPC0_CC_WINDOW_INC_9                                  0xCE42F4

#define mmNIC0_QPC0_CC_WINDOW_INC_10                                 0xCE42F8

#define mmNIC0_QPC0_CC_WINDOW_INC_11                                 0xCE42FC

#define mmNIC0_QPC0_CC_WINDOW_INC_12                                 0xCE4300

#define mmNIC0_QPC0_CC_WINDOW_INC_13                                 0xCE4304

#define mmNIC0_QPC0_CC_WINDOW_INC_14                                 0xCE4308

#define mmNIC0_QPC0_CC_WINDOW_INC_15                                 0xCE430C

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_0                         0xCE4310

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_1                         0xCE4314

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_2                         0xCE4318

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_3                         0xCE431C

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_4                         0xCE4320

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_5                         0xCE4324

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_6                         0xCE4328

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_7                         0xCE432C

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_8                         0xCE4330

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_9                         0xCE4334

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_10                        0xCE4338

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_11                        0xCE433C

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_12                        0xCE4340

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_13                        0xCE4344

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_14                        0xCE4348

#define mmNIC0_QPC0_CC_WINDOW_IN_THRESHOLD_15                        0xCE434C

#define mmNIC0_QPC0_CC_LOG_QPC_0                                     0xCE4350

#define mmNIC0_QPC0_CC_LOG_QPC_1                                     0xCE4354

#define mmNIC0_QPC0_CC_LOG_QPC_2                                     0xCE4358

#define mmNIC0_QPC0_CC_LOG_QPC_3                                     0xCE435C

#define mmNIC0_QPC0_CC_LOG_QPC_4                                     0xCE4360

#define mmNIC0_QPC0_CC_LOG_QPC_5                                     0xCE4364

#define mmNIC0_QPC0_CC_LOG_QPC_6                                     0xCE4368

#define mmNIC0_QPC0_CC_LOG_QPC_7                                     0xCE436C

#define mmNIC0_QPC0_CC_LOG_QPC_8                                     0xCE4370

#define mmNIC0_QPC0_CC_LOG_QPC_9                                     0xCE4374

#define mmNIC0_QPC0_CC_LOG_QPC_10                                    0xCE4378

#define mmNIC0_QPC0_CC_LOG_QPC_11                                    0xCE437C

#define mmNIC0_QPC0_CC_LOG_QPC_12                                    0xCE4380

#define mmNIC0_QPC0_CC_LOG_QPC_13                                    0xCE4384

#define mmNIC0_QPC0_CC_LOG_QPC_14                                    0xCE4388

#define mmNIC0_QPC0_CC_LOG_QPC_15                                    0xCE438C

#define mmNIC0_QPC0_CC_LOG_QPC_16                                    0xCE4390

#define mmNIC0_QPC0_CC_LOG_QPC_17                                    0xCE4394

#define mmNIC0_QPC0_CC_LOG_QPC_18                                    0xCE4398

#define mmNIC0_QPC0_CC_LOG_QPC_19                                    0xCE439C

#define mmNIC0_QPC0_CC_LOG_QPC_20                                    0xCE43A0

#define mmNIC0_QPC0_CC_LOG_QPC_21                                    0xCE43A4

#define mmNIC0_QPC0_CC_LOG_QPC_22                                    0xCE43A8

#define mmNIC0_QPC0_CC_LOG_QPC_23                                    0xCE43AC

#define mmNIC0_QPC0_CC_LOG_QPC_24                                    0xCE43B0

#define mmNIC0_QPC0_CC_LOG_QPC_25                                    0xCE43B4

#define mmNIC0_QPC0_CC_LOG_QPC_26                                    0xCE43B8

#define mmNIC0_QPC0_CC_LOG_QPC_27                                    0xCE43BC

#define mmNIC0_QPC0_CC_LOG_QPC_28                                    0xCE43C0

#define mmNIC0_QPC0_CC_LOG_QPC_29                                    0xCE43C4

#define mmNIC0_QPC0_CC_LOG_QPC_30                                    0xCE43C8

#define mmNIC0_QPC0_CC_LOG_QPC_31                                    0xCE43CC

#define mmNIC0_QPC0_CC_LOG_TX_0                                      0xCE43D0

#define mmNIC0_QPC0_CC_LOG_TX_1                                      0xCE43D4

#define mmNIC0_QPC0_CC_LOG_TX_2                                      0xCE43D8

#define mmNIC0_QPC0_CC_LOG_TX_3                                      0xCE43DC

#define mmNIC0_QPC0_CC_LOG_TX_4                                      0xCE43E0

#define mmNIC0_QPC0_CC_LOG_TX_5                                      0xCE43E4

#define mmNIC0_QPC0_CC_LOG_TX_6                                      0xCE43E8

#define mmNIC0_QPC0_CC_LOG_TX_7                                      0xCE43EC

#define mmNIC0_QPC0_CC_LOG_TX_8                                      0xCE43F0

#define mmNIC0_QPC0_CC_LOG_TX_9                                      0xCE43F4

#define mmNIC0_QPC0_CC_LOG_TX_10                                     0xCE43F8

#define mmNIC0_QPC0_CC_LOG_TX_11                                     0xCE43FC

#define mmNIC0_QPC0_CC_LOG_TX_12                                     0xCE4400

#define mmNIC0_QPC0_CC_LOG_TX_13                                     0xCE4404

#define mmNIC0_QPC0_CC_LOG_TX_14                                     0xCE4408

#define mmNIC0_QPC0_CC_LOG_TX_15                                     0xCE440C

#define mmNIC0_QPC0_CC_LOG_TX_16                                     0xCE4410

#define mmNIC0_QPC0_CC_LOG_TX_17                                     0xCE4414

#define mmNIC0_QPC0_CC_LOG_TX_18                                     0xCE4418

#define mmNIC0_QPC0_CC_LOG_TX_19                                     0xCE441C

#define mmNIC0_QPC0_CC_LOG_TX_20                                     0xCE4420

#define mmNIC0_QPC0_CC_LOG_TX_21                                     0xCE4424

#define mmNIC0_QPC0_CC_LOG_TX_22                                     0xCE4428

#define mmNIC0_QPC0_CC_LOG_TX_23                                     0xCE442C

#define mmNIC0_QPC0_CC_LOG_TX_24                                     0xCE4430

#define mmNIC0_QPC0_CC_LOG_TX_25                                     0xCE4434

#define mmNIC0_QPC0_CC_LOG_TX_26                                     0xCE4438

#define mmNIC0_QPC0_CC_LOG_TX_27                                     0xCE443C

#define mmNIC0_QPC0_CC_LOG_TX_28                                     0xCE4440

#define mmNIC0_QPC0_CC_LOG_TX_29                                     0xCE4444

#define mmNIC0_QPC0_CC_LOG_TX_30                                     0xCE4448

#define mmNIC0_QPC0_CC_LOG_TX_31                                     0xCE444C

#define mmNIC0_QPC0_CC_LOG_LATENCY_0                                 0xCE4450

#define mmNIC0_QPC0_CC_LOG_LATENCY_1                                 0xCE4454

#define mmNIC0_QPC0_CC_LOG_LATENCY_2                                 0xCE4458

#define mmNIC0_QPC0_CC_LOG_LATENCY_3                                 0xCE445C

#define mmNIC0_QPC0_CC_LOG_LATENCY_4                                 0xCE4460

#define mmNIC0_QPC0_CC_LOG_LATENCY_5                                 0xCE4464

#define mmNIC0_QPC0_CC_LOG_LATENCY_6                                 0xCE4468

#define mmNIC0_QPC0_CC_LOG_LATENCY_7                                 0xCE446C

#define mmNIC0_QPC0_CC_LOG_LATENCY_8                                 0xCE4470

#define mmNIC0_QPC0_CC_LOG_LATENCY_9                                 0xCE4474

#define mmNIC0_QPC0_CC_LOG_LATENCY_10                                0xCE4478

#define mmNIC0_QPC0_CC_LOG_LATENCY_11                                0xCE447C

#define mmNIC0_QPC0_CC_LOG_LATENCY_12                                0xCE4480

#define mmNIC0_QPC0_CC_LOG_LATENCY_13                                0xCE4484

#define mmNIC0_QPC0_CC_LOG_LATENCY_14                                0xCE4488

#define mmNIC0_QPC0_CC_LOG_LATENCY_15                                0xCE448C

#define mmNIC0_QPC0_CC_LOG_LATENCY_16                                0xCE4490

#define mmNIC0_QPC0_CC_LOG_LATENCY_17                                0xCE4494

#define mmNIC0_QPC0_CC_LOG_LATENCY_18                                0xCE4498

#define mmNIC0_QPC0_CC_LOG_LATENCY_19                                0xCE449C

#define mmNIC0_QPC0_CC_LOG_LATENCY_20                                0xCE44A0

#define mmNIC0_QPC0_CC_LOG_LATENCY_21                                0xCE44A4

#define mmNIC0_QPC0_CC_LOG_LATENCY_22                                0xCE44A8

#define mmNIC0_QPC0_CC_LOG_LATENCY_23                                0xCE44AC

#define mmNIC0_QPC0_CC_LOG_LATENCY_24                                0xCE44B0

#define mmNIC0_QPC0_CC_LOG_LATENCY_25                                0xCE44B4

#define mmNIC0_QPC0_CC_LOG_LATENCY_26                                0xCE44B8

#define mmNIC0_QPC0_CC_LOG_LATENCY_27                                0xCE44BC

#define mmNIC0_QPC0_CC_LOG_LATENCY_28                                0xCE44C0

#define mmNIC0_QPC0_CC_LOG_LATENCY_29                                0xCE44C4

#define mmNIC0_QPC0_CC_LOG_LATENCY_30                                0xCE44C8

#define mmNIC0_QPC0_CC_LOG_LATENCY_31                                0xCE44CC

#define mmNIC0_QPC0_CC_LOG_RX_0                                      0xCE44D0

#define mmNIC0_QPC0_CC_LOG_RX_1                                      0xCE44D4

#define mmNIC0_QPC0_CC_LOG_RX_2                                      0xCE44D8

#define mmNIC0_QPC0_CC_LOG_RX_3                                      0xCE44DC

#define mmNIC0_QPC0_CC_LOG_RX_4                                      0xCE44E0

#define mmNIC0_QPC0_CC_LOG_RX_5                                      0xCE44E4

#define mmNIC0_QPC0_CC_LOG_RX_6                                      0xCE44E8

#define mmNIC0_QPC0_CC_LOG_RX_7                                      0xCE44EC

#define mmNIC0_QPC0_CC_LOG_RX_8                                      0xCE44F0

#define mmNIC0_QPC0_CC_LOG_RX_9                                      0xCE44F4

#define mmNIC0_QPC0_CC_LOG_RX_10                                     0xCE44F8

#define mmNIC0_QPC0_CC_LOG_RX_11                                     0xCE44FC

#define mmNIC0_QPC0_CC_LOG_RX_12                                     0xCE4500

#define mmNIC0_QPC0_CC_LOG_RX_13                                     0xCE4504

#define mmNIC0_QPC0_CC_LOG_RX_14                                     0xCE4508

#define mmNIC0_QPC0_CC_LOG_RX_15                                     0xCE450C

#define mmNIC0_QPC0_CC_LOG_RX_16                                     0xCE4510

#define mmNIC0_QPC0_CC_LOG_RX_17                                     0xCE4514

#define mmNIC0_QPC0_CC_LOG_RX_18                                     0xCE4518

#define mmNIC0_QPC0_CC_LOG_RX_19                                     0xCE451C

#define mmNIC0_QPC0_CC_LOG_RX_20                                     0xCE4520

#define mmNIC0_QPC0_CC_LOG_RX_21                                     0xCE4524

#define mmNIC0_QPC0_CC_LOG_RX_22                                     0xCE4528

#define mmNIC0_QPC0_CC_LOG_RX_23                                     0xCE452C

#define mmNIC0_QPC0_CC_LOG_RX_24                                     0xCE4530

#define mmNIC0_QPC0_CC_LOG_RX_25                                     0xCE4534

#define mmNIC0_QPC0_CC_LOG_RX_26                                     0xCE4538

#define mmNIC0_QPC0_CC_LOG_RX_27                                     0xCE453C

#define mmNIC0_QPC0_CC_LOG_RX_28                                     0xCE4540

#define mmNIC0_QPC0_CC_LOG_RX_29                                     0xCE4544

#define mmNIC0_QPC0_CC_LOG_RX_30                                     0xCE4548

#define mmNIC0_QPC0_CC_LOG_RX_31                                     0xCE454C

#define mmNIC0_QPC0_CC_LOG_WINDOW_SIZE                               0xCE4550

#define mmNIC0_QPC0_DBG_COUNT_SELECT_0                               0xCE4600

#define mmNIC0_QPC0_DBG_COUNT_SELECT_1                               0xCE4604

#define mmNIC0_QPC0_DBG_COUNT_SELECT_2                               0xCE4608

#define mmNIC0_QPC0_DBG_COUNT_SELECT_3                               0xCE460C

#define mmNIC0_QPC0_DBG_COUNT_SELECT_4                               0xCE4610

#define mmNIC0_QPC0_DBG_COUNT_SELECT_5                               0xCE4614

#define mmNIC0_QPC0_DBG_COUNT_SELECT_6                               0xCE4618

#define mmNIC0_QPC0_DBG_COUNT_SELECT_7                               0xCE461C

#define mmNIC0_QPC0_DBG_COUNT_SELECT_8                               0xCE4620

#define mmNIC0_QPC0_DBG_COUNT_SELECT_9                               0xCE4624

#define mmNIC0_QPC0_DBG_COUNT_SELECT_10                              0xCE4628

#define mmNIC0_QPC0_DBG_COUNT_SELECT_11                              0xCE462C

#define mmNIC0_QPC0_UNSECURED_DOORBELL_QPN                           0xCE4630

#define mmNIC0_QPC0_UNSECURED_DOORBELL_PI                            0xCE4634

#define mmNIC0_QPC0_SECURED_DOORBELL_QPN                             0xCE4638

#define mmNIC0_QPC0_SECURED_DOORBELL_PI                              0xCE463C

#define mmNIC0_QPC0_PRIVILEGE_DOORBELL_QPN                           0xCE4640

#define mmNIC0_QPC0_PRIVILEGE_DOORBELL_PI                            0xCE4644

#define mmNIC0_QPC0_DOORBELL_SECURITY                                0xCE4648

#define mmNIC0_QPC0_DGB_TRIG                                         0xCE464C

#define mmNIC0_QPC0_RES_RING0_PI                                     0xCE4650

#define mmNIC0_QPC0_RES_RING0_CI                                     0xCE4654

#define mmNIC0_QPC0_RES_RING0_CFG                                    0xCE4658

#define mmNIC0_QPC0_RES_RING1_PI                                     0xCE465C

#define mmNIC0_QPC0_RES_RING1_CI                                     0xCE4660

#define mmNIC0_QPC0_RES_RING1_CFG                                    0xCE4664

#define mmNIC0_QPC0_RES_RING2_PI                                     0xCE4668

#define mmNIC0_QPC0_RES_RING2_CI                                     0xCE466C

#define mmNIC0_QPC0_RES_RING2_CFG                                    0xCE4670

#define mmNIC0_QPC0_RES_RING3_PI                                     0xCE4674

#define mmNIC0_QPC0_RES_RING3_CI                                     0xCE4678

#define mmNIC0_QPC0_RES_RING3_CFG                                    0xCE467C

#define mmNIC0_QPC0_REQ_RING0_CI                                     0xCE4680

#define mmNIC0_QPC0_REQ_RING1_CI                                     0xCE4684

#define mmNIC0_QPC0_REQ_RING2_CI                                     0xCE4688

#define mmNIC0_QPC0_REQ_RING3_CI                                     0xCE468C

#define mmNIC0_QPC0_INTERRUPT_CAUSE                                  0xCE4690

#define mmNIC0_QPC0_INTERRUPT_MASK                                   0xCE4694

#define mmNIC0_QPC0_INTERRUPT_CLR                                    0xCE4698

#define mmNIC0_QPC0_INTERRUPT_EN                                     0xCE469C

#define mmNIC0_QPC0_INTERRUPT_BASE_0                                 0xCE46A0

#define mmNIC0_QPC0_INTERRUPT_BASE_1                                 0xCE46A4

#define mmNIC0_QPC0_INTERRUPT_BASE_2                                 0xCE46A8

#define mmNIC0_QPC0_INTERRUPT_BASE_3                                 0xCE46AC

#define mmNIC0_QPC0_INTERRUPT_BASE_4                                 0xCE46B0

#define mmNIC0_QPC0_INTERRUPT_BASE_5                                 0xCE46B4

#define mmNIC0_QPC0_INTERRUPT_BASE_6                                 0xCE46B8

#define mmNIC0_QPC0_INTERRUPT_BASE_7                                 0xCE46BC

#define mmNIC0_QPC0_INTERRUPT_BASE_8                                 0xCE46C0

#define mmNIC0_QPC0_INTERRUPT_DATA_0                                 0xCE46C4

#define mmNIC0_QPC0_INTERRUPT_DATA_1                                 0xCE46C8

#define mmNIC0_QPC0_INTERRUPT_DATA_2                                 0xCE46CC

#define mmNIC0_QPC0_INTERRUPT_DATA_3                                 0xCE46D0

#define mmNIC0_QPC0_INTERRUPT_DATA_4                                 0xCE46D4

#define mmNIC0_QPC0_INTERRUPT_DATA_5                                 0xCE46D8

#define mmNIC0_QPC0_INTERRUPT_DATA_6                                 0xCE46DC

#define mmNIC0_QPC0_INTERRUPT_DATA_7                                 0xCE46E0

#define mmNIC0_QPC0_INTERRUPT_DATA_8                                 0xCE46E4

#define mmNIC0_QPC0_INTERRUPT_PROT                                   0xCE46E8

#define mmNIC0_QPC0_INTERRUPT_USER                                   0xCE46EC

#define mmNIC0_QPC0_INTERRUPT_CFG                                    0xCE46F0

#define mmNIC0_QPC0_INTERRUPT_RESP_ERR_CAUSE                         0xCE46F4

#define mmNIC0_QPC0_INTRRRUPT_RESP_ERR_MASK                          0xCE46F8

#define mmNIC0_QPC0_INTERRUPR_RESP_ERR_CLR                           0xCE4700

#define mmNIC0_QPC0_TMR_GW_VALID                                     0xCE4704

#define mmNIC0_QPC0_TMR_GW_DATA0                                     0xCE4708

#define mmNIC0_QPC0_TMR_GW_DATA1                                     0xCE470C

#define mmNIC0_QPC0_RNR_RETRY_COUNT_EN                               0xCE4710

#endif /* ASIC_REG_NIC0_QPC0_REGS_H_ */
