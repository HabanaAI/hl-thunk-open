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

#ifndef ASIC_REG_DDR_MC_CH1_REGS_H_
#define ASIC_REG_DDR_MC_CH1_REGS_H_

/*
 *****************************************
 *   DDR_MC_CH1 (Prototype: DDR_MC)
 *****************************************
 */

#define mmDDR_MC_CH1_MSTR                                            0x740000

#define mmDDR_MC_CH1_STAT                                            0x740004

#define mmDDR_MC_CH1_MRCTRL0                                         0x740010

#define mmDDR_MC_CH1_MRCTRL1                                         0x740014

#define mmDDR_MC_CH1_MRSTAT                                          0x740018

#define mmDDR_MC_CH1_MRCTRL2                                         0x74001C

#define mmDDR_MC_CH1_PWRCTL                                          0x740030

#define mmDDR_MC_CH1_PWRTMG                                          0x740034

#define mmDDR_MC_CH1_HWLPCTL                                         0x740038

#define mmDDR_MC_CH1_RFSHCTL0                                        0x740050

#define mmDDR_MC_CH1_RFSHCTL1                                        0x740054

#define mmDDR_MC_CH1_RFSHCTL3                                        0x740060

#define mmDDR_MC_CH1_RFSHTMG                                         0x740064

#define mmDDR_MC_CH1_ECCCFG0                                         0x740070

#define mmDDR_MC_CH1_ECCCFG1                                         0x740074

#define mmDDR_MC_CH1_ECCSTAT                                         0x740078

#define mmDDR_MC_CH1_ECCCTL                                          0x74007C

#define mmDDR_MC_CH1_ECCERRCNT                                       0x740080

#define mmDDR_MC_CH1_ECCCADDR0                                       0x740084

#define mmDDR_MC_CH1_ECCCADDR1                                       0x740088

#define mmDDR_MC_CH1_ECCCSYN0                                        0x74008C

#define mmDDR_MC_CH1_ECCCSYN1                                        0x740090

#define mmDDR_MC_CH1_ECCCSYN2                                        0x740094

#define mmDDR_MC_CH1_ECCBITMASK0                                     0x740098

#define mmDDR_MC_CH1_ECCBITMASK1                                     0x74009C

#define mmDDR_MC_CH1_ECCBITMASK2                                     0x7400A0

#define mmDDR_MC_CH1_ECCUADDR0                                       0x7400A4

#define mmDDR_MC_CH1_ECCUADDR1                                       0x7400A8

#define mmDDR_MC_CH1_ECCUSYN0                                        0x7400AC

#define mmDDR_MC_CH1_ECCUSYN1                                        0x7400B0

#define mmDDR_MC_CH1_ECCUSYN2                                        0x7400B4

#define mmDDR_MC_CH1_ECCPOISONADDR0                                  0x7400B8

#define mmDDR_MC_CH1_ECCPOISONADDR1                                  0x7400BC

#define mmDDR_MC_CH1_CRCPARCTL0                                      0x7400C0

#define mmDDR_MC_CH1_CRCPARCTL1                                      0x7400C4

#define mmDDR_MC_CH1_CRCPARCTL2                                      0x7400C8

#define mmDDR_MC_CH1_CRCPARSTAT                                      0x7400CC

#define mmDDR_MC_CH1_INIT0                                           0x7400D0

#define mmDDR_MC_CH1_INIT1                                           0x7400D4

#define mmDDR_MC_CH1_INIT3                                           0x7400DC

#define mmDDR_MC_CH1_INIT4                                           0x7400E0

#define mmDDR_MC_CH1_INIT5                                           0x7400E4

#define mmDDR_MC_CH1_INIT6                                           0x7400E8

#define mmDDR_MC_CH1_INIT7                                           0x7400EC

#define mmDDR_MC_CH1_DIMMCTL                                         0x7400F0

#define mmDDR_MC_CH1_RANKCTL                                         0x7400F4

#define mmDDR_MC_CH1_DRAMTMG0                                        0x740100

#define mmDDR_MC_CH1_DRAMTMG1                                        0x740104

#define mmDDR_MC_CH1_DRAMTMG2                                        0x740108

#define mmDDR_MC_CH1_DRAMTMG3                                        0x74010C

#define mmDDR_MC_CH1_DRAMTMG4                                        0x740110

#define mmDDR_MC_CH1_DRAMTMG5                                        0x740114

#define mmDDR_MC_CH1_DRAMTMG8                                        0x740120

#define mmDDR_MC_CH1_DRAMTMG9                                        0x740124

#define mmDDR_MC_CH1_DRAMTMG10                                       0x740128

#define mmDDR_MC_CH1_DRAMTMG11                                       0x74012C

#define mmDDR_MC_CH1_DRAMTMG12                                       0x740130

#define mmDDR_MC_CH1_DRAMTMG15                                       0x74013C

#define mmDDR_MC_CH1_ZQCTL0                                          0x740180

#define mmDDR_MC_CH1_ZQCTL1                                          0x740184

#define mmDDR_MC_CH1_DFITMG0                                         0x740190

#define mmDDR_MC_CH1_DFITMG1                                         0x740194

#define mmDDR_MC_CH1_DFILPCFG0                                       0x740198

#define mmDDR_MC_CH1_DFILPCFG1                                       0x74019C

#define mmDDR_MC_CH1_DFIUPD0                                         0x7401A0

#define mmDDR_MC_CH1_DFIUPD1                                         0x7401A4

#define mmDDR_MC_CH1_DFIUPD2                                         0x7401A8

#define mmDDR_MC_CH1_DFIMISC                                         0x7401B0

#define mmDDR_MC_CH1_DFITMG2                                         0x7401B4

#define mmDDR_MC_CH1_DFITMG3                                         0x7401B8

#define mmDDR_MC_CH1_DFISTAT                                         0x7401BC

#define mmDDR_MC_CH1_DBICTL                                          0x7401C0

#define mmDDR_MC_CH1_DFIPHYMSTR                                      0x7401C4

#define mmDDR_MC_CH1_ADDRMAP0                                        0x740200

#define mmDDR_MC_CH1_ADDRMAP1                                        0x740204

#define mmDDR_MC_CH1_ADDRMAP2                                        0x740208

#define mmDDR_MC_CH1_ADDRMAP3                                        0x74020C

#define mmDDR_MC_CH1_ADDRMAP4                                        0x740210

#define mmDDR_MC_CH1_ADDRMAP5                                        0x740214

#define mmDDR_MC_CH1_ADDRMAP6                                        0x740218

#define mmDDR_MC_CH1_ADDRMAP7                                        0x74021C

#define mmDDR_MC_CH1_ADDRMAP8                                        0x740220

#define mmDDR_MC_CH1_ADDRMAP9                                        0x740224

#define mmDDR_MC_CH1_ADDRMAP10                                       0x740228

#define mmDDR_MC_CH1_ADDRMAP11                                       0x74022C

#define mmDDR_MC_CH1_ODTCFG                                          0x740240

#define mmDDR_MC_CH1_ODTMAP                                          0x740244

#define mmDDR_MC_CH1_SCHED                                           0x740250

#define mmDDR_MC_CH1_SCHED1                                          0x740254

#define mmDDR_MC_CH1_PERFHPR1                                        0x74025C

#define mmDDR_MC_CH1_PERFLPR1                                        0x740264

#define mmDDR_MC_CH1_PERFWR1                                         0x74026C

#define mmDDR_MC_CH1_DQMAP0                                          0x740280

#define mmDDR_MC_CH1_DQMAP1                                          0x740284

#define mmDDR_MC_CH1_DQMAP2                                          0x740288

#define mmDDR_MC_CH1_DQMAP3                                          0x74028C

#define mmDDR_MC_CH1_DQMAP4                                          0x740290

#define mmDDR_MC_CH1_DQMAP5                                          0x740294

#define mmDDR_MC_CH1_DBG0                                            0x740300

#define mmDDR_MC_CH1_DBG1                                            0x740304

#define mmDDR_MC_CH1_DBGCAM                                          0x740308

#define mmDDR_MC_CH1_DBGCMD                                          0x74030C

#define mmDDR_MC_CH1_DBGSTAT                                         0x740310

#define mmDDR_MC_CH1_SWCTL                                           0x740320

#define mmDDR_MC_CH1_SWSTAT                                          0x740324

#define mmDDR_MC_CH1_POISONCFG                                       0x74036C

#define mmDDR_MC_CH1_POISONSTAT                                      0x740370

#define mmDDR_MC_CH1_ADVECCINDEX                                     0x740374

#define mmDDR_MC_CH1_ECCPOISONPAT0                                   0x74037C

#define mmDDR_MC_CH1_ECCPOISONPAT1                                   0x740380

#define mmDDR_MC_CH1_ECCPOISONPAT2                                   0x740384

#define mmDDR_MC_CH1_CAPARPOISONCTL                                  0x7403A0

#define mmDDR_MC_CH1_CAPARPOISONSTAT                                 0x7403A4

#define mmDDR_MC_CH1_PSTAT                                           0x7403FC

#define mmDDR_MC_CH1_PCCFG                                           0x740400

#define mmDDR_MC_CH1_PCFGR_0                                         0x740404

#define mmDDR_MC_CH1_PCFGW_0                                         0x740408

#define mmDDR_MC_CH1_PCTRL_0                                         0x740490

#define mmDDR_MC_CH1_PCFGQOS0_0                                      0x740494

#define mmDDR_MC_CH1_SBRCTL                                          0x740F24

#define mmDDR_MC_CH1_SBRSTAT                                         0x740F28

#define mmDDR_MC_CH1_SBRWDATA0                                       0x740F2C

#define mmDDR_MC_CH1_SBRWDATA1                                       0x740F30

#endif /* ASIC_REG_DDR_MC_CH1_REGS_H_ */
