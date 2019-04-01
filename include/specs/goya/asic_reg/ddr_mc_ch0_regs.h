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

#ifndef ASIC_REG_DDR_MC_CH0_REGS_H_
#define ASIC_REG_DDR_MC_CH0_REGS_H_

/*
 *****************************************
 *   DDR_MC_CH0 (Prototype: DDR_MC)
 *****************************************
 */

#define mmDDR_MC_CH0_MSTR                                            0x640000

#define mmDDR_MC_CH0_STAT                                            0x640004

#define mmDDR_MC_CH0_MRCTRL0                                         0x640010

#define mmDDR_MC_CH0_MRCTRL1                                         0x640014

#define mmDDR_MC_CH0_MRSTAT                                          0x640018

#define mmDDR_MC_CH0_MRCTRL2                                         0x64001C

#define mmDDR_MC_CH0_PWRCTL                                          0x640030

#define mmDDR_MC_CH0_PWRTMG                                          0x640034

#define mmDDR_MC_CH0_HWLPCTL                                         0x640038

#define mmDDR_MC_CH0_RFSHCTL0                                        0x640050

#define mmDDR_MC_CH0_RFSHCTL1                                        0x640054

#define mmDDR_MC_CH0_RFSHCTL3                                        0x640060

#define mmDDR_MC_CH0_RFSHTMG                                         0x640064

#define mmDDR_MC_CH0_ECCCFG0                                         0x640070

#define mmDDR_MC_CH0_ECCCFG1                                         0x640074

#define mmDDR_MC_CH0_ECCSTAT                                         0x640078

#define mmDDR_MC_CH0_ECCCTL                                          0x64007C

#define mmDDR_MC_CH0_ECCERRCNT                                       0x640080

#define mmDDR_MC_CH0_ECCCADDR0                                       0x640084

#define mmDDR_MC_CH0_ECCCADDR1                                       0x640088

#define mmDDR_MC_CH0_ECCCSYN0                                        0x64008C

#define mmDDR_MC_CH0_ECCCSYN1                                        0x640090

#define mmDDR_MC_CH0_ECCCSYN2                                        0x640094

#define mmDDR_MC_CH0_ECCBITMASK0                                     0x640098

#define mmDDR_MC_CH0_ECCBITMASK1                                     0x64009C

#define mmDDR_MC_CH0_ECCBITMASK2                                     0x6400A0

#define mmDDR_MC_CH0_ECCUADDR0                                       0x6400A4

#define mmDDR_MC_CH0_ECCUADDR1                                       0x6400A8

#define mmDDR_MC_CH0_ECCUSYN0                                        0x6400AC

#define mmDDR_MC_CH0_ECCUSYN1                                        0x6400B0

#define mmDDR_MC_CH0_ECCUSYN2                                        0x6400B4

#define mmDDR_MC_CH0_ECCPOISONADDR0                                  0x6400B8

#define mmDDR_MC_CH0_ECCPOISONADDR1                                  0x6400BC

#define mmDDR_MC_CH0_CRCPARCTL0                                      0x6400C0

#define mmDDR_MC_CH0_CRCPARCTL1                                      0x6400C4

#define mmDDR_MC_CH0_CRCPARCTL2                                      0x6400C8

#define mmDDR_MC_CH0_CRCPARSTAT                                      0x6400CC

#define mmDDR_MC_CH0_INIT0                                           0x6400D0

#define mmDDR_MC_CH0_INIT1                                           0x6400D4

#define mmDDR_MC_CH0_INIT3                                           0x6400DC

#define mmDDR_MC_CH0_INIT4                                           0x6400E0

#define mmDDR_MC_CH0_INIT5                                           0x6400E4

#define mmDDR_MC_CH0_INIT6                                           0x6400E8

#define mmDDR_MC_CH0_INIT7                                           0x6400EC

#define mmDDR_MC_CH0_DIMMCTL                                         0x6400F0

#define mmDDR_MC_CH0_RANKCTL                                         0x6400F4

#define mmDDR_MC_CH0_DRAMTMG0                                        0x640100

#define mmDDR_MC_CH0_DRAMTMG1                                        0x640104

#define mmDDR_MC_CH0_DRAMTMG2                                        0x640108

#define mmDDR_MC_CH0_DRAMTMG3                                        0x64010C

#define mmDDR_MC_CH0_DRAMTMG4                                        0x640110

#define mmDDR_MC_CH0_DRAMTMG5                                        0x640114

#define mmDDR_MC_CH0_DRAMTMG8                                        0x640120

#define mmDDR_MC_CH0_DRAMTMG9                                        0x640124

#define mmDDR_MC_CH0_DRAMTMG10                                       0x640128

#define mmDDR_MC_CH0_DRAMTMG11                                       0x64012C

#define mmDDR_MC_CH0_DRAMTMG12                                       0x640130

#define mmDDR_MC_CH0_DRAMTMG15                                       0x64013C

#define mmDDR_MC_CH0_ZQCTL0                                          0x640180

#define mmDDR_MC_CH0_ZQCTL1                                          0x640184

#define mmDDR_MC_CH0_DFITMG0                                         0x640190

#define mmDDR_MC_CH0_DFITMG1                                         0x640194

#define mmDDR_MC_CH0_DFILPCFG0                                       0x640198

#define mmDDR_MC_CH0_DFILPCFG1                                       0x64019C

#define mmDDR_MC_CH0_DFIUPD0                                         0x6401A0

#define mmDDR_MC_CH0_DFIUPD1                                         0x6401A4

#define mmDDR_MC_CH0_DFIUPD2                                         0x6401A8

#define mmDDR_MC_CH0_DFIMISC                                         0x6401B0

#define mmDDR_MC_CH0_DFITMG2                                         0x6401B4

#define mmDDR_MC_CH0_DFITMG3                                         0x6401B8

#define mmDDR_MC_CH0_DFISTAT                                         0x6401BC

#define mmDDR_MC_CH0_DBICTL                                          0x6401C0

#define mmDDR_MC_CH0_DFIPHYMSTR                                      0x6401C4

#define mmDDR_MC_CH0_ADDRMAP0                                        0x640200

#define mmDDR_MC_CH0_ADDRMAP1                                        0x640204

#define mmDDR_MC_CH0_ADDRMAP2                                        0x640208

#define mmDDR_MC_CH0_ADDRMAP3                                        0x64020C

#define mmDDR_MC_CH0_ADDRMAP4                                        0x640210

#define mmDDR_MC_CH0_ADDRMAP5                                        0x640214

#define mmDDR_MC_CH0_ADDRMAP6                                        0x640218

#define mmDDR_MC_CH0_ADDRMAP7                                        0x64021C

#define mmDDR_MC_CH0_ADDRMAP8                                        0x640220

#define mmDDR_MC_CH0_ADDRMAP9                                        0x640224

#define mmDDR_MC_CH0_ADDRMAP10                                       0x640228

#define mmDDR_MC_CH0_ADDRMAP11                                       0x64022C

#define mmDDR_MC_CH0_ODTCFG                                          0x640240

#define mmDDR_MC_CH0_ODTMAP                                          0x640244

#define mmDDR_MC_CH0_SCHED                                           0x640250

#define mmDDR_MC_CH0_SCHED1                                          0x640254

#define mmDDR_MC_CH0_PERFHPR1                                        0x64025C

#define mmDDR_MC_CH0_PERFLPR1                                        0x640264

#define mmDDR_MC_CH0_PERFWR1                                         0x64026C

#define mmDDR_MC_CH0_DQMAP0                                          0x640280

#define mmDDR_MC_CH0_DQMAP1                                          0x640284

#define mmDDR_MC_CH0_DQMAP2                                          0x640288

#define mmDDR_MC_CH0_DQMAP3                                          0x64028C

#define mmDDR_MC_CH0_DQMAP4                                          0x640290

#define mmDDR_MC_CH0_DQMAP5                                          0x640294

#define mmDDR_MC_CH0_DBG0                                            0x640300

#define mmDDR_MC_CH0_DBG1                                            0x640304

#define mmDDR_MC_CH0_DBGCAM                                          0x640308

#define mmDDR_MC_CH0_DBGCMD                                          0x64030C

#define mmDDR_MC_CH0_DBGSTAT                                         0x640310

#define mmDDR_MC_CH0_SWCTL                                           0x640320

#define mmDDR_MC_CH0_SWSTAT                                          0x640324

#define mmDDR_MC_CH0_POISONCFG                                       0x64036C

#define mmDDR_MC_CH0_POISONSTAT                                      0x640370

#define mmDDR_MC_CH0_ADVECCINDEX                                     0x640374

#define mmDDR_MC_CH0_ECCPOISONPAT0                                   0x64037C

#define mmDDR_MC_CH0_ECCPOISONPAT1                                   0x640380

#define mmDDR_MC_CH0_ECCPOISONPAT2                                   0x640384

#define mmDDR_MC_CH0_CAPARPOISONCTL                                  0x6403A0

#define mmDDR_MC_CH0_CAPARPOISONSTAT                                 0x6403A4

#define mmDDR_MC_CH0_PSTAT                                           0x6403FC

#define mmDDR_MC_CH0_PCCFG                                           0x640400

#define mmDDR_MC_CH0_PCFGR_0                                         0x640404

#define mmDDR_MC_CH0_PCFGW_0                                         0x640408

#define mmDDR_MC_CH0_PCTRL_0                                         0x640490

#define mmDDR_MC_CH0_PCFGQOS0_0                                      0x640494

#define mmDDR_MC_CH0_SBRCTL                                          0x640F24

#define mmDDR_MC_CH0_SBRSTAT                                         0x640F28

#define mmDDR_MC_CH0_SBRWDATA0                                       0x640F2C

#define mmDDR_MC_CH0_SBRWDATA1                                       0x640F30

#endif /* ASIC_REG_DDR_MC_CH0_REGS_H_ */
