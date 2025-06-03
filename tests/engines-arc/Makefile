HOME ?= ~
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(dir $(MKFILE_PATH))

OUT_DIR ?= output
SCHED_FILE := scheduler
ENGINE_FILE := engine

ifdef ARC_DEBUG
SCHED_OUT_DIR := $(OUT_DIR)/scheduler_debug_build
ENGINE_OUT_DIR := $(OUT_DIR)/engine_debug_build
else
SCHED_OUT_DIR := $(OUT_DIR)/scheduler_release_build
ENGINE_OUT_DIR := $(OUT_DIR)/engine_release_build
endif

SYNOPSYS_ROOT = /synopsys/arc_MWDT_ARC/2022.09
METAWARE_ROOT = $(SYNOPSYS_ROOT)/MetaWare
METAWARE_INCLUDE = $(METAWARE_ROOT)/arc/inc

SCHED_SRC_DIR := scheduler/src
ENGINE_SRC_DIR := engine/src
COMMON_SRC_DIR := common/src

#TESTS_SCHED_DIR := tests/scheduler
#TESTS_SCHED_SRC_DIR := $(TESTS_SCHED_DIR)/src
#TESTS_ENGINE_DIR := tests/engine
#TESTS_ENGINE_SRC_DIR := $(TESTS_ENGINE_DIR)/src
#TESTS_COMMON_DIR := tests/common
#TESTS_COMMON_SRC_DIR := $(TESTS_COMMON_DIR)/src


#Scheduler ARC Linker file
SCHED_LDSCRIPT := $(SCHED_SRC_DIR)/scheduler.lcf

#Engine ARC Linker file
ENGINE_LDSCRIPT := $(ENGINE_SRC_DIR)/engine.lcf

#Scheduler ARC source C files
SCHED_SRC := $(SCHED_SRC_DIR)/main.c
SCHED_SRC += $(SCHED_SRC_DIR)/gaudi2_sched_regs.c
SCHED_SRC += $(SCHED_SRC_DIR)/gaudi3_sched_regs.c
SCHED_SRC += $(SCHED_SRC_DIR)/init.c
SCHED_SRC += $(SCHED_SRC_DIR)/sched.c
SCHED_SRC += $(SCHED_SRC_DIR)/qman_cmds.c
SCHED_SRC += $(SCHED_SRC_DIR)/sched_queues.c
SCHED_SRC += $(COMMON_SRC_DIR)/dma.c
SCHED_SRC += $(COMMON_SRC_DIR)/utils.c
SCHED_SRC += $(COMMON_SRC_DIR)/debug.c
SCHED_SRC += $(COMMON_SRC_DIR)/cache.c
SCHED_SRC += $(COMMON_SRC_DIR)/logger.c
SCHED_SRC += $(COMMON_SRC_DIR)/gaudi2_comm_regs.c
SCHED_SRC += $(COMMON_SRC_DIR)/gaudi3_comm_regs.c
SCHED_SRC += $(COMMON_SRC_DIR)/printf.c

SCHED_SRC += $(COMMON_SRC_DIR)/arc_queue_local.c

#Scheduler ARC source ASM files
SCHED_SRC_S := $(SCHED_SRC_DIR)/crt0_sched.S

#Engine ARC source files
ENGINE_SRC := $(ENGINE_SRC_DIR)/main.c
ENGINE_SRC += $(ENGINE_SRC_DIR)/gaudi2_eng_regs.c
ENGINE_SRC += $(ENGINE_SRC_DIR)/gaudi3_eng_regs.c
ENGINE_SRC += $(ENGINE_SRC_DIR)/init.c
ENGINE_SRC += $(ENGINE_SRC_DIR)/regs.c
ENGINE_SRC += $(ENGINE_SRC_DIR)/engine_arc.c
ENGINE_SRC += $(ENGINE_SRC_DIR)/arc_queue_pvt.c
ENGINE_SRC += $(ENGINE_SRC_DIR)/qman_if.c

ENGINE_SRC += $(COMMON_SRC_DIR)/cache.c
ENGINE_SRC += $(COMMON_SRC_DIR)/logger.c
ENGINE_SRC += $(COMMON_SRC_DIR)/dma.c
ENGINE_SRC += $(COMMON_SRC_DIR)/arc_queue_local.c
ENGINE_SRC += $(COMMON_SRC_DIR)/utils.c
ENGINE_SRC += $(COMMON_SRC_DIR)/debug.c
ENGINE_SRC += $(COMMON_SRC_DIR)/gaudi2_comm_regs.c
ENGINE_SRC += $(COMMON_SRC_DIR)/gaudi3_comm_regs.c
ENGINE_SRC += $(COMMON_SRC_DIR)/printf.c

#Engine ARC source ASM files
ENGINE_SRC_S := $(ENGINE_SRC_DIR)/crt0_engine.S

COMMON_HEADERS := $(wildcard include/*/*.h) $(wildcard common/include/*.h)
SCHED_HEADERS := $(COMMON_HEADERS) $(wildcard scheduler/include/*.h)
ENGINE_HEADERS := $(COMMON_HEADERS) $(wildcard engine/include/*.h)

COMMON_INCLUDES := -I ./include
COMMON_INCLUDES += -I ./common/include
COMMON_INCLUDES += -I ../../include/specs

SCHED_INCLUDES := -I ./scheduler/include

ENGINE_INCLUDES := -I ./engine/include
#TESTS_INCLUDES := -I ./tests/include
#TESTS_INCLUDES += -I ./$(TESTS_SCHED_DIR)/include
#TESTS_INCLUDES += -I ./$(TESTS_ENGINE_DIR)/include

LIBS :=

ifeq ($(TARGET_CPU),x86)
CFLAGS := -Wall -g -O0
CC = gcc
COMMON_INCLUDES += -I $(METAWARE_INCLUDE)/arc
else
CFLAGS := -arcv2hs -core4 -Xdual_issue -Xcode_density -Hrgf_banked_regs=32
CFLAGS += -HL -Xll64 -Xunaligned -Xdiv_rem=radix4 -Xswap -Xbitscan
CFLAGS += -Xmpy_option=qmpyh -Xshift_assist -Xbarrel_shifter -Xfpus_div
CFLAGS += -Xfpu_mac -Xtimer0 -Xtimer1 -Xstack_check -dcache=8192,128,2,a
CFLAGS += -Hld_cycles=2 -Xlpb_size=128 -Hpipeline -Hzd_size_threshold=8
CFLAGS += -Hnocrt -Hnolib -e_start -Hnocopyr -Hldopt=-Cstatics
CFLAGS += -fno-builtin -Hloop_sms -Hlto
CFLAGS += -DPRINTF_INCLUDE_CONFIG_H -Werror

ifdef ARC_DEBUG
CFLAGS += -Wall -g -O0 -DARC_DEBUG
else
CFLAGS += -Wall -g -O3
endif

ifdef FAKE_WORKLOAD
CFLAGS += -DFAKE_WORKLOAD
endif

ifdef SCHED_LOOPBACK
CFLAGS += -DSCHED_LOOPBACK
endif

ifdef USE_FW_ACP
CFLAGS += -DUSE_FW_ACP
endif

CC = $(METAWARE_ROOT)/arc/bin/ccac
ELF2BIN = $(METAWARE_ROOT)/arc/bin/elf2bin

COMMON_INCLUDES += -I $(METAWARE_INCLUDE)/arc
endif

ENGINE_CFLAGS := -DENGINE_ARC
SCHED_CFLAGS := -DSCHED_ARC

SCHED_OBJ := $(SCHED_SRC:.c=.o)
SCHED_OBJ += $(SCHED_SRC_S:.S=.o)
SCHED_OBJS := $(addprefix $(SCHED_OUT_DIR)/, $(SCHED_OBJ))

ENGINE_OBJ := $(ENGINE_SRC:.c=.o)
ENGINE_OBJ += $(ENGINE_SRC_S:.S=.o)
ENGINE_OBJS := $(addprefix $(ENGINE_OUT_DIR)/, $(ENGINE_OBJ))

.PHONY: all scheduler engine
all: $(SCHED_FILE).elf $(ENGINE_FILE).elf
	@$(ELF2BIN) $(SCHED_OUT_DIR)/$(SCHED_FILE).elf $(SCHED_OUT_DIR)/sched_dccm.tmp -b 0x80000000 -t 0x80010000 -q
	@$(ELF2BIN) $(SCHED_OUT_DIR)/$(SCHED_FILE).elf $(SCHED_OUT_DIR)/sched_hbmcode.tmp -b 0x40000000 -t 0x4001E000 -q
	@$(ELF2BIN) $(SCHED_OUT_DIR)/$(SCHED_FILE).elf $(SCHED_OUT_DIR)/sched_hbmdata.tmp -b 0x4001E000 -t 0x40020000 -q
	@cat $(SCHED_OUT_DIR)/sched_dccm.tmp $(SCHED_OUT_DIR)/sched_hbmcode.tmp $(SCHED_OUT_DIR)/sched_hbmdata.tmp > $(OUT_DIR)/$(SCHED_FILE).bin
	@$(ELF2BIN) $(ENGINE_OUT_DIR)/$(ENGINE_FILE).elf $(ENGINE_OUT_DIR)/eng_dccm.tmp -b 0x80000000 -t 0x80008000 -q
	@$(ELF2BIN) $(ENGINE_OUT_DIR)/$(ENGINE_FILE).elf $(ENGINE_OUT_DIR)/eng_hbmcode.tmp -b 0x40000000 -t 0x4001E000 -q
	@$(ELF2BIN) $(ENGINE_OUT_DIR)/$(ENGINE_FILE).elf $(ENGINE_OUT_DIR)/eng_hbmdata.tmp -b 0x4001E000 -t 0x40020000 -q
	@cat $(ENGINE_OUT_DIR)/eng_dccm.tmp $(ENGINE_OUT_DIR)/eng_hbmcode.tmp $(ENGINE_OUT_DIR)/eng_hbmdata.tmp > $(OUT_DIR)/$(ENGINE_FILE).bin

engine: $(ENGINE_FILE).elf

$(ENGINE_FILE).elf: $(ENGINE_OBJS) $(ENGINE_LDSCRIPT)
	$(CC) $(ENGINE_OBJS) $(ENGINE_LDSCRIPT) $(CFLAGS) $(LDFLAGS) -Hldopt=-Coutput=$(ENGINE_OUT_DIR)/$@.map -o $(ENGINE_OUT_DIR)/$@

scheduler: $(SCHED_FILE).elf

$(SCHED_FILE).elf: $(SCHED_OBJS) $(SCHED_LDSCRIPT)
	$(CC) $(SCHED_OBJS) $(SCHED_LDSCRIPT) $(CFLAGS) $(LDFLAGS) -Hldopt=-Coutput=$(SCHED_OUT_DIR)/$@.map -o $(SCHED_OUT_DIR)/$@

$(SCHED_OUT_DIR)/%.o: %.c $(SCHED_HEADERS) | $(SCHED_OUT_DIR)
	$(CC) $(SCHED_CFLAGS) $(CFLAGS) $(COMMON_INCLUDES) $(TESTS_INCLUDES) $(SCHED_INCLUDES) -c $< -o $@

$(SCHED_OUT_DIR)/%.o: %.S | $(SCHED_OUT_DIR)
	$(CC) $(SCHED_CFLAGS) $(CFLAGS) $(COMMON_INCLUDES) $(TESTS_INCLUDES) $(SCHED_INCLUDES) -c $< -o $@

$(ENGINE_OUT_DIR)/%.o: %.c $(ENGINE_HEADERS) | $(ENGINE_OUT_DIR)
	$(CC) $(ENGINE_CFLAGS) $(CFLAGS) $(COMMON_INCLUDES) $(TESTS_INCLUDES) $(ENGINE_INCLUDES) -c $< -o $@

$(ENGINE_OUT_DIR)/%.o: %.S | $(ENGINE_OUT_DIR)
	$(CC) $(ENGINE_CFLAGS) $(CFLAGS) $(COMMON_INCLUDES) $(ENGINE_INCLUDES) -c $< -o $@

$(SCHED_OUT_DIR):
	@mkdir -p $(SCHED_OUT_DIR)/$(SCHED_SRC_DIR)
	@mkdir -p $(SCHED_OUT_DIR)/$(COMMON_SRC_DIR)
#	@mkdir -p $(SCHED_OUT_DIR)/$(TESTS_SCHED_SRC_DIR)
#	@mkdir -p $(SCHED_OUT_DIR)/$(TESTS_COMMON_SRC_DIR)

$(ENGINE_OUT_DIR):
	@mkdir -p $(ENGINE_OUT_DIR)/$(ENGINE_SRC_DIR)
	@mkdir -p $(ENGINE_OUT_DIR)/$(COMMON_SRC_DIR)
#	@mkdir -p $(ENGINE_OUT_DIR)/$(TESTS_ENGINE_SRC_DIR)
#	@mkdir -p $(ENGINE_OUT_DIR)/$(TESTS_COMMON_SRC_DIR)

.PHONY: clean
clean:
	@rm -rf $(SCHED_OUT_DIR)
	@rm -rf $(ENGINE_OUT_DIR)
