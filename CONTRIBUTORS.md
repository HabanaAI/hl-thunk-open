# Contributors

This file acknowledges the major contributors to `hl-thunk`, derived from the
project's commit history. It is generated periodically as the public mirror
is synced with newer releases, so it may not reflect every individual commit
author — only those with a substantial number of commits to the codebase
(currently: 10 or more) as of the most recent sync.

## Notable changes (this sync — Habana SW 1.24.1)

**Common / Gaudi / Gaudi2**
- Core API evolution: substantial refactor of `src/libhlthunk.c` and
  `src/libhlthunk.h` across releases, plus a new `src/libhlthunk_nic.c`
  (~1,140 lines) adding dedicated NIC/RDMA ioctl wrappers.
- Safer string handling: expanded use of `snprintf()` over `sprintf()` in
  sysfs/PCI path and MAC-address string construction.
- Continuous hardware register spec maintenance under
  `include/specs/{gaudi,gaudi2}/asic_reg`.

**Gaudi3**
- Platform introduction: Gaudi3 device masks and opcodes added to the test
  framework and UAPI (`HLTEST_DEVICE_MASK_GAUDI3*`, new opcodes).
- New `include/specs/gaudi3` and `include/specs/gaudi3/asic_reg` register
  definitions (181 Gaudi3-related files added in this sync).
- New `tests/gaudi3` suite (device init, memory, DMA, NIC scenarios) and a
  new `tests/engines-arc` tree (91 files) — ARC scheduler/engine test
  tooling shared by Gaudi2/Gaudi3.
- New `scripts/test_runner` (21 files) — Python-based test orchestration.

## Key contributors (by commit count, full project history: 2019–2026)

Based on the internal development history (5,068 commits). Descriptions
reflect each contributor's most-touched areas of the actual `hl-thunk`
codebase, not other Habana repositories.

**Oded Gabbay (617 commits)** — Core `libhlthunk` API implementation and
maintenance, device registration/initialization, and long-running hardware
register spec upkeep.

**Tomer Tayar (446 commits)** — UAPI ioctl interface definitions, Gaudi2/
Gaudi3 test coverage, hardware register specs, core library maintenance.

**Omer Shpigelman (363 commits)** — Gaudi/Gaudi2 test suite development,
FS1 platform support, hardware register specs, UAPI definitions.

**Ofir Bitton (213 commits)** — Hardware register spec alignment, common
test infrastructure, core thunk API, Gaudi3 test coverage.

**Tal Risin (210 commits)** — FS1 and Gaudi3 platform test development,
UAPI extensions, common test infrastructure.

**Sagiv Ozeri (209 commits)** — Gaudi3 and Gaudi2 test development, common
test infrastructure, UAPI extensions.

**Dani Liberman (196 commits)** — Common test infrastructure, Gaudi3 test
development, UAPI and register spec updates.

**Alex Perlin (195 commits)** — CI/CD pipeline automation for build, test,
and release-promotion workflows (pipeline configs are internal-only and not
part of this public mirror, but the historical contribution is real).

**Koby Elbaz (183 commits)** — Common test infrastructure, hardware
register specs, Gaudi3 test development.

**Dafna Hirschfeld (178 commits)** — Common test infrastructure, UAPI
definitions, Gaudi3 test development, ARC scheduler test tooling
(`tests/engines-arc`).

**Animesh Kishore (151 commits)** — Common and Gaudi3 test infrastructure,
UAPI extensions, core thunk library contributions.

## Everyone else (10+ commits)

Contributors are listed alphabetically by first name, with the corporate
contact address associated with their commits.

- Abhilash K V <abhilash.k.v@intel.com>
- Alex Perlin <aperlin@habana.ai>
- Alexey Nikandrov <anikandrov@habana.ai>
- Alon Mizrahi <amizrahi@habana.ai>
- Andrey Agranovich <andrey.agranovich@intel.com>
- Animesh Kishore <akishore@habana.ai>
- Ariel Suller <asuller@habana.ai>
- Avri Kehat <avri.kehat@intel.com>
- Bartosz Myrcha <bmyrcha@habana.ai>
- Bharat Jauhari <bjauhari@habana.ai>
- Dafna Hirschfeld <dafna.hirschfeld@intel.com>
- Dalit Ben Zoor <dbenzoor@habana.ai>
- Dan Rapaport <drapaport@habana.ai>
- Dani Liberman <dliberman@habana.ai>
- David Meriin <dmeriin@habana.ai>
- Didi Freiman <didi.freiman@intel.com>
- Dotan Barak <dbarak@habana.ai>
- Eyal Greenblatt <eyal.greenblatt@intel.com>
- Farah Kassabri <farah.kassabri@intel.com>
- Ganesh Kumar Gurumurthy <gkgurumurthy@habana.ai>
- Gila Aweke <gila.aweke@intel.com>
- Ido Gan <ido.gan@intel.com>
- Ilia Levi <ilia.levi@intel.com>
- Ilya Natanzon <ilya.natanzon@intel.com>
- Itay Shay <ishay@habana.ai>
- Kaleemulla Mogal <kmogal@habana.ai>
- Koby Elbaz <kelbaz@habana.ai>
- Moti Haimovski <moti.haimovski@intel.com>
- Oded Gabbay <ogabbay@habana.ai>
- Ofir Bitton <obitton@habana.ai>
- Ohad Sharabi <osharabi@habana.ai>
- Olga Ostrer <okaushansky@habana.ai>
- Omer Shpigelman <oshpigelman@habana.ai>
- Pawel Szewc <pszewc@habana.ai>
- Rajaravi Krishna Katta <rkatta@habana.ai>
- Roni Polak <ropolak@habana.ai>
- Roy Lenz <rlenz@habana.ai>
- Saar Gamzo <sgamzo@habana.ai>
- Sagiv Ozeri <sozeri@habana.ai>
- Shahar Pickman <spickman@habana.ai>
- Sharley Calzolari <sharley.calzolari@intel.com>
- Surendra Kumar Singh <ssingh@habana.ai>
- Tadeusz Lipiński <tadeuszx.lipinski@intel.com>
- Tal Albo <talbo@habana.ai>
- Tal Cohen <tal5.cohen@intel.com>
- Tal Risin <tal.risin@intel.com>
- Tomer Tayar <ttayar@habana.ai>
- Yonatan Cohen <ycohen@habana.ai>
- Yuri Nudelman <ynudelman@habana.ai>
- Yuval Elmaliah <yuval.elmaliah@intel.com>
- Zvika Yehudai <zvika.yehudai@intel.com>

Thank you to everyone else who has contributed smaller fixes and
improvements — they are still visible in the commit history of the
internal development repository even though this public mirror is
synced as a squashed snapshot rather than a full commit-by-commit
history.
