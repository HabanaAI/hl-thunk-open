/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015 Neil Horman <nhorman@tuxdriver.com>.
 * All rights reserved.
 */

#ifndef _HL_FUNCTION_VERSIONING_H_
#define _HL_FUNCTION_VERSIONING_H_

#define _HL_STR(x) #x
#define HL_STR(x) _HL_STR(x)

#ifdef HL_BUILD_SHARED_LIB

/*
 * Provides backwards compatibility when updating exported functions.
 * When a symol is exported from a library to provide an API, it also provides a
 * calling convention (ABI) that is embodied in its name, return type,
 * arguments, etc.  On occasion that function may need to change to accommodate
 * new functionality, behavior, etc.  When that occurs, it is desirable to
 * allow for backwards compatibility for a time with older binaries that are
 * dynamically linked to the dpdk.  To support that, the __vsym and
 * VERSION_SYMBOL macros are created.  They, in conjunction with the
 * <library>_version.map file for a given library allow for multiple versions of
 * a symbol to exist in a shared library so that older binaries need not be
 * immediately recompiled.
 *
 * Refer to the guidelines document in the docs subdirectory for details on the
 * use of these macros
 */

/*
 * Macro Parameters:
 * b - function base name
 * e - function version extension, to be concatenated with base name
 * n - function symbol version string to be applied
 * f - function prototype
 * p - full function symbol name
 */

/*
 * VERSION_SYMBOL
 * Creates a symbol version table entry binding symbol <b>@HLTNK_<n> to the
 * internal function name <b>_<e>
 */
#define VERSION_SYMBOL(b, e, n) \
__asm__(".symver " HL_STR(b) HL_STR(e) ", " HL_STR(b) "@HLTNK_" HL_STR(n))

/*
 * BIND_DEFAULT_SYMBOL
 * Creates a symbol version entry instructing the linker to bind references to
 * symbol <b> to the internal symbol <b>_<e>
 */
#define BIND_DEFAULT_SYMBOL(b, e, n) \
__asm__(".symver " HL_STR(b) HL_STR(e) ", " HL_STR(b) "@@HLTNK_" HL_STR(n))

#define __vsym __attribute__((used))

/*
 * MAP_STATIC_SYMBOL
 * If a function has been bifurcated into multiple versions, none of which
 * are defined as the exported symbol name in the map file, this macro can be
 * used to alias a specific version of the symbol to its exported name.  For
 * example, if you have 2 versions of a function foo_v1 and foo_v2, where the
 * former is mapped to foo@HLTNK_1 and the latter is mapped to foo@HLTNK_2 when
 * building a shared library, this macro can be used to map either foo_v1 or
 * foo_v2 to the symbol foo when building a static library, e.g.:
 * MAP_STATIC_SYMBOL(void foo(), foo_v2);
 */
#define MAP_STATIC_SYMBOL(f, p)

#else
/*
 * No symbol versioning in use
 */
#define VERSION_SYMBOL(b, e, n)
#define __vsym
#define BIND_DEFAULT_SYMBOL(b, e, n)
#define UNPAREN(x) x
#define MAP_STATIC_SYMBOL(f, p) UNPAREN(f __attribute__((alias(HL_STR(p)))))
/*
 * HL_BUILD_SHARED_LIB=n
 */
#endif

#endif /* _HL_FUNCTION_VERSIONING_H_ */
