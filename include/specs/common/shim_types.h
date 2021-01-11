/* SPDX-License-Identifier: MIT
 *
 * Copyright 2020 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef SHIM_TYPES_H
#define SHIM_TYPES_H

#define SHIM_GET_FUNCTIONS "ShimGetFunctions"

enum shim_api_type {
	SHIM_API_SYNAPSE,
	SHIM_API_HLTHUNK,
	SHIM_API_HCL,
	SHIM_API_PYTORCH,
	SHIM_API_TENSOR_FLOW,
	SHIM_API_MOCK_CPP,
	SHIM_API_MOCK_C,
	SHIM_API_MAX_TYPE, // must be last
};

#endif // SHIM_TYPES_H
