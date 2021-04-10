/* SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef PCI_IDS_H
#define PCI_IDS_H

#define PCI_VENDOR_ID_HABANALABS	0x1da3

enum hl_pci_ids {
	/* PCI device ID 0 is not legal */
	PCI_IDS_INVALID			= 0x0000,
	PCI_IDS_GOYA			= 0x0001,
	PCI_IDS_GAUDI			= 0x1000,
	PCI_IDS_GAUDI_SEC		= 0x1010,
	PCI_IDS_GOYA_SIMULATOR		= 0xff01,
	PCI_IDS_GAUDI_SIMULATOR		= 0xff02,
	PCI_IDS_GOYA_FPGA		= 0xff03,
	PCI_IDS_GAUDI_FPGA		= 0xff04,
};

#endif /* PCI_IDS_H */
