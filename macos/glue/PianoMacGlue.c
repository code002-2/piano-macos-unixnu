/*
 * Board hooks for macOS 27.3 on piano.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
#include <stdint.h>

/* macos-owner-root-authenticated-open.patch: set once a verified root is mounted. */
volatile int native_owner_root_accepted;
volatile int32_t native_owner_root_mount_device = -1;	/* NODEV */

/* Optional USB bring-up hooks referenced by NativeUfs diagnostics. */
int piano_usb_bringup(void)
{
	return 0;
}

void piano_usb_table_dump(void)
{
}
