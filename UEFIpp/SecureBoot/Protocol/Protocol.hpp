#pragma once

#include "../../Uefi/Uefi.hpp"

extern BOOLEAN gSecureBoot, gSetupMode;

namespace Protocol
{
	EFI_STATUS
	Install(
		IN EFI_HANDLE ImageHandle,
		IN PEFI_SYSTEM_TABLE SystemTable
	);
}