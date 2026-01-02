#pragma once

#include "../../Uefi/Uefi.hpp"

namespace Image
{
	EFI_STATUS
	Validate(
		IN PCVOID ImageBase,
		IN CUINT64 ImageSize
	);

	CBOOLEAN
	IsRangeInBounds(
		IN CUINT64 Offset,
		IN CUINT64 Size,
		IN CUINT64 Total
	);

	EFI_STATUS
	GetNtHeaders64(
		IN PCVOID ImageBase,
		IN CUINT64 ImageSize,
		OUT EFI_IMAGE_NT_HEADERS64*& Nt
	);
}