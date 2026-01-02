#pragma once

#include "../../Uefi/Uefi.hpp"

namespace DevicePath
{
	EFI_STATUS
	PathToStr(
		IN PCEFI_DEVICE_PATH_PROTOCOL Path,
		OUT PSTR& Str
	);
}