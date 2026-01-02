#include "DevicePath.hpp"
#include "../../Uefi/Util/Util.hpp"

static PEFI_DEVICE_PATH_TO_TEXT_PROTOCOL gDpToText = nullptr;

static
inline
EFI_STATUS
Init(
	VOID
)
{
	if (!gDpToText)
	{
		return gBS->LocateProtocol(const_cast<PCEFI_GUID>(&gEfiDevicePathToTextProtocolGuid), nullptr, reinterpret_cast<PVOID*>(&gDpToText));
	}

	return EFI_SUCCESS;
}

EFI_STATUS
DevicePath::PathToStr(
	IN PCEFI_DEVICE_PATH_PROTOCOL Path,
	OUT PSTR& Str
)
{
	Str = nullptr;

	if (!Path)
	{
		return EFI_INVALID_PARAMETER;
	}

	EFI_STATUS Status = EFI_SUCCESS;

	if (!gDpToText)
	{
		Status = Init();

		if (EfiError(Status))
		{
			return Status;
		}
	}

	PCWSTR StrW = gDpToText->ConvertDevicePathToPath(Path, true, true);

	if (!StrW)
	{
		return EFI_ABORTED;
	}

	PWSTR Temp = const_cast<PWSTR>(StrW);
	Status = Util::StrWToStr(Temp, Str, true, false);

	return Status;
}