#include "Protocol.hpp"
#include "../../Uefi/NVRAM/NVRAM.hpp"

BOOLEAN gSecureBoot = false, gSetupMode = false;

EFI_STATUS
InstallSecurityArch(
	IN EFI_HANDLE ImageHandle,
	IN PEFI_SYSTEM_TABLE SystemTable
);

EFI_STATUS
InstallSecurity2Arch(
	IN EFI_HANDLE ImageHandle,
	IN PEFI_SYSTEM_TABLE SystemTable
);

static
EFI_STATUS
GetMode(
	OUT BOOLEAN& SecureBoot,
	OUT BOOLEAN& SetupMode
)
{
	SecureBoot = false;
	SetupMode = false;

	PUINT8 Buffer = nullptr;
	UINT64 DataSize = 0;

	EFI_STATUS Status = NVRAM::Get<UINT8>(gEfiGlobalVariableGuid, "SecureBoot", Buffer, DataSize, true);

	if (EfiError(Status))
	{
		return Status;
	}

	if (DataSize != sizeof(BOOLEAN))
	{
		return EFI_BAD_BUFFER_SIZE;
	}

	if (Buffer[0])
	{
		SecureBoot = true;
	}
	else
	{
		SecureBoot = false;
	}

	delete[] Buffer;
	Buffer = nullptr;
	DataSize = 0;

	Status = NVRAM::Get<UINT8>(gEfiGlobalVariableGuid, "SetupMode", Buffer, DataSize, true);

	if (EfiError(Status))
	{
		SecureBoot = false;
		return Status;
	}

	if (DataSize != sizeof(BOOLEAN))
	{
		SecureBoot = false;
		return EFI_BAD_BUFFER_SIZE;
	}

	if (Buffer[0])
	{
		SetupMode = true;
	}
	else
	{
		SetupMode = false;
	}

	delete[] Buffer;

	return EFI_SUCCESS;
}

EFI_STATUS
Protocol::Install(
	IN EFI_HANDLE ImageHandle,
	IN PEFI_SYSTEM_TABLE SystemTable
)
{
	GetMode(gSecureBoot, gSetupMode);
	InstallSecurityArch(ImageHandle, SystemTable);
	InstallSecurity2Arch(ImageHandle, SystemTable);

	return EFI_SUCCESS;
}