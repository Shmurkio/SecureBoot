#include "Protocol.hpp"
#include "../../Uefi/Serial/Serial.hpp"
#include "../DevicePath/DevicePath.hpp"
#include "../Image/Image.hpp"

EFI_SECURITY2_ARCH_PROTOCOL gSecurity2Stub = { 0 };

static
EFI_STATUS
__cdecl
FileAuthentication(
	IN PCEFI_SECURITY2_ARCH_PROTOCOL This,
	IN PCEFI_DEVICE_PATH_PROTOCOL File,
	IN PCVOID FileBuffer,
	IN CUINT64 FileSize,
	IN CBOOLEAN BootPolicy
)
{
	Serial::Out << "[SECURITY2] FileAuthentication:" << Serial::Endl;

	PSTR PathStr = nullptr;
	EFI_STATUS Status = DevicePath::PathToStr(File, PathStr);

	if (EfiError(Status))
	{
		Serial::Out << "[+] Getting device path failed" << Serial::Endl;
		return EFI_SUCCESS;
	}

	Serial::Out << "[+] Device path: " << PathStr << Serial::Endl
		<< "[+] Image base: 0x" << Serial::Hex << Serial::Upper << FileBuffer << Serial::Dec << Serial::Endl
		<< "[+] Image size: " << FileSize << Serial::Endl
		<< "[+] Boot policy: " << BootPolicy << Serial::Endl
		<< "[+] Secure boot: " << gSecureBoot << Serial::Endl
		<< "[+] Setup mode: " << gSetupMode << Serial::Endl;

	if (BootPolicy && gSecureBoot && !gSetupMode && FileBuffer && FileSize)
	{
		/*return*/ Image::Validate(FileBuffer, FileSize);
	}

	return EFI_SUCCESS;
}

EFI_STATUS
InstallSecurity2Arch(
	IN EFI_HANDLE ImageHandle,
	IN PEFI_SYSTEM_TABLE SystemTable
)
{
	gSecurity2Stub.FileAuthentication = FileAuthentication;
	return gBS->InstallProtocolInterface(&gImageHandle, const_cast<PCEFI_GUID>(&gEfiSecurity2ArchProtocolGuid), EFI_NATIVE_INTERFACE, reinterpret_cast<PVOID>(&gSecurity2Stub));
}