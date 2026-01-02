#include "Protocol.hpp"

EFI_SECURITY_ARCH_PROTOCOL gSecurityStub = { 0 };

static
EFI_STATUS
__cdecl
FileAuthenticationState(
	IN PCEFI_SECURITY_ARCH_PROTOCOL This,
	IN CUINT32 AuthenticationStatus,
	IN PCEFI_DEVICE_PATH_PROTOCOL File
)
{
	return EFI_SUCCESS;
}

EFI_STATUS
InstallSecurityArch(
	IN EFI_HANDLE ImageHandle,
	IN PEFI_SYSTEM_TABLE SystemTable
)
{
	gSecurityStub.FileAuthenticationState = FileAuthenticationState;
	return gBS->InstallProtocolInterface(&gImageHandle, const_cast<PCEFI_GUID>(&gEfiSecurityArchProtocolGuid), EFI_NATIVE_INTERFACE, reinterpret_cast<PVOID>(&gSecurityStub));
}