#pragma once

#include "../../Uefi/Uefi.hpp"

namespace PKCS7
{
#pragma pack(push, 1)
	typedef struct _WIN_CERTIFICATE
	{
		UINT32 Length;
		UINT16 Revision;
		UINT16 CertificateType;
		UINT8 Certificate[1];
	} WIN_CERTIFICATE, *PWIN_CERTIFICATE;
#pragma pop

	using CWIN_CERTIFICATE = const WIN_CERTIFICATE;
	using PCWIN_CERTIFICATE = const WIN_CERTIFICATE*;

	typedef struct _WIN_CERT_VIEW
	{
		PUINT8 Base;
		UINT32 TotalSize;
		UINT16 Revision;
		UINT16 CertType;
		PUINT8 Data;
		UINT32 DataSize;
		BOOLEAN Present;
	} WIN_CERT_VIEW, *PWIN_CERT_VIEW;

	using CWIN_CERT_VIEW = const WIN_CERT_VIEW;
	using PCWIN_CERT_VIEW = const WIN_CERT_VIEW*;

	EFI_STATUS
	GetCert(
		IN PCVOID ImageBase,
		IN CUINT64 ImageSize,
		OUT WIN_CERT_VIEW& View
	);
}