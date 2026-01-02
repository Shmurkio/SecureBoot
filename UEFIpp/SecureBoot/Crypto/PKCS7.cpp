#include "PKCS7.hpp"
#include "../Image/Image.hpp"

static
inline
CUINT64
AlignUp8(
	IN CUINT64 X
)
{
	return (X + 7U) & ~7U;
}

static constexpr CUINT16 gWinCertTypeX509 = 0x0001;
static constexpr CUINT16 gWinCertTypePkcsSignedData = 0x0002;

EFI_STATUS
PKCS7::GetCert(
	IN PCVOID ImageBase,
	IN CUINT64 ImageSize,
	OUT WIN_CERT_VIEW& View
)
{
	View = { 0 };

	if (!ImageBase || !ImageSize)
	{
		return EFI_INVALID_PARAMETER;
	}

	EFI_IMAGE_NT_HEADERS64* NtHeaders64 = nullptr;
	EFI_STATUS Status = Image::GetNtHeaders64(ImageBase, ImageSize, NtHeaders64);

	if (EfiError(Status))
	{
		return Status;
	}

	const EFI_IMAGE_OPTIONAL_HEADER64& Opt = NtHeaders64->OptionalHeader;

	if (Opt.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY)
	{
		return EFI_NOT_FOUND;
	}

	const EFI_IMAGE_DATA_DIRECTORY& SecDir = Opt.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];

	if (!SecDir.VirtualAddress || !SecDir.Size)
	{
		return EFI_NOT_FOUND;
	}

	CUINT64 SecOff = SecDir.VirtualAddress;
	CUINT64 SecSize = SecDir.Size;

	if (!Image::IsRangeInBounds(SecOff, SecSize, ImageSize))
	{
		return EFI_COMPROMISED_DATA;
	}

	PCUINT8 Base = reinterpret_cast<PCUINT8>(ImageBase);

	UINT64 Cur = SecOff;
	CUINT64 End = SecOff + SecSize;

	/*
	* [File offset]
	* ┌──────────────────────────┐
	* │ WIN_CERTIFICATE Header   │  <-- 8 bytes
	* │- Length                  │
	* │- Revision                │
	* │- CertificateType         │
	* ├──────────────────────────┤
	* │Certificate[Length - 8]   │  <-- Len - 8
	* │(PKCS#7 SignedData for    │
	* │type 0x0002)              │
	* ├──────────────────────────┤
	* │ Padding (8-byte aligned) │
	* ├──────────────────────────┤
	* │ Next WIN_CERTIFICATE ... │
	* └──────────────────────────┘
	*/

	CUINT64 HeaderSize = offsetof(WIN_CERTIFICATE, Certificate);

	while ((Cur + HeaderSize) <= End)
	{
		if (!Image::IsRangeInBounds(Cur, HeaderSize, ImageSize))
		{
			return EFI_COMPROMISED_DATA;
		}

		PCWIN_CERTIFICATE Cert = reinterpret_cast<PCWIN_CERTIFICATE>(Base + Cur);

		CUINT32 Len = Cert->Length;

		// Length includes header and payload.
		if (Len < HeaderSize)
		{
			return EFI_COMPROMISED_DATA;
		}

		if ((Cur + Len) > End || !Image::IsRangeInBounds(Cur, Len, ImageSize))
		{
			return EFI_COMPROMISED_DATA;
		}

		// For Authenticode, PKCS#7 SignedData is required.
		if (Cert->CertificateType == gWinCertTypePkcsSignedData)
		{
			View.Base = const_cast<PUINT8>(Base + Cur);
			View.TotalSize = Len;
			View.Revision = Cert->Revision;
			View.CertType = Cert->CertificateType;
			View.Data = View.Base + HeaderSize;
			View.DataSize = Len - static_cast<UINT32>(HeaderSize);
			View.Present = true;

			return EFI_SUCCESS;
		}

		Cur += AlignUp8(Len);
	}

	return EFI_NOT_FOUND;
}