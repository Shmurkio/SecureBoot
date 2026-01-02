#include "Image.hpp"
#include "../../Uefi/Serial/Serial.hpp"
#include "../Crypto/PKCS7.hpp"
#include "../Crypto/SHA256.hpp"

CBOOLEAN
Image::IsRangeInBounds(
	IN CUINT64 Offset,
	IN CUINT64 Size,
	IN CUINT64 Total
)
{
	if (Offset > Total)
	{
		return false;
	}

	if (Size > Total)
	{
		return false;
	}

	if (Offset + Size < Offset)
	{
		return false;
	}

	return (Offset + Size) <= Total;
}

EFI_STATUS
Image::GetNtHeaders64(
	IN PCVOID ImageBase,
	IN CUINT64 ImageSize,
	OUT EFI_IMAGE_NT_HEADERS64*& Nt
)
{
	Nt = nullptr;

	if (!ImageBase || !ImageSize)
	{
		return EFI_INVALID_PARAMETER;
	}

	if (!ImageBase || ImageSize < sizeof(EFI_IMAGE_DOS_HEADER))
	{
		return EFI_INVALID_PARAMETER;
	}

	const EFI_IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<const EFI_IMAGE_DOS_HEADER*>(ImageBase);

	if (DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE)
	{
		return EFI_UNSUPPORTED;
	}

	if (!IsRangeInBounds(DosHeader->e_lfanew, sizeof(EFI_IMAGE_NT_HEADERS64), ImageSize))
	{
		return EFI_COMPROMISED_DATA;
	}

	const EFI_IMAGE_NT_HEADERS64* NtHeaders = reinterpret_cast<const EFI_IMAGE_NT_HEADERS64*>(reinterpret_cast<PCUINT8>(ImageBase) + DosHeader->e_lfanew);

	if (NtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
	{
		return EFI_UNSUPPORTED;
	}

	if (NtHeaders->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return EFI_UNSUPPORTED;
	}

	CUINT64 SectionOffset = DosHeader->e_lfanew + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER) + NtHeaders->FileHeader.SizeOfOptionalHeader;
	CUINT64 SectionBytes = NtHeaders->FileHeader.NumberOfSections * sizeof(EFI_IMAGE_SECTION_HEADER);

	if (!IsRangeInBounds(SectionOffset, SectionBytes, ImageSize))
	{
		return EFI_COMPROMISED_DATA;
	}

	Nt = const_cast<EFI_IMAGE_NT_HEADERS64*>(NtHeaders);

	return EFI_SUCCESS;
}

EFI_STATUS
Image::Validate(
	IN PCVOID ImageBase,
	IN CUINT64 ImageSize
)
{
	if (!ImageBase || !ImageSize)
	{
		return EFI_INVALID_PARAMETER;
	}

	PKCS7::WIN_CERT_VIEW View = { 0 };
	EFI_STATUS Status = PKCS7::GetCert(ImageBase, ImageSize, View);

	if (EfiError(Status))
	{
		Serial::Out << "[+] Failed to get PKCS#7 certificate: 0x" << Serial::Upper << Serial::Hex << Status << Serial::Dec << Serial::Endl;
		return Status;
	}

	Serial::Out << "[+] PKCS#7 certificate:" << Serial::Endl
		<< "    Base: 0x" << Serial::Upper << Serial::Hex << View.Base << Serial::Dec << Serial::Endl
		<< "    Total size: " << View.TotalSize << Serial::Endl
		<< "    Revision: " << View.Revision << Serial::Endl
		<< "    Cert type: " << View.CertType << Serial::Endl
		<< "    Data: 0x" << Serial::Upper << Serial::Hex << View.Data << Serial::Dec << Serial::Endl
		<< "    Data size: " << View.DataSize << Serial::Endl
		<< "    Present: " << View.Present << Serial::Endl;

	CUINT64 CertOff = View.Base - reinterpret_cast<PCUINT8>(ImageBase);
	CUINT64 CertSize = View.TotalSize;

	UINT8 Digest[32] = { 0 };
	Status = SHA256::HashAuthenticode(ImageBase, ImageSize, CertOff, CertSize, Digest);

	if (EfiError(Status))
	{
		Serial::Out << "[+] Failed to hash authenticode: 0x" << Serial::Upper << Serial::Hex << Status << Serial::Dec << Serial::Endl;
		return Status;
	}

	Serial::Out << "[+] Authenticode SHA-256: ";

	for (UINT32 i = 0; i < 32; ++i)
	{
		UINT8 Byte = Digest[i];

		Serial::Out << Serial::Hex << Serial::Upper << ((Byte >> 4) & 0xF);
		Serial::Out << Serial::Hex << Serial::Upper << (Byte & 0xF);
	}

	Serial::Out << Serial::Dec << Serial::Endl;

	return EFI_SUCCESS;
}