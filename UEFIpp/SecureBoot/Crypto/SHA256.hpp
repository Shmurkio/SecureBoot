#pragma once

#include "../../Uefi/Uefi.hpp"

namespace SHA256
{
	typedef struct _SHA256_CTX
	{
		UINT32 State[8];
		UINT64 BitLen;
		UINT8 Buffer[64];
		UINT32 BufferLen;
	} SHA256_CTX, *PSHA256_CTX;

	using CSHA256_CTX = const SHA256_CTX;
	using PCSHA256_CTX = const SHA256_CTX*;

	EFI_STATUS
	Init(
		OUT SHA256_CTX& Ctx
	);

	EFI_STATUS
	Update(
		IN OUT SHA256_CTX& Ctx,
		IN PCVOID Data,
		IN UINT64 Size
	);

	EFI_STATUS
	Finalize(
		IN OUT SHA256_CTX& Ctx,
		OUT UINT8 Digest[32]
	);

	EFI_STATUS
	Compute(
		IN PCVOID Buffer,
		IN CUINT64 BufferLength,
		OUT UINT8 Digest[32]
	);

	EFI_STATUS
	HashAuthenticode(
		IN PCVOID ImageBase,
		IN CUINT64 ImageSize,
		IN CUINT64 CertOff,
		IN CUINT64 CertSize,
		OUT UINT8 Digest[32]
	);
}