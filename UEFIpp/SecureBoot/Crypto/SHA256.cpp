#include "SHA256.hpp"
#include "../Image/Image.hpp"

// First 32 bits of the fractional parts of the cube roots of the first 64 primes.
static constexpr UINT32 gSha256RoundConstants[64] =
{
	0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
	0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
	0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
	0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U, 0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
	0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U, 0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
	0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
	0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
	0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U, 0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
};

static
inline
VOID
CopyBytes(
	IN PUINT8 Dst,
	IN PCUINT8 Src,
	IN CUINT64 Count
)
{
	for (UINT64 i = 0; i < Count; ++i)
	{
		Dst[i] = Src[i];
	}
}

static
inline
CUINT32
RotateRightBits32(
	IN CUINT32 Value,
	IN CUINT32 RotationCount
)
{
	return (Value >> RotationCount) | (Value << (32U - RotationCount));
}

static
inline
CUINT32
ChooseBits32(
	IN CUINT32 ControlBits,
	IN CUINT32 IfControlBitIsOne,
	IN CUINT32 IfControlBitIsZero
)
{
	return (ControlBits & IfControlBitIsOne) ^ (~ControlBits & IfControlBitIsZero);
}

static
inline
CUINT32
MajorityBits32(
	IN CUINT32 A,
	IN CUINT32 B,
	IN CUINT32 C
)
{
	return (A & B) ^ (A & C) ^ (B & C);
}

static
inline
CUINT32
BigSigma0(
	IN CUINT32 Value
)
{
	return RotateRightBits32(Value, 2) ^ RotateRightBits32(Value, 13) ^ RotateRightBits32(Value, 22);
}

static
inline
CUINT32
BigSigma1(
	IN CUINT32 Value
)
{
	return RotateRightBits32(Value, 6) ^ RotateRightBits32(Value, 11) ^ RotateRightBits32(Value, 25);
}

static
inline
CUINT32
SmallSigma0(
	IN CUINT32 Value
)
{
	return RotateRightBits32(Value, 7) ^ RotateRightBits32(Value, 18) ^ (Value >> 3);
}

static
inline
CUINT32
SmallSigma1(
	IN CUINT32 Value
)
{
	return RotateRightBits32(Value, 17) ^ RotateRightBits32(Value, 19) ^ (Value >> 10);
}

static
inline
CUINT32
LoadBigEndianU32(
	IN PCUINT8 Bytes
)
{
	return ((static_cast<UINT32>(Bytes[0]) << 24) | (static_cast<UINT32>(Bytes[1]) << 16) | (static_cast<UINT32>(Bytes[2]) << 8) | static_cast<UINT32>(Bytes[3]));
}

static
inline
VOID
StoreBigEndianU32(
	OUT PUINT8 Bytes,
	IN CUINT32 Value
)
{
	Bytes[0] = static_cast<UINT8>(Value >> 24);
	Bytes[1] = static_cast<UINT8>(Value >> 16);
	Bytes[2] = static_cast<UINT8>(Value >> 8);
	Bytes[3] = static_cast<UINT8>(Value);
}

static
inline
VOID
StoreBigEndianU64(
	OUT PUINT8 Bytes,
	IN CUINT64 Value
)
{
	Bytes[0] = static_cast<UINT8>(Value >> 56);
	Bytes[1] = static_cast<UINT8>(Value >> 48);
	Bytes[2] = static_cast<UINT8>(Value >> 40);
	Bytes[3] = static_cast<UINT8>(Value >> 32);
	Bytes[4] = static_cast<UINT8>(Value >> 24);
	Bytes[5] = static_cast<UINT8>(Value >> 16);
	Bytes[6] = static_cast<UINT8>(Value >> 8);
	Bytes[7] = static_cast<UINT8>(Value);
}

static
VOID
ProcessOneBlock(
	IN OUT SHA256::SHA256_CTX& Ctx,
	IN PCUINT8 Bytes
)
{
	UINT32 MessageScheduleWords[64] = { 0 };

	for (UINT32 i = 0; i < 16; ++i)
	{
		MessageScheduleWords[i] = LoadBigEndianU32(Bytes + (i * 4));
	}

	for (UINT32 i = 16; i < 64; ++i)
	{
		CUINT32 Sigma1 = SmallSigma1(MessageScheduleWords[i - 2]);
		CUINT32 Sigma0 = SmallSigma0(MessageScheduleWords[i - 15]);
		MessageScheduleWords[i] = Sigma1 + MessageScheduleWords[i - 7] + Sigma0 + MessageScheduleWords[i - 16];
	}

	UINT32 WorkingA = Ctx.State[0];
	UINT32 WorkingB = Ctx.State[1];
	UINT32 WorkingC = Ctx.State[2];
	UINT32 WorkingD = Ctx.State[3];
	UINT32 WorkingE = Ctx.State[4];
	UINT32 WorkingF = Ctx.State[5];
	UINT32 WorkingG = Ctx.State[6];
	UINT32 WorkingH = Ctx.State[7];

	for (UINT32 i = 0; i < 64; ++i)
	{
		CUINT32 Upper = WorkingH + BigSigma1(WorkingE) + ChooseBits32(WorkingE, WorkingF, WorkingG) + gSha256RoundConstants[i] + MessageScheduleWords[i];
		CUINT32 Lower = BigSigma0(WorkingA) + MajorityBits32(WorkingA, WorkingB, WorkingC);

		WorkingH = WorkingG;
		WorkingG = WorkingF;
		WorkingF = WorkingE;
		WorkingE = WorkingD + Upper;
		WorkingD = WorkingC;
		WorkingC = WorkingB;
		WorkingB = WorkingA;
		WorkingA = Upper + Lower;
	}

	Ctx.State[0] += WorkingA;
	Ctx.State[1] += WorkingB;
	Ctx.State[2] += WorkingC;
	Ctx.State[3] += WorkingD;
	Ctx.State[4] += WorkingE;
	Ctx.State[5] += WorkingF;
	Ctx.State[6] += WorkingG;
	Ctx.State[7] += WorkingH;
}

EFI_STATUS
SHA256::Init(
	OUT SHA256_CTX& Ctx
)
{
	Ctx.State[0] = 0x6A09E667U;
	Ctx.State[1] = 0xBB67AE85U;
	Ctx.State[2] = 0x3C6EF372U;
	Ctx.State[3] = 0xA54FF53AU;
	Ctx.State[4] = 0x510E527FU;
	Ctx.State[5] = 0x9B05688CU;
	Ctx.State[6] = 0x1F83D9ABU;
	Ctx.State[7] = 0x5BE0CD19U;

	Ctx.BitLen = 0;
	Ctx.BufferLen = 0;

	return EFI_SUCCESS;
}

EFI_STATUS
SHA256::Update(
	IN OUT SHA256_CTX& Ctx,
	IN PCVOID Data,
	IN UINT64 Size
)
{
	if (!Data && Size)
	{
		return EFI_INVALID_PARAMETER;
	}

	PCUINT8 Input = static_cast<PCUINT8>(Data);

	if ((Size >> 61) != 0)
	{
		return EFI_INVALID_PARAMETER;
	}

	CUINT64 AddBits = (Size << 3);

	if (Ctx.BitLen + AddBits < Ctx.BitLen)
	{
		return EFI_INVALID_PARAMETER;
	}

	Ctx.BitLen += AddBits;

	UINT64 Offset = 0;

	if (Ctx.BufferLen)
	{
		CUINT64 NeededBytes = 64 - Ctx.BufferLen;
		CUINT64 BytesToCopy = (Size < NeededBytes) ? Size : NeededBytes;

		CopyBytes(Ctx.Buffer + Ctx.BufferLen, Input + Offset, BytesToCopy);
		Ctx.BufferLen += static_cast<UINT32>(BytesToCopy);
		Offset += BytesToCopy;

		if (Ctx.BufferLen == 64)
		{
			ProcessOneBlock(Ctx, Ctx.Buffer);
			Ctx.BufferLen = 0;
		}
	}

	while (Offset + 64 <= Size)
	{
		ProcessOneBlock(Ctx, Input + Offset);
		Offset += 64;
	}

	CUINT64 RemainingBytes = Size - Offset;

	if (RemainingBytes)
	{
		CopyBytes(Ctx.Buffer, Input + Offset, RemainingBytes);
		Ctx.BufferLen = static_cast<UINT32>(RemainingBytes);
	}

	return EFI_SUCCESS;
}

EFI_STATUS
SHA256::Finalize(
	IN OUT SHA256_CTX& Ctx,
	OUT UINT8 Digest[32]
)
{
	if (!Digest)
	{
		return EFI_INVALID_PARAMETER;
	}

	CUINT64 OriginalBitLen = Ctx.BitLen;

	UINT8 PaddingBytes[64] = { 0 };
	PaddingBytes[0] = 0x80;

	CUINT32 BlockRemainder = Ctx.BufferLen % 64U;
	CUINT32 PaddingByteCount = (BlockRemainder < 56U) ? (56U - BlockRemainder) : (120U - BlockRemainder);

	EFI_STATUS Status = Update(Ctx, PaddingBytes, PaddingByteCount);

	if (EfiError(Status))
	{
		return Status;
	}

	UINT8 MsgLen[8] = { 0 };
	StoreBigEndianU64(MsgLen, OriginalBitLen);

	Status = Update(Ctx, MsgLen, sizeof(MsgLen));

	if (EfiError(Status))
	{
		return Status;
	}

	for (UINT32 i = 0; i < 8; ++i)
	{
		StoreBigEndianU32(Digest + (i * 4), Ctx.State[i]);
	}

	return EFI_SUCCESS;
}

EFI_STATUS
SHA256::Compute(
	IN PCVOID Buffer,
	IN CUINT64 BufferLength,
	OUT UINT8 Digest[32]
)
{
	if (!Digest || (!Buffer && BufferLength))
	{
		return EFI_INVALID_PARAMETER;
	}

	SHA256_CTX Ctx = { 0 };
	EFI_STATUS Status = Init(Ctx);

	if (EfiError(Status))
	{
		return Status;
	}

	Status = Update(Ctx, Buffer, BufferLength);

	if (EfiError(Status))
	{
		return Status;
	}

	return Finalize(Ctx, Digest);
}

static
EFI_STATUS
HashUpdateSkipRange(
	IN OUT SHA256::SHA256_CTX& Ctx,
	IN PCUINT8 Base,
	IN CUINT64 TotalSize,
	IN CUINT64 Off,
	IN CUINT64 Size,
	IN CUINT64 SkipOff,
	IN CUINT64 SkipSize
)
{
	if (!Size)
	{
		return EFI_SUCCESS;
	}

	if (!Image::IsRangeInBounds(Off, Size, TotalSize))
	{
		return EFI_COMPROMISED_DATA;
	}

	if (!SkipSize)
	{
		return SHA256::Update(Ctx, Base + Off, Size);
	}

	if (!Image::IsRangeInBounds(SkipOff, SkipSize, TotalSize))
	{
		return EFI_COMPROMISED_DATA;
	}

	CUINT64 End = Off + Size;
	CUINT64 SkipEnd = SkipOff + SkipSize;

	if (End <= SkipOff || Off >= SkipEnd)
	{
		return SHA256::Update(Ctx, Base + Off, Size);
	}

	if (Off < SkipOff)
	{
		CUINT64 PartSize = SkipOff - Off;
		EFI_STATUS Status = SHA256::Update(Ctx, Base + Off, PartSize);

		if (EfiError(Status))
		{
			return Status;
		}
	}

	if (End > SkipEnd)
	{
		CUINT64 PartOff = SkipEnd;
		CUINT64 PartSize = End - SkipEnd;

		return SHA256::Update(Ctx, Base + PartOff, PartSize);
	}

	return EFI_SUCCESS;
}

EFI_STATUS
SHA256::HashAuthenticode(
	IN PCVOID ImageBase,
	IN CUINT64 ImageSize,
	IN CUINT64 CertOff,
	IN CUINT64 CertSize,
	OUT UINT8 Digest[32]
)
{
	if (!ImageBase || !ImageSize || !Digest)
	{
		return EFI_INVALID_PARAMETER;
	}

	if (CertSize)
	{
		if (!Image::IsRangeInBounds(CertOff, CertSize, ImageSize))
		{
			return EFI_COMPROMISED_DATA;
		}
	}

	EFI_IMAGE_NT_HEADERS64* NtHeaders64 = nullptr;
	EFI_STATUS Status = Image::GetNtHeaders64(ImageBase, ImageSize, NtHeaders64);

	if (EfiError(Status))
	{
		return Status;
	}

	PCUINT8 Base = reinterpret_cast<PCUINT8>(ImageBase);
	const EFI_IMAGE_OPTIONAL_HEADER64& Opt = NtHeaders64->OptionalHeader;

	SHA256::SHA256_CTX HashCtx = { 0 };
	Status = SHA256::Init(HashCtx);

	if (EfiError(Status))
	{
		return Status;
	}

	UINT64 SizeOfHeaders = static_cast<UINT64>(Opt.SizeOfHeaders);

	if (!SizeOfHeaders || SizeOfHeaders > ImageSize)
	{
		SizeOfHeaders = ImageSize;
	}

	CUINT64 NtOff = reinterpret_cast<PCUINT8>(NtHeaders64) - Base;
	CUINT64 ChecksumOff = NtOff + offsetof(EFI_IMAGE_NT_HEADERS64, OptionalHeader) + offsetof(EFI_IMAGE_OPTIONAL_HEADER64, CheckSum);
	CUINT64 SecDirEntryOff = NtOff + offsetof(EFI_IMAGE_NT_HEADERS64, OptionalHeader) + offsetof(EFI_IMAGE_OPTIONAL_HEADER64, DataDirectory) + (EFI_IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(EFI_IMAGE_DATA_DIRECTORY));

	if (!Image::IsRangeInBounds(ChecksumOff, sizeof(UINT32), ImageSize) || !Image::IsRangeInBounds(SecDirEntryOff, sizeof(EFI_IMAGE_DATA_DIRECTORY), ImageSize))
	{
		return EFI_COMPROMISED_DATA;
	}

	if ((ChecksumOff + sizeof(UINT32)) > SizeOfHeaders)
	{
		return EFI_COMPROMISED_DATA;
	}

	if ((SecDirEntryOff + sizeof(EFI_IMAGE_DATA_DIRECTORY)) > SizeOfHeaders)
	{
		return EFI_COMPROMISED_DATA;
	}

	Status = HashUpdateSkipRange(HashCtx, Base, ImageSize, 0, ChecksumOff, CertOff, CertSize);

	if (EfiError(Status))
	{
		return Status;
	}

	{
		CUINT32 Zero = 0;
		Status = SHA256::Update(HashCtx, &Zero, sizeof(Zero));

		if (EfiError(Status))
		{
			return Status;
		}
	}

	CUINT64 AfterChecksum = ChecksumOff + sizeof(UINT32);

	if (SecDirEntryOff < AfterChecksum)
	{
		return EFI_COMPROMISED_DATA;
	}

	Status = HashUpdateSkipRange(HashCtx, Base, ImageSize, AfterChecksum, SecDirEntryOff - AfterChecksum, CertOff, CertSize);

	if (EfiError(Status))
	{
		return Status;
	}

	{
		EFI_IMAGE_DATA_DIRECTORY ZeroDir = { 0 };
		Status = SHA256::Update(HashCtx, &ZeroDir, sizeof(ZeroDir));

		if (EfiError(Status))
		{
			return Status;
		}
	}

	CUINT64 AfterSecDir = SecDirEntryOff + sizeof(EFI_IMAGE_DATA_DIRECTORY);

	if (AfterSecDir > SizeOfHeaders)
	{
		return EFI_COMPROMISED_DATA;
	}

	Status = HashUpdateSkipRange(HashCtx, Base, ImageSize, AfterSecDir, SizeOfHeaders - AfterSecDir, CertOff, CertSize);

	if (EfiError(Status))
	{
		return Status;
	}

	const EFI_IMAGE_SECTION_HEADER* FirstSection = reinterpret_cast<const EFI_IMAGE_SECTION_HEADER*>(reinterpret_cast<PCUINT8>(&NtHeaders64->OptionalHeader) + NtHeaders64->FileHeader.SizeOfOptionalHeader);

	CUINT16 SectionCount = NtHeaders64->FileHeader.NumberOfSections;

	CUINT64 SecHdrOff = static_cast<UINT64>(reinterpret_cast<PCUINT8>(FirstSection) - Base);
	CUINT64 SecHdrSize = static_cast<UINT64>(SectionCount) * sizeof(EFI_IMAGE_SECTION_HEADER);

	if (!Image::IsRangeInBounds(SecHdrOff, SecHdrSize, ImageSize))
	{
		return EFI_COMPROMISED_DATA;
	}

	UINT16 Idx[96] = { 0 };

	if (SectionCount > (sizeof(Idx) / sizeof(Idx[0])))
	{
		return EFI_COMPROMISED_DATA;
	}

	for (UINT16 i = 0; i < SectionCount; ++i)
	{
		Idx[i] = i;
	}

	for (UINT16 i = 0; i < SectionCount; ++i)
	{
		UINT16 Min = i;

		for (UINT16 j = i + 1; j < SectionCount; ++j)
		{
			if (FirstSection[Idx[j]].PointerToRawData < FirstSection[Idx[Min]].PointerToRawData)
			{
				Min = j;
			}
		}

		CUINT16 Tmp = Idx[i];
		Idx[i] = Idx[Min];
		Idx[Min] = Tmp;
	}

	for (UINT16 i = 0; i < SectionCount; ++i)
	{
		const EFI_IMAGE_SECTION_HEADER& Sh = FirstSection[Idx[i]];

		CUINT64 RawOff = static_cast<UINT64>(Sh.PointerToRawData);
		CUINT64 RawSize = static_cast<UINT64>(Sh.SizeOfRawData);

		if (!RawSize)
		{
			continue;
		}

		if (!Image::IsRangeInBounds(RawOff, RawSize, ImageSize))
		{
			return EFI_COMPROMISED_DATA;
		}

		Status = HashUpdateSkipRange(HashCtx, Base, ImageSize, RawOff, RawSize, CertOff, CertSize);

		if (EfiError(Status))
		{
			return Status;
		}
	}

	Status = SHA256::Finalize(HashCtx, Digest);

	if (EfiError(Status))
	{
		return Status;
	}

	return EFI_SUCCESS;
}