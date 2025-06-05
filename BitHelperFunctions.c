#include "BitHelperFunctions.h"
#include <stdlib.h>
#include <math.h>

uint8_t GetBitAtIndex(uint8_t const*const Buffer, uint32_t const Index)
{
	if (Buffer == 0) return 0;

	uint32_t const ArrayIndex = Index / 8;
	uint8_t const BitIndex = Index % 8;

	uint8_t byte = *(Buffer + ArrayIndex);
	return (byte >> BitIndex) & 0x01;
}

void SetBitAtIndex(uint8_t * const Buffer, uint32_t const Index, uint8_t const BitValue)
{
	if (Buffer == 0) return;

	uint32_t const ArrayIndex = Index / 8;
	uint8_t const BitIndex = Index % 8;

	*(Buffer + ArrayIndex) &= ~(0x01 << BitIndex);
	*(Buffer + ArrayIndex) |= (BitValue & 0x01) << BitIndex;
}

void XOR(uint8_t const*const Src1, uint8_t const*const Src2, uint8_t* Dst, uint32_t const NumberOfBits)
{
	if(Src1 == 0 || Src2 == 0 || Dst == 0 || NumberOfBits == 0) return;
	
	uint32_t const NumberOfBytes = (uint32_t)floor(NumberOfBits / 8.0);

	for(int i = 0; i < NumberOfBytes; i++)
	{
		Dst[i] = Src1[i] ^ Src2[i];
	} 

	for(int i = 0; i < (NumberOfBits % 8); i++)
	{
		SetBitAtIndex((Dst+NumberOfBytes), i, GetBitAtIndex((Src1 + NumberOfBytes), i) ^ GetBitAtIndex((Src2 + NumberOfBytes), i));
	}
}

uint8_t *XORMalloc(uint8_t const *const Src1, uint8_t const *const Src2,
                   uint32_t const NumberOfBits)
{
    if(Src1 == 0 || Src2 == 0 || NumberOfBits == 0) return 0;
	uint32_t const ByteSize = ceil(NumberOfBits / 8.0);
    
    uint8_t* Dst = calloc(ByteSize, sizeof(uint8_t));
	if(Dst == 0) return 0;

    XOR(Src1, Src2, Dst, NumberOfBits);
    return Dst;
}

uint8_t* CopyBitRange(uint8_t const*const Buffer, uint32_t const BufferLengthByte, uint32_t const StartBitIndex, uint32_t const EndBitIndex)
{
	if(Buffer == 0 || EndBitIndex > (BufferLengthByte * 8)) return 0;

	uint32_t const BitLength = EndBitIndex - StartBitIndex;
	uint32_t const ByteLength = (uint32_t)ceil(BitLength / 8.0);
	uint8_t* Values = calloc(ByteLength, sizeof(uint8_t));

	for(uint32_t i = 0; i < BitLength; i++)
	{
		SetBitAtIndex(Values, i, GetBitAtIndex(Buffer, i + StartBitIndex));
	}

	return Values;
}
