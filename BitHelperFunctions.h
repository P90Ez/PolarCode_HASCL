#ifndef BITHELPERFUNCTIONS_H
#define BITHELPERFUNCTIONS_H

#include <stdint.h>

/// @brief Returns the bit at the given index
/// @return Bit value at LSB
uint8_t GetBitAtIndex(uint8_t const* const Buffer, uint32_t const Index);

/// @brief Sets the bit value in the buffer at the given index.
void SetBitAtIndex(uint8_t* const Buffer, uint32_t const Index, uint8_t const BitValue);

/// @brief XORs all bits of Src1 with Src2 and writes them into Dst.
void XOR(uint8_t const*const Src1, uint8_t const*const Src2, uint8_t* Dst, uint32_t const NumberOfBits);

/// @brief XORs all bits of Src1 with Src2 and writes them into a newly allocated buffer (free it yourself!)
/// @return New buffer of size NumberOfBits.
uint8_t* XORMalloc(uint8_t const*const Src1, uint8_t const*const Src2, uint32_t const NumberOfBits);

/// @brief Copies bits from StartIndex to EndIndex into a new buffer.
/// @return New buffer of size (EndBitIndex - StartBitIndex) / 8 byte, containing specified bit range.
uint8_t* CopyBitRange(uint8_t const*const Buffer, uint32_t const BufferLengthByte, uint32_t const StartBitIndex, uint32_t const EndBitIndex);

#endif