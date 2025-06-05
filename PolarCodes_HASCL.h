#ifndef PLC_HASCL_H
#define PLC_HASCL_H
#include <stdint.h>

/*  This is a Polar Code encoder + successive cancellation list decoder optimized for memory usage 
*   and is based on the tutorial series "LDPC and Polar Codes in 5G Standard" by NPTEL-NOC IITM.
*   https://youtube.com/playlist?list=PLyqSpQzTE6M81HJ26ZaNv0V3ROBrcv-Kc
*   The initial use case was the reconstruction of a key from an SRAM fingerprint on a microcontroller.
*   
*   This code is distributed as is. Use at your own risk.
*   
*   Notes:
*   FrozenBitMask - frozen bits are indicated by the value 0, non-frozen bits are 1.
*   This implementation (especially PLC_Reproduce) makes use of Tom Crypt's SHA1 hashing function.
*   Either include Tom Crypt into your project, or remove code (when PLC_Reproduce is not used).
*/

#define OutputKeyLengthByte 20

/// @brief Initializes this module.
/// @param N Word length (in bits).
/// @param K Codeword length / raw key length (in bits).
/// @param NumberOfDecoders Number of decoders (for list decoding).
void PLC_Init(uint16_t const N, uint16_t const K, uint8_t const NumberOfDecoders);

/// @brief Tries to reconstruct the key from the given SRAM PUF fingerprint.
/// @param Fingerprint SRAM fingerprint.
/// @param FingerprintLength Length of fingerprint (in bytes).
/// @param HelperData Helper data - values of frozen bits.
/// @param HelperDataSize Helper data length (in bytes).
/// @param FrozenBitMask Mask, which indicates which bits are frozen.
/// @param FrozenBitMaskLength Mask length (in bytes).
/// @param ValidationHash Hash to determine the correct output of the multiple possibilities.
/// @param ValidationHashLength Length of hash (in bytes).
/// @return Reproduced key, with length OutputKeyLengthByte, on success, nullptr otherwise.
uint8_t* PLC_Reproduce(uint8_t const*const Fingerprint, uint16_t const _FingerprintLength, 
                       uint8_t const*const HelperData, uint16_t const HelperDataSize,
                       uint8_t const*const FrozenBitMask, uint16_t const _FrozenBitMaskLength,
                       uint8_t const*const ValidationHash, uint16_t const _ValidationHashLength);

/// @brief Encodes a given plain text. The frozen bit mask (reliability sequence) has to be applied beforehand.
/// @param Input Plain text to encode. Only first N bits are used.
/// @param InputLength Length of input (in bytes).
/// @return Encoded word, with length N. Nullptr on error.
uint8_t* PLC_Encode(uint8_t const*const Input, uint16_t const InputLength);
                   
/// @brief Successive cancellation list decoder. Decodes a given encoded word.
/// @param Input Encoded word. Only first N bits are used.
/// @param InputLength Length of input (in bytes).
/// @param FrozenBitMask Mask, which indicates which bits are frozen (-> usually indicated by a reliability sequence).
/// @param FrozenBitMaskLength Mask length (in bytes).
/// @return A list (of length NumberOfDecoders) of possible decoded plain texts (with length N). Nullptr on error.
uint8_t **PLC_SCL_Decode(uint8_t const*const Input, uint16_t const InputLength, 
                         uint8_t const*const FrozenBitMask, uint16_t const FrozenBitMaskLength);

#endif