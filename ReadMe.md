# Polar Code encoder + decoder

This is a Polar Code encoder + successive cancellation list decoder optimized for memory usage and is based on the tutorial series ["LDPC and Polar Codes in 5G Standard" by NPTEL-NOC IITM](https://youtube.com/playlist?list=PLyqSpQzTE6M81HJ26ZaNv0V3ROBrcv-Kc).

The initial use case was the reconstruction of a key from an SRAM fingerprint on a microcontroller.
Due to this, the encoder removes all values at frozen positions!!

This code is distributed as is. Use at your own risk.

## Notes

`FrozenBitMask` - frozen bits are indicated by the value 0, non-frozen bits are 1.

This implementation (especially `PLC_Reproduce`) makes use of Tom Crypt's SHA1 hashing function.
Either include [Tom Crypt](https://github.com/libtom/libtomcrypt) into your project, or remove code (when `PLC_Reproduce` is not used).
