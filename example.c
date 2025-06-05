#include "PolarCodes_HASCL.h"
#include "BitHelperFunctions.h"
#include <stdlib.h>
#include <stdio.h>

/*
	If you want to build/run this example, uncomment define "IgnoreTomCrypt" in PolarCodes_HASCL.c
*/

int main()
{
	uint32_t const N = 16;
	uint32_t const K = 8;
	uint8_t const NumberOfDecoders = 4;
	uint32_t const NBytes = N / 8;

	uint8_t FrozenBitMask[] = {0x6A, 0x96}; //001101010 10010110
	uint32_t const FrozenBitMaskLength = NBytes;

	uint8_t const Message = 0x69;

	PLC_Init(N, K, NumberOfDecoders);

	uint8_t const PlainLength = NBytes;
	uint8_t* Plain = calloc(PlainLength, sizeof(uint8_t));

	//assign message bits (TODO: add CRC / hash to be able to pick correct decoded word from decoder output)
	for(int32_t i = N-1, MessagePosition = K-1; i >= 0 && MessagePosition >= 0; i--)
	{
		if(GetBitAtIndex(FrozenBitMask, i)) //-> bit is not frozen
		{
			SetBitAtIndex(Plain, i, GetBitAtIndex(&Message, MessagePosition));
			MessagePosition++;
		}
	}

	printf("Plaintext: ");
	for(uint32_t i = 0; i < NBytes; i++)
	{
		printf("0x%02X ", Plain[i]);
	}
	printf("\n");

	// --- encode --- //
	uint8_t* EncodedWord = PLC_Encode(Plain, PlainLength);
	free(Plain); Plain = 0;

	if(EncodedWord == 0) return -1; //encoding failed

	printf("Encoded word: ");
	for(uint32_t i = 0; i < NBytes; i++)
	{
		printf("0x%02X ", EncodedWord[i]);
	}
	printf("\n");

	//apply noise, etc...

	// --- decode --- //
	uint8_t** DecodedList = PLC_SCL_Decode(EncodedWord, NBytes, FrozenBitMask, FrozenBitMaskLength);
	free(EncodedWord); EncodedWord = 0;

	if(DecodedList == 0) return -2; //decoding failed

	//decide on correct decoder output (via CRC or hash, ...)
	printf("Decoder outputs:\n");
	for(uint8_t i = 0; i < NumberOfDecoders; i++)
	{
		//TODO

		printf("%u: ", i);
		for(uint32_t j = 0; j < NBytes; j++)
		{
			printf("0x%02X ", DecodedList[i][j]);
		}
		printf("\n");
	}

	//extract message bits
	//TODO
}