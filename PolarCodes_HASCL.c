#include "PolarCodes_HASCL.h"
#include "BitHelperFunctions.h"
#include <tomcrypt.h>
#include <stdbool.h>
#include <math.h>

static uint16_t N = 1024;
#define NBytes (N/8)
#define n ((uint16_t)log2(N))
static uint16_t K = 128;
#define KBytes (K/8)
static uint8_t NumberOfDecoders = 2;

#define BPSK_t int16_t
#define Decision_t uint8_t

#define SHA1_ByteLength 20
static uint8_t* SHA1_Hash(uint8_t const*const Values, uint16_t const ByteLength)
{
	int idx, err;

	if (register_hash(&sha1_desc) == -1) return 0;
	idx = find_hash("sha1");

	uint8_t* Hash = malloc(SHA1_ByteLength);
	uint16_t OutLen = SHA1_ByteLength;
	if ((err = hash_memory(idx, Values, ByteLength, Hash, &OutLen)) != CRYPT_OK || OutLen != SHA1_ByteLength) {
		free(Hash);
		return 0;
	}

	return Hash;
}

// --- INIT --- //
void PLC_Init(uint16_t const N_, uint16_t const K_, uint8_t const _NumberOfDecoders)
{
	N = N_;
	K = K_;
	NumberOfDecoders = _NumberOfDecoders;
}

// --- REPRODUCE --- //
uint8_t *PLC_Reproduce(
	uint8_t const *const Fingerprint, uint16_t const FingerprintLength,
	uint8_t const *const HelperData, uint16_t const HelperDataSize,
	uint8_t const *const FrozenBitMask, uint16_t const FrozenBitMaskLength,
	uint8_t const *const ValidationHash, uint16_t const ValidationHashLength)
{
	if(Fingerprint == 0 || FingerprintLength < NBytes) return 0;
	if(HelperData == 0 || HelperDataSize == 0) return 0;
	if(FrozenBitMask == 0 || FrozenBitMaskLength != NBytes) return 0;
	if(ValidationHash == 0 || ValidationHashLength != SHA1_ByteLength) return 0;

	//encode
	uint8_t* CodeWord = PLC_Encode(Fingerprint, FingerprintLength, FrozenBitMask, FrozenBitMaskLength);
	if(CodeWord == 0) return 0;

	SendDebug(Fingerprint, 20);

	//apply helper data
	for(uint16_t i = 0, HDIndex = 0; i < N && (HDIndex / 8) < HelperDataSize; i++)
	{
		if(!GetBitAtIndex(FrozenBitMask, i))
		{
			SetBitAtIndex(CodeWord, i, GetBitAtIndex(HelperData, HDIndex));
			HDIndex++;
		}
	}

	//decode
	uint8_t** RecoveredFingerprints = PLC_SCL_Decode(CodeWord, NBytes, FrozenBitMask, FrozenBitMaskLength);

	free(CodeWord); CodeWord = 0;
	if(RecoveredFingerprints == 0) return 0;

	//get matching "recovered" fingerprint
	uint8_t* RecoveredFingerprint = 0;
	for(uint8_t i = 0; i < NumberOfDecoders; i++)
	{
		if(RecoveredFingerprint == 0 && RecoveredFingerprints[i] != 0)
		{
			uint8_t* HashedFingerprint = SHA1_Hash(RecoveredFingerprints[i], NBytes);

			bool Match = HashedFingerprint != 0;
			for(uint16_t j = 0; j < SHA1_ByteLength && j < ValidationHashLength && Match; j++)
			{
				Match = HashedFingerprint[j] == ValidationHash[j];
			}
			free(HashedFingerprint); HashedFingerprint = 0;

			if(Match) RecoveredFingerprint = RecoveredFingerprints[i];
			else
			{
				//not matching? free!
				free(RecoveredFingerprints[i]); 
				RecoveredFingerprints[i] = 0;
			}
		}
		else
		{
			//already found match? free!
			free(RecoveredFingerprints[i]); 
			RecoveredFingerprints[i] = 0;
		}
	}
	free(RecoveredFingerprints); RecoveredFingerprints = 0;

	if(RecoveredFingerprint == 0) return 0;

	//encode
	CodeWord = PLC_Encode(RecoveredFingerprint, NBytes, FrozenBitMask, FrozenBitMaskLength);
	free(RecoveredFingerprint); RecoveredFingerprint = 0;

	//extract raw key
	uint8_t* RawKey = calloc(KBytes, sizeof(uint8_t));
	for(uint16_t i = 0, RawKeyIndex = 0; i < N && RawKeyIndex < K; i++)
	{
		if(GetBitAtIndex(FrozenBitMask, i))
		{
			SetBitAtIndex(RawKey, RawKeyIndex, GetBitAtIndex(CodeWord, i));
			RawKeyIndex++;
		}
	}
	free(CodeWord); CodeWord = 0;

	//hash raw key
	uint8_t* Key = SHA1_Hash(RawKey, KBytes);
	free(RawKey); RawKey = 0;

	return Key;
}

// --- ENCODE --- //
uint8_t *PLC_Encode(uint8_t const *const Fingerprint,
					  uint16_t const FingerprintLength,
					  uint8_t const *const FrozenBitMask,
					  uint16_t const FrozenBitMaskLength)
{
	if(Fingerprint == 0 || FingerprintLength < NBytes) return 0;
	if(FrozenBitMask == 0 || FrozenBitMaskLength != NBytes) return 0;

	//Copy only non frozen bits into working array (frozen bits -> 0)
	uint8_t* Values = calloc(NBytes, sizeof(uint8_t));
	for(uint16_t i = 0; i < N; i++)
	{
		if(GetBitAtIndex(FrozenBitMask, i))
		{
			SetBitAtIndex(Values, i, GetBitAtIndex(Fingerprint, i));
		}
	}

	for (uint16_t m = 1; m < N; m *= 2)
	{
		for (uint16_t i = 0; i < N; i += 2 * m)
		{
			uint8_t* a = CopyBitRange(Values, NBytes, i, i + m);
			uint8_t* b = CopyBitRange(Values, NBytes, i + m, i + 2 * m);

			for (uint16_t j = 0; j < m; j++)
			{
				SetBitAtIndex(Values, i + j, GetBitAtIndex(a, j) ^ GetBitAtIndex(b, j));
				SetBitAtIndex(Values, i + m + j, GetBitAtIndex(b, j));
			}
			
			free(a);
			free(b);
		}
	}

	return Values;
}

// --- DECODE - helper functions --- //

/// @brief Min-sum approximation (often denoted as f)
static BPSK_t MinSum(BPSK_t const a, BPSK_t const b)
{
	BPSK_t sign = (a * b) > 0 ? 1 : -1;

	BPSK_t a_abs = a < 0 ? a * -1 : a;
	BPSK_t b_abs = b < 0 ? b * -1 : b;

	BPSK_t min = a_abs < b_abs ? a_abs : b_abs;

	return sign * min;
}

/// @brief Min-sum approximation (often denoted as f), for two given arrays.
static BPSK_t* MinSumArray(BPSK_t* A, BPSK_t* B, uint16_t const Length)
{
	if(A == 0 || B == 0 || Length == 0) return 0;

	BPSK_t* Values = calloc(Length, sizeof(BPSK_t));
	for(uint16_t i = 0; i < Length; i++)
	{
		Values[i] = MinSum(A[i], B[i]);
	}

	return Values;
}

/// @brief g-function in literature
static BPSK_t g(BPSK_t const a, BPSK_t const b, Decision_t const c)
{
	return b + (1 - 2 * c) * a;
}

/// @brief g-function in literature, for three given arrays.
static BPSK_t* gArray(BPSK_t const*const A, BPSK_t const*const B, Decision_t const*const C, uint16_t const Length)
{
	if(A == 0 || B == 0 || C == 0 || Length == 0) return 0;

	BPSK_t* Values = calloc(Length, sizeof(BPSK_t));
	for(uint16_t i = 0; i < Length; i++)
	{
		Values[i] = g(A[i], B[i], GetBitAtIndex(C, i));
	}

	return Values;
}

/// @brief BPSK encoding for a single bit.
static BPSK_t ToBPSK(uint8_t const Bit)
{
	return Bit ? -1 : 1; // 1 -> -1 ; 0 -> 1
}

//Node states
typedef uint8_t NodeState;
#define NS_Untouched 0
#define NS_LeftDone 1
#define NS_RightDone 2
#define NS_Done 3
#define NS_Error 4

/// @brief Gets the node state for a specified node at specified depth.
static NodeState GetNodeState(NodeState const*const NodeStates, uint16_t const Depth, uint16_t const Node)
{
	if(NodeStates == 0) return NS_Error;

	uint16_t const Position = (uint16_t)pow(2, Depth) + Node - 1;
	return NodeStates[Position];
}

/// @brief Sets the node state for a specified node at specified depth.
static void SetNodeState(NodeState *const NodeStates, uint16_t Depth, uint16_t const Node, NodeState const State)
{
	if(NodeStates == 0) return;

	uint16_t const Position = (uint16_t)pow(2, Depth) + Node - 1;
	NodeStates[Position] = State;
}

typedef struct
{
	BPSK_t** LLRs;
	Decision_t** Decisions;
	int16_t PathMetrics;
} DecoderData;

/// @brief Creates a new decoder -> allocates memory.
static DecoderData* CreateDecoder()
{
	DecoderData* Data = malloc(sizeof(DecoderData));
	Data->PathMetrics = 0;
	Data->LLRs = malloc((n + 1) * sizeof(BPSK_t*));
	Data->Decisions = malloc((n + 1) * sizeof(Decision_t*));
	for(uint16_t i = 0; i < n + 1; i++)
	{
		Data->LLRs[i] = malloc(N * sizeof(BPSK_t));
		Data->Decisions[i] = calloc(((uint16_t)ceil(N / 8.0)), sizeof(Decision_t));
	}

	return Data;
}

/// @brief Deletes a decoders -> frees memory.
static void DeleteDecoder(DecoderData* Data)
{
	if(Data == 0) return;

	for(uint16_t i = 0; i < n + 1; i++)
	{
		free(Data->LLRs[i]);
		free(Data->Decisions[i]);
	}
	free(Data->LLRs);
	free(Data->Decisions);
	free(Data);
}

/// @brief Allocates a new decoder and copies all values from given decoder.
static DecoderData* CopyDecoder(DecoderData const*const Dec1)
{
	if(Dec1 == 0) return 0;

	DecoderData* Dec2 = CreateDecoder();

	Dec2->PathMetrics = Dec1->PathMetrics;
	for(uint16_t i = 0; i < n + 1; i++)
	{
		memcpy(Dec2->LLRs[i], Dec1->LLRs[i], N * sizeof(BPSK_t));
		memcpy(Dec2->Decisions[i], Dec1->Decisions[i], ((uint16_t)ceil(N / 8.0)) * sizeof(Decision_t));
	}

	return Dec2;
}

/// @brief Gets a LLR (Log Likelihood Ratio) from the specified decoder, at depth and (node) index.
static BPSK_t GetLLR(DecoderData const*const Decoder, uint16_t const Depth, uint16_t const Index)
{
	if(Decoder == 0 || Decoder->LLRs == 0) return 0;

	return Decoder->LLRs[Depth][Index];
}

/// @brief Gets a LLR (Log Likelihood Ratio) range from the specified decoder, at depth from StartIndex to EndIndex.
static BPSK_t* GetLLRRange(DecoderData const*const Decoder, uint16_t const Depth, uint16_t const StartIndex, uint16_t const EndIndex)
{
	if(Decoder == 0 || Decoder->LLRs == 0 || EndIndex <= StartIndex) return 0;

	uint16_t const Length = EndIndex - StartIndex;
	BPSK_t* Values = malloc(Length * sizeof(BPSK_t));

	for(uint16_t i = 0; i < Length; i++)
	{
		Values[i] = GetLLR(Decoder, Depth, i + StartIndex);
	}

	return Values;
}

/// @brief Sets a LLR (Log Likelihood Ratio) range of the specified decoder, at depth from StartIndex to EndIndex.
static void SetLLRRange(DecoderData *const Decoder, uint16_t const Depth, uint16_t const StartIndex, uint16_t const EndIndex, BPSK_t const*const Values)
{
	if(Decoder == 0 || Decoder->LLRs == 0 || Values == 0 || EndIndex <= StartIndex) return;

	uint16_t const Length = EndIndex - StartIndex;
	for(uint16_t i = 0; i < Length; i++)
	{
		Decoder->LLRs[Depth][i + StartIndex] = Values[i];
	}
}

/// @brief Gets a decoders decisions for a given depth in a given range.
static Decision_t* GetDecisionsRange(DecoderData const*const Decoder, uint16_t const Depth, uint16_t const StartIndex, uint16_t const EndIndex)
{
	if(Decoder == 0 || Decoder->Decisions == 0 || EndIndex <= StartIndex) return 0;

	uint16_t const Length = EndIndex - StartIndex;
	Decision_t *const Values = calloc((uint16_t)ceil(Length / 8.0), sizeof(Decision_t));

	for(uint16_t i = 0; i < Length; i++)
	{
		SetBitAtIndex(Values, i, GetBitAtIndex(Decoder->Decisions[Depth], i + StartIndex));
	}

	return Values;
}

/// @brief Sets a decoders decision at a given depth and index.
static void SetDecision(DecoderData *const Decoder, uint16_t const Depth, uint16_t const Index, Decision_t const Decision)
{
	if(Decoder == 0 || Decoder->Decisions == 0) return;

	SetBitAtIndex(Decoder->Decisions[Depth], Index, Decision);
}

/// @brief Sets a decoders decisions at given depth in a given range.
static void SetDecisionsRange(DecoderData *const Decoder, uint16_t const Depth, uint16_t const StartIndex, uint16_t const EndIndex, Decision_t const*const Decisions)
{
	if(Decoder == 0 || Decoder->Decisions == 0 || Decisions == 0 || EndIndex <= StartIndex) return;

	uint16_t const Length = EndIndex - StartIndex;
	for(uint16_t i = 0; i < Length; i++)
	{
		SetDecision(Decoder, Depth, StartIndex + i, GetBitAtIndex(Decisions, i));
	}
}

/// @brief Adds additional metric to decoder's path metric
static void AddPathMetric(DecoderData *const Decoder, int const Metric)
{
	if(Decoder == 0) return;

	Decoder->PathMetrics += Metric;
}

typedef struct {
	uint8_t DecoderId;
	int16_t PathMetric;
	BPSK_t Decision;
} DecoderDecision;

/// @brief Compares DecoderDecisions, based on path metric.
/// @return -1 when path metric of Dec1 < Dec2; 0 when path metric of Dec1 == Dec2; 1 when path metric of Dec1 > Dec2.
int CompareDecoderDecisions(const void* _Dec1, const void* _Dec2)
{
	DecoderDecision const*const Dec1 = (DecoderDecision const*const)_Dec1;
	DecoderDecision const*const Dec2 = (DecoderDecision const*const)_Dec2;

	return Dec1->PathMetric < Dec2->PathMetric ? -1 : (Dec1->PathMetric == Dec2->PathMetric ? 0 : 1);
}

// --- DECODE --- //
uint8_t **PLC_SCL_Decode(uint8_t const *const Input, uint16_t const InputLength,
					   uint8_t const *const FrozenBitMask, uint16_t const FrozenBitMaskLength)
{
	if(Input == 0 || InputLength < NBytes) return 0;
	if(FrozenBitMask == 0 || FrozenBitMaskLength != NBytes) return 0;

	NodeState* NodeStates = calloc(((uint16_t)pow(2, n + 1) - 1), sizeof(NodeState));
	DecoderData** Decoders = malloc(NumberOfDecoders * sizeof(DecoderData*));
	for(uint8_t i = 0; i < NumberOfDecoders; i++)
	{
		Decoders[i] = 0;
	}

	uint8_t CurrentDecoders = 1;
	int Depth = 0;
	uint16_t Node = 0;
	bool Done = false;

	//create initial decoder and add input values BPSK encoded
	DecoderData* InitialDecoder = CreateDecoder();
	for(uint16_t i = 0; i < N; i++)
	{
		InitialDecoder->LLRs[Depth][i] = ToBPSK(GetBitAtIndex(Input, i));
	}
	Decoders[0] = InitialDecoder; InitialDecoder = 0;

	while(!Done)
	{
		if(Depth == n) // -> leaf node
		{
			if(!GetBitAtIndex(FrozenBitMask, Node)) // bit is frozen
			{
				for(uint8_t i = 0; i < CurrentDecoders; i++)
				{
					BPSK_t DecisionMetric = GetLLR(Decoders[i], Depth, Node);
					SetDecision(Decoders[i], Depth, Node, 0); // bit is frozen -> value is set to 0 (-> "frozen") during encoding
					if(DecisionMetric < 0) AddPathMetric(Decoders[i], abs(DecisionMetric));
				}
			}
			else // bit is not frozen
			{
				//get both possible decisions (+path metric) for each decoder
				DecoderDecision* DecoderDecisions = malloc(2 * NumberOfDecoders * sizeof(DecoderDecision));
				memset(DecoderDecisions, 0, 2 * NumberOfDecoders * sizeof(DecoderDecision));

				for(uint8_t i = 0; i < CurrentDecoders; i++)
				{
					BPSK_t const DecisionMetric = GetLLR(Decoders[i], Depth, Node);
					Decision_t const Decision = DecisionMetric < 0 ? 1 : 0;
					Decision_t const InverseDecision = DecisionMetric >= 0 ? 1 : 0;

					DecoderDecisions[i].Decision = Decision;
					DecoderDecisions[i].DecoderId = i;
					DecoderDecisions[i].PathMetric = Decoders[i]->PathMetrics;

					int16_t const CopiedPathMetric = Decoders[i]->PathMetrics + abs(DecisionMetric);
					DecoderDecisions[i + CurrentDecoders].Decision = InverseDecision;
					DecoderDecisions[i + CurrentDecoders].DecoderId = i;
					DecoderDecisions[i + CurrentDecoders].PathMetric = CopiedPathMetric;
				}

				//sort decisions by viability (-> lowest path metric)
				qsort(DecoderDecisions, CurrentDecoders * 2, sizeof(DecoderDecision), CompareDecoderDecisions);

				//update decoder array without unnecessary copying (-> less peak memory usage)
				uint8_t* DecodersVisited = calloc(CurrentDecoders, sizeof(uint8_t));
				for(int8_t i = CurrentDecoders * 2 - 1; i >= 0; i--)
				{
					uint8_t const CurrentDecoderId = DecoderDecisions[i].DecoderId;
					if(i >= NumberOfDecoders)
					{
						DecodersVisited[CurrentDecoderId]++;
						if(DecodersVisited[CurrentDecoderId] >= 2) //all instances of this decoder are outside of viable decision spectrum -> free up space
						{
							DeleteDecoder(Decoders[CurrentDecoderId]);
							Decoders[CurrentDecoderId] = 0;
							CurrentDecoders--;
						}
					}
					else
					{
						if(DecodersVisited[CurrentDecoderId] == 0) { // both instances of this decoder are inside the viable decision spectrum -> copy and set to free space
							//copy and assign values
							DecoderData* CopiedDecoder = CopyDecoder(Decoders[CurrentDecoderId]);
							SetDecision(CopiedDecoder, Depth, Node, DecoderDecisions[i].Decision);
							CopiedDecoder->PathMetrics = DecoderDecisions[i].PathMetric;

							//find free position
							int8_t FreeDecoderPosition = -1;
							for(uint8_t i = 0; i < NumberOfDecoders && FreeDecoderPosition == -1; i++)
							{
								if(Decoders[i] == 0) FreeDecoderPosition = i;
							}

							if(FreeDecoderPosition < 0) // critical error!!!!!
							{
								free(CopiedDecoder);
								free(DecoderDecisions);
								free(DecodersVisited);
								free(NodeStates);
								for(uint8_t i = 0; i < NumberOfDecoders; i++)
								{
									DeleteDecoder(Decoders[i]);
								}
								free(Decoders);
								return 0;
							}

							//add to decoders
							Decoders[FreeDecoderPosition] = CopiedDecoder;

							//increase value to indicate no further copy necessary
							DecodersVisited[CurrentDecoderId]++;
							CurrentDecoders++;
						}
						else //only 1 instance of this decoder is inside the viable decision spectrum -> assign values
						{
							SetDecision(Decoders[CurrentDecoderId], Depth, Node, DecoderDecisions[i].Decision);
							Decoders[CurrentDecoderId]->PathMetrics = DecoderDecisions[i].PathMetric;
							
							DecodersVisited[CurrentDecoderId]++;
						}
					}
				}
				
				free(DecoderDecisions);
				free(DecodersVisited);

				if(CurrentDecoders > NumberOfDecoders) // critical error!!!!!
				{
					free(NodeStates);
					for(uint8_t i = 0; i < NumberOfDecoders; i++)
					{
						DeleteDecoder(Decoders[i]);
					}
					free(Decoders);
					return 0;
				}
			}

			//next node: parent
			Node = (uint16_t)floor(Node / 2.0);
			Depth -= 1;
		}
		else // -> interior node
		{
			switch (GetNodeState(NodeStates, Depth, Node))
			{
			case NS_Untouched: // step "L" (left node)
				{
					uint16_t const NumberIncomingBeliefs = (uint16_t)pow(2, n - Depth);
					uint16_t const NumberOutgoingBeliefs = NumberIncomingBeliefs / 2;

					//next node: left child
					uint16_t const NextNode = Node * 2;
					uint16_t const ChildDepth = Depth + 1;

					for(uint8_t i = 0; i < CurrentDecoders; i++)
					{
						BPSK_t* a = GetLLRRange(Decoders[i], Depth, Node * NumberIncomingBeliefs, Node * NumberIncomingBeliefs + NumberIncomingBeliefs / 2);
						BPSK_t* b = GetLLRRange(Decoders[i], Depth, Node * NumberIncomingBeliefs + NumberIncomingBeliefs / 2, Node * NumberIncomingBeliefs + NumberIncomingBeliefs);

						BPSK_t* MinSumRay = MinSumArray(a, b, NumberIncomingBeliefs);
						SetLLRRange(Decoders[i], ChildDepth, NumberOutgoingBeliefs * NextNode, NumberOutgoingBeliefs * (NextNode + 1), MinSumRay);

						free(a);
						free(b);
						free(MinSumRay);
					}

					SetNodeState(NodeStates, Depth, Node, NS_LeftDone);
					Node = NextNode;
					Depth = ChildDepth;
				}
				break;
			case NS_LeftDone: // step "R" (right node)
				{
					uint16_t const NumberIncomingBeliefs = (int)pow(2, n - Depth);
					uint16_t const NumberOutgoingBeliefs = NumberIncomingBeliefs / 2;
					uint16_t const LeftChildNode = 2 * Node;
					uint16_t const ChildDepth = Depth + 1;

					//next node: right child
					uint16_t const NextNode = Node * 2 + 1;

					for(uint8_t i = 0; i < CurrentDecoders; i++)
					{
						BPSK_t* a = GetLLRRange(Decoders[i], Depth, Node * NumberIncomingBeliefs, Node * NumberIncomingBeliefs + NumberIncomingBeliefs / 2);
						BPSK_t* b = GetLLRRange(Decoders[i], Depth, Node * NumberIncomingBeliefs + NumberIncomingBeliefs / 2, Node * NumberIncomingBeliefs + NumberIncomingBeliefs);
						Decision_t* IncomingDecisions = GetDecisionsRange(Decoders[i], ChildDepth, NumberOutgoingBeliefs * LeftChildNode, NumberOutgoingBeliefs * LeftChildNode + NumberOutgoingBeliefs);

						BPSK_t* gRay = gArray(a, b, IncomingDecisions, NumberIncomingBeliefs);
						SetLLRRange(Decoders[i], ChildDepth, NumberOutgoingBeliefs * NextNode, NumberOutgoingBeliefs * (NextNode + 1), gRay);

						free(a);
						free(b);
						free(IncomingDecisions);
						free(gRay);
					}

					SetNodeState(NodeStates, Depth, Node, NS_RightDone);
					Node = NextNode;
					Depth = ChildDepth;
				}
				break;
			case NS_RightDone: // step "U" (center / to parent)
				{
					uint16_t const NumberIncomingBeliefs = (uint16_t)pow(2, n - Depth);
					uint16_t const NumberOutgoingBeliefs = NumberIncomingBeliefs / 2;
					uint16_t const LeftChildNode = 2 * Node;
					uint16_t const RightChildNode = LeftChildNode + 1;
					uint16_t const ChildDepth = Depth + 1;

					for(uint16_t i = 0; i < CurrentDecoders; i++)
					{
						Decision_t* LeftChildDecisions = GetDecisionsRange(Decoders[i], ChildDepth, NumberOutgoingBeliefs * LeftChildNode, NumberOutgoingBeliefs * (LeftChildNode + 1));
						Decision_t* RightChildDecisions = GetDecisionsRange(Decoders[i], ChildDepth, NumberOutgoingBeliefs * RightChildNode, NumberOutgoingBeliefs * (RightChildNode + 1));

						Decision_t* Decisions = calloc(ceil(NumberOutgoingBeliefs / 8.0), sizeof(Decision_t));
						for(uint16_t j = 0; j < NumberOutgoingBeliefs; j++)
						{
							SetBitAtIndex(Decisions, j, (GetBitAtIndex(LeftChildDecisions, j) + GetBitAtIndex(RightChildDecisions, j)) % 2);
						}

						SetDecisionsRange(Decoders[i], Depth, NumberIncomingBeliefs * Node, Node * NumberIncomingBeliefs + NumberIncomingBeliefs / 2, Decisions);
						SetDecisionsRange(Decoders[i], Depth, NumberIncomingBeliefs * Node + NumberIncomingBeliefs / 2, NumberIncomingBeliefs * Node + NumberIncomingBeliefs, RightChildDecisions);

						free(LeftChildDecisions);
						free(RightChildDecisions);
						free(Decisions);
					}

					SetNodeState(NodeStates, Depth, Node, NS_Done);

					//next node: parent
					Node = (uint16_t)floor(Node / 2.0);
					Depth -= 1;

					if(Depth < 0) Done = true;
				}
				break;
			default: break;
			}
		}
	}

	//copy decoder decisions to output list
	uint8_t** Output = malloc(NumberOfDecoders * sizeof(uint8_t*));
	for(uint16_t i = 0; i < NumberOfDecoders; i++)
	{
		if(i < CurrentDecoders)
		{
			Output[i] = malloc((uint16_t)ceil(N / 8.0) * sizeof(uint8_t));
			memcpy(Output[i], Decoders[i]->Decisions[n], (uint16_t)ceil(N / 8.0));
			DeleteDecoder(Decoders[i]);
		}
		else
		{
			Output[i] = 0;
		}
	}

	free(Decoders);
	free(NodeStates);

	return Output;
}
