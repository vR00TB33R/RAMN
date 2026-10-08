#include "ramn_coin.h"

#ifdef ENABLE_RAMN_COIN

#include "ramn_canfd.h"
#include "ramn_trng.h"

#define RAMN_COIN_MAGIC              0x4Du // 'M' in ASCII
#define RAMN_COIN_RESULT_MAGIC       0x52u // 'R' in ASCII
#define RAMN_COIN_MAX_ATTEMPTS       1000000u
#define RAMN_COIN_TARGET_ZERO_BYTES  2u
#define RAMN_COIN_HASH_TIMEOUT_MS    10u
#define RAMN_COIN_STACK_WORDS        384u
#define RAMN_COIN_SEND_RETRIES       100u

static StaticTask_t  coinTaskControlBlock;
static StackType_t   coinTaskStack[RAMN_COIN_STACK_WORDS];
static StaticQueue_t challengeQueueControlBlock;
static uint8_t       challengeQueueStorage[sizeof(uint32_t)];
static QueueHandle_t challengeQueue;

// Only the coin task uses the HASH peripheral, so the handle needs no locking.
static HASH_HandleTypeDef coinHash;

// Overrides the weak HAL hook called by HAL_HASH_Init().
void HAL_HASH_MspInit(HASH_HandleTypeDef *hhash)
{
	(void)hhash;
	__HAL_RCC_HASH_CLK_ENABLE();
}

static RAMN_Bool_t sha256(const uint8_t message[8], uint8_t digest[32])
{
	// HAL accesses its buffers as 32-bit words.
	uint32_t in[2];
	uint32_t out[8];
	for (uint32_t i = 0u; i < 8u; i++) ((uint8_t *)in)[i] = message[i];

	if (coinHash.State == HAL_HASH_STATE_RESET) {
		// 8-bit data type makes the first message byte the most significant.
		coinHash.Init.DataType = HASH_DATATYPE_8B;
		if (HAL_HASH_Init(&coinHash) != HAL_OK) return False;
	}

	if (HAL_HASHEx_SHA256_Start(&coinHash, (const uint8_t *)in, 8u,
			(uint8_t *)out, RAMN_COIN_HASH_TIMEOUT_MS) != HAL_OK) {
		// A failed run leaves the HAL mid-message, so reset it for the next call.
		(void)HAL_HASH_DeInit(&coinHash);
		return False;
	}

	for (uint32_t i = 0u; i < 32u; i++) digest[i] = ((const uint8_t *)out)[i]; // Copy the 32-byte hash from the output buffer to the digest.
	return True;
}

static uint8_t countLeadingZeroBytes(const uint8_t hash[32])
{
	uint8_t count = 0u;
	while (count < 32u && hash[count] == 0u) count++;
	return count;
}

static void mineChallenge(uint32_t challenge, uint32_t *resultNonce, uint8_t resultHash[32])
{
	uint8_t preimage[8];
	uint8_t hash[32];
	uint8_t bestHash[32];
	const uint32_t startNonce = RAMN_RNG_Pop32();
	uint32_t bestNonce = startNonce;
	uint8_t bestZeros = 0u;

	for (uint32_t i = 0u; i < 32u; i++) bestHash[i] = 0xFFu;
	preimage[0] = (uint8_t)(challenge >> 24);
	preimage[1] = (uint8_t)(challenge >> 16);
	preimage[2] = (uint8_t)(challenge >> 8);
	preimage[3] = (uint8_t)challenge;
	for (uint32_t i = 0u; i < RAMN_COIN_MAX_ATTEMPTS; i++) {
		const uint32_t nonce = startNonce + i;
		preimage[4] = (uint8_t)nonce;
		preimage[5] = (uint8_t)(nonce >> 8);
		preimage[6] = (uint8_t)(nonce >> 16);
		preimage[7] = (uint8_t)(nonce >> 24);
		if (sha256(preimage, hash) == False) break;

		const uint8_t zeros = countLeadingZeroBytes(hash);
		if (i == 0u || zeros > bestZeros) {
			bestZeros = zeros;
			bestNonce = nonce;
			for (uint32_t j = 0u; j < 32u; j++) bestHash[j] = hash[j];
		}
		if (zeros >= RAMN_COIN_TARGET_ZERO_BYTES) break;
	}

	*resultNonce = bestNonce;
	for (uint32_t i = 0u; i < 32u; i++) resultHash[i] = bestHash[i];
}

static void sendCANResponse(uint32_t nonce, const uint8_t hash[32])
{
	uint8_t payload[8];
	payload[0] = RAMN_COIN_RESULT_MAGIC;
	payload[1] = (uint8_t)nonce;
	payload[2] = (uint8_t)(nonce >> 8);
	payload[3] = (uint8_t)(nonce >> 16);
	payload[4] = (uint8_t)(nonce >> 24);
	payload[5] = hash[0];
	payload[6] = hash[1];
	payload[7] = hash[2];

	FDCAN_TxHeaderTypeDef header;
	header.BitRateSwitch = FDCAN_BRS_OFF;
	header.ErrorStateIndicator = FDCAN_ESI_ACTIVE;
	header.FDFormat = FDCAN_CLASSIC_CAN;
	header.TxFrameType = FDCAN_DATA_FRAME;
	header.IdType = FDCAN_EXTENDED_ID;
	header.Identifier = RAMN_COIN_CAN_ID_RSP;
	header.DataLength = FDCAN_DLC_BYTES_8;
	header.TxEventFifoControl = FDCAN_NO_TX_EVENTS;
	header.MessageMarker = 0u;

	for (uint32_t attempt = 0u; attempt < RAMN_COIN_SEND_RETRIES; attempt++) {
		if (RAMN_FDCAN_SendMessage(&header, payload) != RAMN_TRY_LATER) break;
		osDelay(10u);
	}
}

static void coinTask(void *argument)
{
	(void)argument;
	for (;;) {
		uint32_t challenge;
		if (xQueueReceive(challengeQueue, &challenge, portMAX_DELAY) == pdTRUE) {
			uint32_t nonce;
			uint8_t hash[32];
			mineChallenge(challenge, &nonce, hash);
			sendCANResponse(nonce, hash);
		}
	}
}

void RAMN_COIN_Init(void)
{
	challengeQueue = xQueueCreateStatic(1u, sizeof(uint32_t), challengeQueueStorage,
										&challengeQueueControlBlock);
	if (challengeQueue == NULL) return;
	if (xTaskCreateStatic(coinTask, "RAMN_Coin", RAMN_COIN_STACK_WORDS, NULL,
						  (UBaseType_t)osPriorityLow, coinTaskStack,
						  &coinTaskControlBlock) == NULL) {
		challengeQueue = NULL;
	}
}

RAMN_Bool_t RAMN_COIN_ProcessRxCANMessage(
		const FDCAN_RxHeaderTypeDef *pHeader,
		const uint8_t              *data)
{
	if (pHeader->IdType != FDCAN_EXTENDED_ID || pHeader->RxFrameType != FDCAN_DATA_FRAME ||
		pHeader->Identifier != RAMN_COIN_CAN_ID_CMD) return False;
	if (DLCtoUINT8(pHeader->DataLength) < 5u || data[0] != RAMN_COIN_MAGIC ||
		challengeQueue == NULL) return False;

	const uint32_t challenge = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
			((uint32_t)data[3] << 8) | (uint32_t)data[4];
	(void)xQueueSend(challengeQueue, &challenge, 0u);
	return True;
}

#endif /* ENABLE_RAMN_COIN */