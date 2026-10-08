#ifndef INC_RAMN_COIN_H_
#define INC_RAMN_COIN_H_

#include "main.h"

#ifdef ENABLE_RAMN_COIN

#if defined(TARGET_ECUB)
#define RAMN_COIN_ECU_ADDRESS  0x0Bu
#elif defined(TARGET_ECUC)
#define RAMN_COIN_ECU_ADDRESS  0x0Cu
#elif defined(TARGET_ECUD)
#define RAMN_COIN_ECU_ADDRESS  0x0Du
#else
#error "ENABLE_RAMN_COIN is only supported on ECU B, C and D"
#endif

#define RAMN_COIN_CAN_ID_CMD  (0x18FFDA00u | RAMN_COIN_ECU_ADDRESS)
#define RAMN_COIN_CAN_ID_RSP  (0x18FFDB00u | RAMN_COIN_ECU_ADDRESS)

void RAMN_COIN_Init(void);
RAMN_Bool_t RAMN_COIN_ProcessRxCANMessage(
		const FDCAN_RxHeaderTypeDef *pHeader,
		const uint8_t              *data);

#else

#define RAMN_COIN_Init() ((void)0)

static inline RAMN_Bool_t RAMN_COIN_ProcessRxCANMessage_Disabled(
		const FDCAN_RxHeaderTypeDef *pHeader,
		const uint8_t              *data)
{
	(void)pHeader;
	(void)data;
	return False;
}
#define RAMN_COIN_ProcessRxCANMessage RAMN_COIN_ProcessRxCANMessage_Disabled

#endif

#endif /* INC_RAMN_COIN_H_ */