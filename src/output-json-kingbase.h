#ifndef __OUTPUT_JSON_KINGBASE_H__
#define __OUTPUT_JSON_KINGBASE_H__

#include "app-layer-kingbase.h"

void JsonKingbaseLogRequest(JsonBuilder *js, KingbaseTransaction *, KingbaseState *);
void JsonKingbaseLogResponse(JsonBuilder *js, KingbaseTransaction *, KingbaseState *);

void JsonKingbaseLogRegister(void);

#endif /* __OUTPUT_JSON_KINGBASE_H__ */
