#ifndef __OUTPUT_JSON_TIDB_H__
#define __OUTPUT_JSON_TIDB_H__

#include "app-layer-tidb.h"

void JsonTidbLogRequest(JsonBuilder *js, TidbTransaction *, TidbState *);
void JsonTidbLogResponse(JsonBuilder *js, TidbTransaction *, TidbState *);

void JsonTidbLogRegister(void);

#endif /* __OUTPUT_JSON_TIDB_H__ */
