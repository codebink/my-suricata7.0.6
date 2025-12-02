#ifndef __OUTPUT_JSON_DMDB_H__
#define __OUTPUT_JSON_DMDB_H__

#include "app-layer-dmdb.h"

void JsonDmdbLogRequest(JsonBuilder *js, DmdbTransaction *, DmdbState *);
void JsonDmdbLogResponse(JsonBuilder *js, DmdbTransaction *, DmdbState *);

void JsonDmdbLogRegister(void);

#endif /* __OUTPUT_JSON_DMDB_H__ */
