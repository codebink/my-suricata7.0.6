#ifndef __OUTPUT_JSON_ORACLE_H__
#define __OUTPUT_JSON_ORACLE_H__

#include "app-layer-oracle.h"

void JsonOracleLogRequest(JsonBuilder *js, OracleTransaction *);
void JsonOracleLogResponse(JsonBuilder *js, OracleTransaction *);

void JsonOracleLogRegister(void);

#endif /* __OUTPUT_JSON_ORACLE_H__ */
