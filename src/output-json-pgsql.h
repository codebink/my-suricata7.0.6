#ifndef __OUTPUT_JSON_PGSQL_H__
#define __OUTPUT_JSON_PGSQL_H__

#include "app-layer-pgsql.h"

void JsonPgsqlLogRequest(JsonBuilder *js, PgsqlTransaction *, PgsqlState *);
void JsonPgsqlLogResponse(JsonBuilder *js, PgsqlTransaction *, PgsqlState *);

void JsonPgsqlLogRegister(void);

#endif /* __OUTPUT_JSON_PGSQL_H__ */
