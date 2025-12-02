#ifndef __OUTPUT_JSON_SQLSERVER_H__
#define __OUTPUT_JSON_SQLSERVER_H__

#include "app-layer-sqlserver.h"

void JsonSqlserverLogRequest(JsonBuilder *js, SqlserverTransaction *, SqlserverState *);
void JsonSqlserverLogResponse(JsonBuilder *js, SqlserverTransaction *, SqlserverState *);

void JsonSqlserverLogRegister(void);

#endif /* __OUTPUT_JSON_SQLSERVER_H__ */
