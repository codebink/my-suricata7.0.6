#ifndef __OUTPUT_JSON_MYSQL_H__
#define __OUTPUT_JSON_MYSQL_H__

#include "app-layer-mysql.h"

void JsonMysqlLogRequest(JsonBuilder *js, MysqlTransaction *, MysqlState *);
void JsonMysqlLogResponse(JsonBuilder *js, MysqlTransaction *, MysqlState *);

void JsonMysqlLogRegister(void);

#endif /* __OUTPUT_JSON_MYSQL_H__ */
