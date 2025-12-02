#ifndef __OUTPUT_JSON_MARIADB_H__
#define __OUTPUT_JSON_MARIADB_H__

#include "app-layer-mariadb.h"

void JsonMariadbLogRequest(JsonBuilder *js, MariadbTransaction *, MariadbState *);
void JsonMariadbLogResponse(JsonBuilder *js, MariadbTransaction *, MariadbState *);

void JsonMariadbLogRegister(void);

#endif /* __OUTPUT_JSON_MARIADB_H__ */
