#ifndef __OUTPUT_JSON_DB2_H__
#define __OUTPUT_JSON_DB2_H__

#include "app-layer-db2.h"

void JsonDb2LogRequest(JsonBuilder *js, Db2Transaction *);
void JsonDb2LogResponse(JsonBuilder *js, Db2Transaction *);

void JsonDb2LogRegister(void);

#endif /* __OUTPUT_JSON_DB2_H__ */
