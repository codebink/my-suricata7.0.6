#ifndef __OUTPUT_JSON_HANA_H__
#define __OUTPUT_JSON_HANA_H__

#include "app-layer-hana.h"

void JsonHanaLogRequest(JsonBuilder *js, HanaTransaction *);
void JsonHanaLogResponse(JsonBuilder *js, HanaTransaction *);

void JsonHanaLogRegister(void);

#endif /* __OUTPUT_JSON_HANA_H__ */
