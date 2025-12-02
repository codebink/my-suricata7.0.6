#ifndef __OUTPUT_JSON_RADIUS_H__
#define __OUTPUT_JSON_RADIUS_H__

#include "app-layer-radius.h"

void JsonRadiusLogRequest(JsonBuilder *js, RadiusTransaction *);
void JsonRadiusLogResponse(JsonBuilder *js, RadiusTransaction *);

void JsonRadiusLogRegister(void);

#endif /* __OUTPUT_JSON_RADIUS_H__ */
