#ifndef __OUTPUT_JSON_MONGODB_H__
#define __OUTPUT_JSON_MONGODB_H__

#include "app-layer-mongodb.h"

void JsonMongodbLogRequest(JsonBuilder *js, MongodbTransaction *);
void JsonMongodbLogResponse(JsonBuilder *js, MongodbTransaction *);

void JsonMongodbLogRegister(void);

#endif /* __OUTPUT_JSON_MONGODB_H__ */
