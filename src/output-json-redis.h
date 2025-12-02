#ifndef __OUTPUT_JSON_REDIS_H__
#define __OUTPUT_JSON_REDIS_H__

#include "app-layer-redis.h"

void JsonRedisLogRequest(JsonBuilder *js, RedisTransaction *, RedisState *);
void JsonRedisLogResponse(JsonBuilder *js, RedisTransaction *, RedisState *);

void JsonRedisLogRegister(void);

#endif /* __OUTPUT_JSON_REDIS_H__ */
