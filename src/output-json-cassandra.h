#ifndef __OUTPUT_JSON_CASSANDRA_H__
#define __OUTPUT_JSON_CASSANDRA_H__

#include "app-layer-cassandra.h"

void JsonCassandraLogRequest(JsonBuilder *js, CassandraTransaction *, CassandraState *);
void JsonCassandraLogResponse(JsonBuilder *js, CassandraTransaction *, CassandraState *);

void JsonCassandraLogRegister(void);

#endif /* __OUTPUT_JSON_CASSANDRA_H__ */
