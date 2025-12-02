#ifndef __OUTPUT_JSON_GITSMART_H__
#define __OUTPUT_JSON_GITSMART_H__

#include "app-layer-gitsmart.h"

void JsonGitsmartLogRequest(JsonBuilder *js, GitsmartTransaction *);
void JsonGitsmartLogResponse(JsonBuilder *js, GitsmartTransaction *);

void JsonGitsmartLogRegister(void);

#endif /* __OUTPUT_JSON_GITSMART_H__ */
