#ifndef __OUTPUT_JSON_KRB5_H__
#define __OUTPUT_JSON_KRB5_H__

#include "app-layer-krb5.h"

void JsonKrb5LogRequest(JsonBuilder *js, Krb5Transaction *);
void JsonKrb5LogResponse(JsonBuilder *js, Krb5Transaction *);

void JsonKrb5LogRegisterTcp(void);
void JsonKrb5LogRegisterUdp(void);


#endif /* __OUTPUT_JSON_KRB5_H__ */
