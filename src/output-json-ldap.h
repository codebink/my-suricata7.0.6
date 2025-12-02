#ifndef __OUTPUT_JSON_LDAP_H__
#define __OUTPUT_JSON_LDAP_H__

#include "app-layer-ldap.h"

void JsonLdapLogRequest(JsonBuilder *js, LdapTransaction *);
void JsonLdapLogResponse(JsonBuilder *js, LdapTransaction *);

void JsonLdapLogRegister(void);

#endif /* __OUTPUT_JSON_LDAP_H__ */
