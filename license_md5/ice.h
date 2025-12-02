
#ifndef _ICE_H
#define _ICE_H

typedef struct ice_key_struct	ICE_KEY;

#if __STDC__
#define P_(x) x
#else
#define P_(x) ()
#endif

extern ICE_KEY	*ice_key_create P_((int n));
extern void	ice_key_destroy P_((ICE_KEY *ik));
extern void	ice_key_set P_((ICE_KEY *ik, const unsigned char *k));
extern void	ice_key_encrypt P_((const ICE_KEY *ik,
			const unsigned char *ptxt, unsigned char *ctxt));
extern void	ice_key_decrypt P_((const ICE_KEY *ik,
			const unsigned char *ctxt, unsigned char *ptxt));

#undef P_

#endif
