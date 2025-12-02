
#ifndef _STEGANO_H
#define _STEGANO_H

#include <stdio.h>


/*
 * Define boolean types.
 */

typedef int	BOOL;

#ifndef FALSE
#define FALSE	0
#endif

#ifndef TRUE
#define TRUE	1
#endif


/*
 * Define global variables.
 */

extern BOOL	compress_flag;
extern BOOL	quiet_flag;
extern int	line_length;


/*
 * Define external functions.
 */

extern void	password_set (const char *passwd);
extern BOOL	message_extract (FILE *inf, FILE *outf);
extern void	space_calculate (FILE *inf);

extern void	compress_init (void);
extern BOOL	compress_bit (int bit, FILE *inf, FILE *outf);
extern BOOL	compress_flush (FILE *inf, FILE *outf);

extern void	uncompress_init (void);
extern BOOL	uncompress_bit (int bit, FILE *outf);
extern BOOL	uncompress_flush (FILE *outf);

extern void	encrypt_init (void);
extern BOOL	encrypt_bit (int bit, FILE *inf, FILE *outf);
extern BOOL	encrypt_flush (FILE *inf, FILE *outf);

extern void	decrypt_init (void);
extern BOOL	decrypt_bit (int bit, FILE *outf);
extern BOOL	decrypt_flush (FILE *outf);

extern void	encode_init (void);
extern BOOL	encode_bit (int bit, FILE *inf, FILE *outf);
extern BOOL	encode_flush (FILE *inf, FILE *outf);
//success 返回1, 
extern BOOL message_string_encode (const char *msg, FILE *infile, FILE *outfile);
extern BOOL message_fp_encode ( FILE *msg_fp, FILE *infile, FILE *outfile);

#endif
