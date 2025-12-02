#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stegano.h"

int main ( int		argc, char		*argv[])
{
	int		c;
	int		optind;
	BOOL		errflag = FALSE;
	char		*passwd = NULL;
	char		*message_string = NULL;
	FILE		*message_fp = NULL;
	FILE		*infile = stdin;
	FILE		*outfile = stdout;

	optind = 1;
	for (optind = 1; optind < argc && argv[optind][0] == '-'; optind++) 
    {
	    char	c = argv[optind][1];
	    char	*optarg;

	    
	    switch (c) {
		
		case 'm':
		    if (argv[optind][2] != '\0')
			optarg = &argv[optind][2];
		    else if (++optind == argc) {
			errflag = TRUE;
			break;
		    } else
			optarg = argv[optind];

		    message_string = optarg;
		    break;
	  }

	    if (errflag)
		break;
	}

	if (message_string != NULL && message_fp != NULL) {
	    fprintf (stderr, "Cannot specify both message string and file\n");
	    errflag = TRUE;
	}

	if (optind < argc) {
	    if ((infile = fopen (argv[optind], "r")) == NULL) {
		perror (argv[optind]);
		return 1;
	    }
	}

	if (optind + 1 < argc) {
	    if ((outfile = fopen (argv[optind + 1], "w")) == NULL) {
		perror (argv[optind + 1]);
		return 1;
	    }
	}
    char buf[1024]={0};

	 if (message_string != NULL) {
	    if (!message_string_encode (message_string, infile, outfile)) // 1 : success.
		return 1;
	} else if (message_fp != NULL) {
	    if (!message_fp_encode (message_fp, infile, outfile))
		return 1;
	    fclose (message_fp);
	} else {
	    if (!message_extract (infile, outfile))
		return 1;
	}

	fclose (outfile);
	fclose (infile);

	return 0;
}


