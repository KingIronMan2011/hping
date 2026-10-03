/* portable signal() and interactive signal handlers */

/* $Id: signal.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

/* Portable signal() from R.Stevens,
 * modified to reset the handler */
void (*Signal(int signo, void (*func)(int)))(int)
{
	struct sigaction act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0; /* So if set SA_RESETHAND is cleared */
	if (signo == SIGALRM)
	{
#ifdef SA_INTERRUPT
		act.sa_flags |= SA_INTERRUPT;   /* SunOS 4.x */
#endif
	}
	else
	{
#ifdef SA_RESTART
		act.sa_flags |= SA_RESTART;     /* SVR4, 4.4BSD, Linux */
#endif
	}
	if (sigaction(signo, &act, &oact) == -1)
		return SIG_ERR;
	return (oact.sa_handler);
}

void inc_destparm(int sid)
{
	static long sec = 0;
	static long usec = 0;
	int *p;
	int errno_save = errno;

	switch (ctrlzbind) {
	case BIND_DPORT:
		p = &dst_port;
		break;
	case BIND_TTL:
		p = &src_ttl;
		break;
	default:
		printf("error binding ctrl+z\n");
		/* errno = errno_save; */
		return;
	}

	if ( (time(NULL) == sec) && ((get_usec() - usec) < 200000) ) {
		if (*p > 0)
			(*p)-=2;
		if (*p < 0)
			*p=0;
	} else
		(*p)++;
	
	printf("\b\b\b\b\b\b\b\b\b");
	printf("%d: ", *p);
	fflush(stdout);

	sec = time(NULL);
	usec = get_usec();
	signal(SIGTSTP, inc_destparm);
	errno = errno_save;
}
