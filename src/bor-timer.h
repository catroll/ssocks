/* bor-timer.h : Liste de timers pour select
 *
 * Edouard.Thiel@lif.univ-mrs.fr - 19/03/2010 - V 2.0a
 *
 * This program is free software under the terms of the 
 * GNU Lesser General Public License (LGPL) version 2.1.
*/

#ifndef BOR_TIMER__H
#define BOR_TIMER__H

#include <sys/time.h>
#include <time.h>

/* Compatibilite avec C++ */
#if defined(c_plusplus) && !defined(__cplusplus)
#define __cplusplus
#endif
#ifdef __cplusplus
extern "C" {
#endif


/* Prototypes */

int bor_timer_add (unsigned long delay, void *data);
void bor_timer_remove (int handle);
struct timeval *bor_timer_delay ();
int bor_timer_handle ();
void *bor_timer_data ();


/* Compatibilite avec C++ */
#ifdef __cplusplus
}
#endif

#endif /* BOR_TIMER__H */

