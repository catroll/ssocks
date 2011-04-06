/* bor-timer.c : Liste de timers pour select
 *
 * Edouard.Thiel@lif.univ-mrs.fr - 19/03/2010 - V 2.0a
 *
 * This program is free software under the terms of the
 * GNU Lesser General Public License (LGPL) version 2.1.
*/

#include "bor-util.h"
#include "bor-timer.h"


/*
    Usage :
    
    int h1, h2, res;
    
    h1 = bor_timer_add (delai1, data1);
    h2 = bor_timer_add (delai2, data2);
    
    res = select (..., bor_timer_delay());
    
    if (res == 0) {
        handle = bor_timer_handle();
        data = bor_timer_data();
        
        if (handle == h1) { 
            printf ("delai1 ecoule");
        } else if (handle == h2) { 
            printf ("delai2 ecoule");
        }
        
        bor_timer_remove (handle);
    }

*/


typedef struct {
    int handle;
    void *data;
    struct timeval expiration;
} bor_timer_struct;

#define BOR_TIMER_MAX 1000

bor_timer_struct bor_timer_list[BOR_TIMER_MAX];
int bor_timer_nb = 0;
int bor_timer_uniq = 0;


/* Ajoute un timer dont l'echeance sera dans delay millisecondes ;
   data est l'adresse d'une donnee quelconque, que l'on pourra recuperer
   lorsque le timer arrivera a echeance.
   Renvoie un "handle", c'est-a-dire un numero unique de timer, qui
   permettra de reconnaitre quel est le timer arrive a echeance,
   ou encore permettra de supprimer ce timer.

   L'insertion se fait par dichotomie dans une liste triee sur la date
   d'expiration ; le prochain timer est donc toujours en position 0.
   Verbeux.
*/
int bor_timer_add (unsigned long delay, void *data)
{
    int m1, m2, mid;
    struct timeval t, *mt;

    if (bor_timer_nb >= BOR_TIMER_MAX) {
        fprintf (stderr, "bor_timer_add: erreur, trop de timers\n");
        return -1;
    }

    /* Recupere date courante */
    gettimeofday (&t, NULL);

    /* Calcule date d'expiration */
    t.tv_usec += delay * 1000;   /* delay en millisecondes */
    if (t.tv_usec > 1000000) {
        t.tv_sec += t.tv_usec / 1000000;
        t.tv_usec %= 1000000;
    }

    /* Recherche dichotomique */
    m1 = 0; m2 = bor_timer_nb;
    while (m2-m1 > 0) {
        mid = (m1+m2) / 2;    /* Milieu tq m1 <= mid < m2 */
        mt = &bor_timer_list[mid].expiration;
        if ( mt->tv_sec < t.tv_sec ||
            (mt->tv_sec == t.tv_sec && mt->tv_usec < t.tv_usec) )
             m1 = mid+1;   /* t doit aller dans [mid+1 .. m2] */
        else m2 = mid;     /* t doit aller dans [m1 .. mid]   */
    }

    /* Insere en position m1 */
    if (m1 < bor_timer_nb)
        memmove (bor_timer_list+m1+1,   /* dest */
                 bor_timer_list+m1,     /* src */
                 (bor_timer_nb-m1)*sizeof(bor_timer_struct));
    bor_timer_nb++;
    bor_timer_list[m1].handle = bor_timer_uniq++;
    bor_timer_list[m1].data = data;
    bor_timer_list[m1].expiration = t;
    return bor_timer_list[m1].handle;
}


/* Supprime un timer a partir de son handle.
 * On maintient le tableau trie. Silencieux.
*/
void bor_timer_remove (int handle)
{
    int i;
    if (handle < 0) return;
    for (i = 0; i < bor_timer_nb; i++)
        if (bor_timer_list[i].handle == handle) {
            memmove (bor_timer_list+i,    /* dest */
                     bor_timer_list+i+1,  /* src */
                     (bor_timer_nb-i-1)*sizeof(bor_timer_struct));
            bor_timer_nb--;
            break;
        }
}


/* Renvoie le delai entre la date courante et le prochain timer,
   a passer directement a select(). Silencieux.
*/
struct timeval *bor_timer_delay ()
{
    static struct timeval t;

    /* Aucun timer */
    if (bor_timer_nb == 0) return NULL;

    /* Recupere date courante */
    gettimeofday(&t, NULL);

    /* Le prochain timeout est bor_timer_list[0].expiration ;
       on calcule la difference avec la date courante */
    t.tv_sec  = bor_timer_list[0].expiration.tv_sec  - t.tv_sec;
    t.tv_usec = bor_timer_list[0].expiration.tv_usec - t.tv_usec;
    if (t.tv_usec < 0) { t.tv_usec += 1000000; t.tv_sec -= 1;}
    if (t.tv_sec  < 0) t.tv_sec = t.tv_usec = 0;

    /* printf ("Timeout dans %d s  %6d us\n", (int)t.tv_sec, (int)t.tv_usec); */

    /* Renvoie adresse statique du struct */
    return &t;
}


/* Renvoie le handle du prochain timer, sinon -1. Silencieux.
*/
int bor_timer_handle ()
{
    if (bor_timer_nb == 0) return -1;
    return bor_timer_list[0].handle;
}


/* Renvoie la data du prochain timer, sinon NULL. Silencieux.
*/
void *bor_timer_data ()
{
    if (bor_timer_nb == 0) return NULL;
    return bor_timer_list[0].data;
}

