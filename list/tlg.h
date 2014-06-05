/*-- tlg.h --- LISTA SIMPLU INLANTUITA GENERICA ---*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifndef _random_
  #define _random_
  #define random(n) (rand() % (n))
  #define randomize() (srand((unsigned)time(NULL)))
#endif

#ifndef _LISTA_GENERICA_
#define _LISTA_GENERICA_

typedef struct celg
{ struct celg *urm;   /* adresa urmatoarei celule */
  void *info;         /* adresa informatie */
} TCelg, *TLG, **ALG; /* tipurile Celula, Lista si Adresa_Lista */

typedef int (*TF1)(void*);     /* functie prelucrare un element */
typedef int (*TF2)(void*, void*);  /* functie prelucrare doua elemente */

/*-- operatii elementare - primul parametru este lista sau adresa de lista --*/

/*- inserare la inceput reusita sau nu (1/0) -*/
int InsLgP(ALG, void*);          /* inserare pointer */
int InsLgE(ALG, void*, size_t);  /* inserare cu copiere element */

/*- eliminare elemente -*/ 
void ElimLgC(ALG);   /* eliminare celula */
void ElimLgE(ALG);   /* eliminare celula si element */
void DistrLgC(ALG);  /* distruge celule */
void DistrLgE(ALG);  /* distruge celule si elemente */

size_t LgLG(ALG);   /* numarul de elemente din lista */

ALG CautaSf(ALG a); /* adresa ultimului camp legatura */

ALG CautaLG(ALG a, TF1 f, int Gasit);
    /* daca exista celula pentru care f(element) intoarce Gasit
         atunci intoarce adresa legaturii catre celula respectiva,
         altfel intoarce adresa campului legatura (urm) din ultima celula */
#endif
