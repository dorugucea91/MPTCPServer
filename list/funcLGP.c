/*--- funcLGP.c -- operatii de baza pentru lista simplu inlantuita generica
                 cu info pointer la element ---*/
#include "tlg.h"

int InsLgP(ALG a, void* e)  /* inserare la inceput reusita sau nu (1/0) */
{ TLG aux = (TLG)malloc(sizeof(TCelg));  /* incearca alocare */
  if (!aux) return 0;               /* alocare imposibila -> esec */
  aux->info = e;                    /* completeaza campul info */
  aux->urm = *a;                    /* conecteaza celula in lista */
  *a = aux;                         
  return 1;                         /* operatia de inserare a reusit */
}

int InsLgE(ALG a, void* e, size_t d)/* inserare la inceput reusita sau nu (1/0) */
{ TLG aux = (TLG)malloc(sizeof(TCelg));  /* incearca alocare pt.celula */
  if (!aux) return 0;               /* alocare imposibila -> esec */
  aux->info = malloc(d);            /* incearca alocare pt.element */
  if (!aux->info) { free(aux); return 0;}
  memcpy(aux->info, e, d);          /* copiaza element */
  aux->urm = *a;                    /* conecteaza celula in lista */
  *a = aux;
  return 1;                         /* operatia de inserare a reusit */
} 

void ElimLgC(ALG a)   /* eliminare celula */
{ TLG aux = *a;          /* adresa celulei eliminate */
  if (!aux) return;      /* lista vida */
  *a = aux->urm;         /* deconecteaza celula din lista */
  free(aux);             /* elibereaza spatiul ocupat de celula */
}

void ElimLgE(ALG a)   /* eliminare celula si element */
{ TLG aux = *a;          /* adresa celulei eliminate */
  if (!aux) return;      /* lista vida */
  free(aux->info);       /* elibereaza spatiul ocupat de element */
  *a = aux->urm;         /* deconecteaza celula din lista */
  free(aux);             /* elibereaza spatiul ocupat de celula */
}

void DistrLgC(ALG a)  /* distruge celule */
{ TLG aux;
  while (*a != NULL)     /* cat timp mai exista celule */
  { aux = *a;            /* pregateste eliminarea celulei curente */
    *a = aux->urm;       /* avans la celula urmatoare */
    free(aux);           /* elibereaza spatiul ocupat de celula */
  }
}

void DistrLgE(ALG a)  /* distruge celule si elemente */
{ TLG aux;
  while (*a != NULL)     /* cat timp mai exista celule */
  { aux = *a;            /* pregateste eliminarea celulei curente */
    *a = aux->urm;       /* avans la celula urmatoare */
    free(aux->info);     /* elibereaza spatiul ocupat de element */
    free(aux);           /* elibereaza spatiul ocupat de celula */
  }
}

size_t LgLG(ALG a)      /* numarul de elemente din lista */
{ size_t lg = 0;
  TLG p = *a;
  for (; p != NULL; p = p->urm) lg++;  /* parcurge lista, numarand celulele */
  return lg;
}


ALG CautaSf(ALG a) /* cauta adresa ultimului camp legatura */
{ while (*a != NULL) a = &(*a)->urm;
  return a;
}

ALG CautaLG(ALG a, TF1 f, int Gasit)
       /* daca exista celula pentru care f(adr.element) intoarce Gasit
	  atunci intoarce adresa legaturii catre celula respectiva,
	  altfel intoarce adresa campului legatura (urm) din ultima celula */
{ for (; *a != NULL; a = &(*a)->urm) { 
    if (f((*a)->info) == Gasit) break;
    }
  return a;
}

ALG CautaSuccesor(ALG a, void* e, TF2 Comp)
{ while (*a) 
  { if (Comp(e, (*a)->info) < 0) return a;
    a = &(*a)->urm;
  }
  return a;
}

void Muta(ALG as, ALG ar)
{ TLG aux;
  aux = *as;
  *as = aux->urm;
  aux->urm = *ar;
  *ar = aux;
}

void OrdL(ALG a, TF2 Comp)
{ ALG s, prim = a;
  while ((*a) && (*a)->urm)
  { if (Comp((*a)->info, (*a)->urm->info) <= 0)
     a = &(*a)->urm;
    else 
    { s = CautaSuccesor(prim, (*a)->urm->info, Comp);
      Muta(&(*a)->urm, s);
    }
  }
}




  
  
 

