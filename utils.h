// Allan Cedric G. B. Alves da Silva - GRR20190351

#ifndef __UTILS_H__
#define __UTILS_H__

// Bibliotecas
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

/*!
    @brief  Teste de alocação de memória

    @param  ptr Ponteiro para a região de memória alocada
*/
void allocation_test(void *ptr);

/*!
    @brief  Calcula o tempo corrente do programa

    @return Tempo corrente em milissegundos 
*/
double timestamp();

#endif