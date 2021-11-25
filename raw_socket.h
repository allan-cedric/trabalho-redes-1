#ifndef __RAW_SOCKET_H__
#define __RAW_SOCKET_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>

#define ERROR_CODE -1

/*!
    @brief  Cria um raw socket

    @param  device  Interface de comunicação

    @return Descritor de arquivo (FD) do socket
*/
int rawsocket_connection(char *device);

/*!
    @brief Função wrapper da função sendto(). Envia uma mensagem para um raw socket.

    @param  socket_fd   Descritor do socket
    @param  buf         Buffer da mensagem
    @param  buf_size    Tamanho da mensagem

    @return Quantidade de bytes enviados
*/
int sendto_rawsocket(int socket_fd, void *buf, size_t buf_size);

/*!
    @brief Função wrapper da função recvfrom(). Recebe uma mensagem de um raw socket.

    @param  socket_fd   Descritor do socket
    @param  buf         Buffer da mensagem
    @param  buf_size    Tamanho da mensagem

    @return Quantidade de bytes lidos
*/
int recvfrom_rawsocket(int socket_fd, void *buf, size_t buf_size);

/*!
    @brief  Calcula o tempo corrente do programa

    @return Tempo corrente em milissegundos 
*/
double timestamp();

#endif