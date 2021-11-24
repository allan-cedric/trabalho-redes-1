#ifndef __SERVER_H__
#define __SERVER_H__

#include "kermit.h"

/*!
    @brief Inicializa o servidor. Cria uma conexão raw socket.
*/
void server_init();

/*!
    @brief  Servidor espera por um pacote kermit

    @param  kpckt   Pacote kermit recebido
*/
void wait_kpckt(kermit_pckt_t *kpckt);

/*!
    @brief Decodifica e trata um pacote kermit recebido

    @param kpckt_recv Pacote a ser tratado
    @param kpckt_send Pacote de resposta
*/
void kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Servidor envia um pacote kermit

    @param  kpckt   Pacote kermit a enviar
*/
void send_kpckt(kermit_pckt_t *kpckt);

/*!
    @brief  Verifica se um pacote kermit é válido para o servidor

    @param  kpckt   Pacote kermit a ser verificado

    @return 1 se é válido, senão 0
*/
int valid_kermit_pckt_for_server(kermit_pckt_t *kpckt);

/*!
    @brief Finaliza a conexão raw socket do servidor
*/
void server_close();

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "cd"
*/
void cd_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "ls"
*/
void ls_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "ver"
*/
void ver_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

#endif