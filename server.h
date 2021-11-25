#ifndef __SERVER_H__
#define __SERVER_H__

#include "kermit.h"

/*!
    @brief Inicializa o servidor. Cria uma conexão raw socket.
*/
void server_init();

/*!
    @brief  Servidor espera por um pacote kermit de um cliente

    @param  kpckt   Pacote kermit recebido
*/
void wait_kpckt_from_client(kermit_pckt_t *kpckt);

/*!
    @brief  Recebe uma resposta de um cliente

    @param  kpckt   Pacote kermit a ser recebido

    @return 0 se recebeu com sucesso, senão 1 (timeout)
*/
int recv_kpckt_from_client(kermit_pckt_t *kpckt);

/*!
    @brief Rotina de tratamento de pacotes kermit recebidos no servidor

    @param kpckt_recv Pacote a ser tratado
    @param kpckt_send Pacote de resposta
*/
void server_kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Servidor envia um pacote kermit a um cliente

    @param  kpckt   Pacote kermit a enviar
*/
void send_kpckt_to_client(kermit_pckt_t *kpckt);

/*!
    @brief  Verifica se um pacote kermit é válido para o servidor

    @param  kpckt   Pacote kermit a ser verificado

    @return 1 se é válido, senão 0
*/
int valid_kpckt_for_server(kermit_pckt_t *kpckt);

/*!
    @brief Finaliza a conexão raw socket do servidor
*/
void server_close();

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "cd"

    @param kpckt_recv Pacote a ser tratado
    @param kpckt_send Pacote de resposta
*/
void cd_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "ls"

    @param kpckt_recv Pacote a ser tratado
    @param kpckt_send Pacote de resposta
*/
void ls_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "ver"

    @param kpckt_recv Pacote a ser tratado
    @param kpckt_send Pacote de resposta
*/
void ver_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "linha"

    @param kpckt_recv Pacote a ser tratado
    @param kpckt_send Pacote de resposta
*/
void linha_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "linhas"

    @param kpckt_recv Pacote a ser tratado
    @param kpckt_send Pacote de resposta
*/
void linhas_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

#endif