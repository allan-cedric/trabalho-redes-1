// Allan Cedric G. B. Alves da Silva - GRR20190351

#ifndef __SERVER_H__
#define __SERVER_H__

#include "kermit.h"

// --- server.c ---

/*!
    @brief Inicializa o servidor. Cria uma conexão raw socket.
*/
void server_init();

/*!
    @brief  Servidor espera por um pacote kermit de um cliente

    @param  kpckt   Pacote kermit a ser preenchido
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

// --- server_handler.c ---

/*!
    @brief  Função genérica para execução de rotinas de tratamento de comandos

    @param  kpckt_recv  Pacote kermit recebido
    @param  kpckt_send  Pacote kermit de resposta a ser gerado
    @param  cmd_handler Rotina de tratamento de um comando
*/
void cmd_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send,
               void (*cmd_handler)(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send));

/*!
    @brief  Tratamento do comando "ls"

    @param  kpckt_recv  Pacote kermit recebido
    @param  kpckt_send  Pacote resposta a ser gerado
*/
void ls_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Tratamento do comando "ver"

    @param  kpckt_recv  Pacote kermit recebido
    @param  kpckt_send  Pacote resposta a ser gerado
*/
void ver_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Tratamento do comando "linha"

    @param  kpckt_recv  Pacote kermit recebido
    @param  kpckt_send  Pacote resposta a ser gerado
*/
void linha_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Tratamento do comando "linhas"

    @param  kpckt_recv  Pacote kermit recebido
    @param  kpckt_send  Pacote resposta a ser gerado
*/
void linhas_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Tratamento do comando "edit"

    @param  kpckt_recv  Pacote kermit recebido
    @param  kpckt_send  Pacote resposta a ser gerado
*/
void edit_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Tratamento do comando "compilar"

    @param  kpckt_recv  Pacote kermit recebido
    @param  kpckt_send  Pacote resposta a ser gerado
*/
void compilar_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "cd"

    @param  kpckt_recv  Pacote a ser tratado
    @param  kpckt_send  Pacote de resposta
*/
void cd_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "ls"

    @param  kpckt_recv  Pacote a ser tratado
    @param  kpckt_send  Pacote de resposta
*/
void ls_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "ver"

    @param  kpckt_recv  Pacote a ser tratado
    @param  kpckt_send  Pacote de resposta
*/
void ver_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "linha"

    @param  kpckt_recv  Pacote a ser tratado
    @param  kpckt_send  Pacote de resposta
*/
void linha_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "linhas"

    @param  kpckt_recv  Pacote a ser tratado
    @param  kpckt_send  Pacote de resposta
*/
void linhas_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "edit"

    @param  kpckt_recv  Pacote a ser tratado
    @param  kpckt_send  Pacote de resposta
*/
void edit_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief  Rotina para o tratamento de pacotes kermit do comando "compilar"

    @param  kpckt_recv  Pacote a ser tratado
    @param  kpckt_send  Pacote de resposta
*/
void compilar_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

#endif