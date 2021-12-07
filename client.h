// Allan Cedric G. B. Alves da Silva - GRR20190351

#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "kermit.h"

/*!
    @brief  Inicializa o cliente. Cria uma conexão raw socket.
*/
void client_init();

/*!
    @brief  Entrada de dados do cliente

    @return Codificação inteira do comando
*/
int read_client_input();

/*!
    @brief  Lê um comando do cliente

    @return Codificação inteira do comando, 
            senão -1 caso o comando não exista
*/
int read_client_command();

/*!
    @brief  Lê os argumentos de um comando

    @param  cmd_type    Tipo do comando

    @return 0 se foram lidos com sucesso, senão -1
*/
int read_client_args(int cmd_type);

/*!
    @brief  Verifica e executa comandos standalone do cliente

    @param  cmd_type    Tipo do comando

    @return 1 se é um comando standalone, senão 0
*/
int client_standalone_commands(int cmd_type);

/*!
    @brief  Cria um pacote kermit com base no comando inserido
    
    @param  kpckt       Pacote kermit a ser preenchido
    @param  cmd_type    Tipo do comando
*/
void client_command_kermit_pckt(kermit_pckt_t *kpckt, int cmd_type);

/*!
    @brief  Envia uma mensagem para o servidor

    @param  kpckt   Pacote kermit a ser enviado
*/
void send_kpckt_to_server(kermit_pckt_t *kpckt);

/*!
    @brief  Recebe uma resposta do servidor

    @param  kpckt   Pacote kermit a ser preenchido

    @return 0 se recebeu com sucesso, senão 1 (timeout)
*/
int recv_kpckt_from_server(kermit_pckt_t *kpckt);

/*!
    @brief  Verifica se o pacote kermit é válido para o cliente

    @param  kpckt   Pacote kermit a ser verificado

    @return 1 se for um pacote válido, senão 0
*/
int valid_kpckt_for_client(kermit_pckt_t *kpckt);

/*!
    @brief Decodifica e trata um pacote kermit recebido pelo cliente

    @param kpckt_recv   Pacote kermit a ser tratado
    @param kpckt_send   Pacote kermit de resposta
    @param event_type   Tipo de evento a tratar

    @return 1 se precisa enviar o pacote resposta ao servidor, senão 0
*/
int client_kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send, int *event_type);

/*!
    @brief  Rotina que gera o pacote kermit com o argumento 
            do comando "linha"

    @param  kpckt       Pacote kermit de resposta
    @param  event_type  Evento a ser tratado
*/
void linha_type_handler(kermit_pckt_t *kpckt, int *event_type);

/*!
    @brief  Rotina que gera o pacote kermit com o argumento 
            do comando "linhas"

    @param  kpckt       Pacote kermit de resposta
    @param  event_type  Evento a ser tratado
*/
void linhas_type_handler(kermit_pckt_t *kpckt, int *event_type);

/*!
    @brief  Rotina que gera o pacote kermit com o argumento 
            linha do comando "edit"

    @param  kpckt       Pacote kermit de resposta
    @param  event_type  Evento a ser tratado
*/
void edit_type_handler(kermit_pckt_t *kpckt, int *event_type);

/*!
    @brief  Rotina que gera o pacote kermit com o argumento 
            textual do comando "edit"

    @param  kpckt       Pacote kermit de resposta
    @param  event_type  Evento a ser tratado
*/
void buf_type_handler(kermit_pckt_t *kpckt, int *event_type);

/*!
    @brief  Rotina que gera o pacote kermit com o argumento 
            de opções/flags do comando "Compilar"

    @param  kpckt       Pacote kermit de resposta
    @param  event_type  Evento a ser tratado
*/
void compilar_type_handler(kermit_pckt_t *kpckt, int *event_type);

/*!
    @brief Finaliza conexão raw socket do cliente
*/
void client_close();

#endif