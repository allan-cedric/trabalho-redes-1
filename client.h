#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "kermit.h"

/*!
    @brief  Inicializa o cliente. Cria uma conexão raw socket.
*/
void client_init();

/*!
    @brief Entrada de dados do cliente
*/
void read_client_input();

/*!
    @brief  Lê um comando do cliente

    @return Codificação inteira do comando, senão -1 caso o comando não exista
*/
int read_client_command();

/*!
    @brief  Lê os argumentos de um comando

    @return 0 se foram lidos com sucesso, senão -1
*/
int read_client_args();

/*!
    @brief  Verifica e executa comandos standalone do cliente

    @return 1 se é um comando standalone, senão 0
*/
int client_standalone_commands();

/*!
    @brief  Cria um pacote kermit com base no comando inserido
            (Depende da chamada read_client_input)
    
    @param  kpckt   Pacote kermit a ser preenchido
*/
void client_command_kermit_pckt(kermit_pckt_t *kpckt);

/*!
    @brief  Envia uma mensagem para o servidor

    @param  kpckt   Pacote kermit a ser enviado
*/
void send_kpckt_to_server(kermit_pckt_t *kpckt);

/*!
    @brief  Recebe uma resposta do servidor

    @param  kpckt   Pacote kermit a ser recebido

    @return 0 se recebeu com sucesso, senão 1 (timeout)
*/
int recv_kpckt_from_server(kermit_pckt_t *kpckt);

/*!
    @brief  Verifica se o pacote kermit é válido para o cliente

    @param  kpckt   Pacote kermit

    @return 1 se for um pacote válido, senão 0
*/
int valid_kpckt_for_client(kermit_pckt_t *kpckt);

/*!
    @brief Decodifica e trata um pacote kermit recebido

    @param kpckt_recv Pacote a ser tratado
    @param kpckt_send Pacote de resposta

    @return 1 se precisa enviar o pacote resposta ao servidor, senão 0
*/
int kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send);

/*!
    @brief Finaliza conexão raw socket do cliente
*/
void client_close();

#endif