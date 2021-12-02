// Allan Cedric G. B. Alves da Silva - GRR20190351

#ifndef __KERMIT_H__
#define __KERMIT_H__

// Bibliotecas
#include "raw_socket.h"

#define BUF_SIZE (1024 + 1) // Tamanho para buffer auxiliares
#define DATA_SIZE (15)      // Tamanho do campo de dados do pacote kermit

#define TIMEOUT (2000) // ms
#define TIMEOUT_PROB (97) // %

// --- Códigos do protocolo ---

// Marcadores e endereços do pacote kermit
#define INIT_MARKER (0x7E)
#define CLI_ADDR (0x1)
#define SER_ADDR (0x2)

// Códigos para o campo de tipo do pacote kermit
#define CD_TYPE (0x0)
#define LS_TYPE (0x1)
#define VER_TYPE (0x2)
#define LINHA_TYPE (0x3)
#define LINHAS_TYPE (0x4)
#define EDIT_TYPE (0x5)
#define COMPILAR_TYPE (0x6)

// Códigos para o tipo standalone (client side)
#define LCD_TYPE (0x10)
#define LLS_TYPE (0x11)

// Código para envio de dados (client side)
#define BUF_TYPE (0x12)

// Códigos de resposta do pacote kermit
#define ACK_TYPE (0x8)
#define NACK_TYPE (0x9)
#define LINHA_ARG_TYPE (0xA)
#define LS_CONTENT_TYPE (0xB)
#define ARQ_CONTENT_TYPE (0xC)
#define END_TRANS_TYPE (0xD)
#define ERROR_TYPE (0xF)

// Códigos de erro do pacote kermit
#define NO_PERM (0x1)
#define NO_DIR (0x2)
#define NO_ARQ (0x3)
#define NO_LINE (0x4)

typedef unsigned char byte_t;

// Estrutura para controlar o número de sequências das mensagens
typedef struct seq_t
{
    byte_t recv : 4;
    byte_t send : 4;
} seq_t;

// Estrutura de um pacote kermit
typedef struct kermit_pckt_t
{
    byte_t init_marker;         // Marcador de início (1 byte)
    byte_t dest_addr : 2;       // Endereço destino (2 bits)
    byte_t origin_addr : 2;     // Endereço origem (2 bits)
    byte_t size : 4;            // Tamanho do campo dados (4 bits)
    byte_t seq : 4;             // Núm. de sequência (4 bits)
    byte_t type : 4;            // Tipo da mensagem (4 bits)
    byte_t data[DATA_SIZE + 1]; // Campo de dados (15 byte + 1 byte)
    byte_t parity;              // Paridade do pacote (1 byte)
} kermit_pckt_t;

/*!
    @brief  Gera um pacote kermit

    @param  kpckt       Pacote kermit a ser preenchido
    @param  dest_addr   Endereço destino   
    @param  origin_addr Endereço origem
    @param  seq         Sequência
    @param  type        Tipo da mensagem
    @param  data        Campo de dados
    @param  num_data    Número de dados
    @param  data_size   Tamanho de um dado
*/
void gen_kermit_pckt(kermit_pckt_t *kpckt, int dest_addr, int origin_addr,
                     int seq, int type, void *data, size_t num_data, size_t data_size);

/*!
    @brief  Impressão formatada de um pacote kermit

    @param  kpckt   Pacote kermit a ser impresso
*/
void print_kermit_pckt(kermit_pckt_t *kpckt);

/*!
    @brief  Verifica se é um pacote kermit válido

    @param  kpckt   Pacote kermit a ser verificado

    @return 1 se for válido, senão 0
*/
int valid_kermit_pckt(kermit_pckt_t *kpckt);

/*!
    @brief  Detecção de erros de um pacote kermit

    @param  kpckt   Pacote kermit a ser verficado

    @return 0 caso não tenha erros, senão algo diferente de 0
*/
int error_detection(kermit_pckt_t *kpckt);

#endif