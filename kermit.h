#ifndef __KERMIT_H__
#define __KERMIT_H__

#include "raw_socket.h"

#define BUF_SIZE (1024 + 1)
#define MSG_SIZE (15)

#define TIMEOUT (5000)

// --- Códigos do protocolo ---

// Marcadores e endereços
#define INIT_MARKER (0x7E)
#define CLI_ADDR (0x1)
#define SER_ADDR (0x2)

// Tamanho máximo de seq.
#define MAX_SEQ (0x10)

// Códigos para cada comando
#define CD_TYPE (0x0)
#define LS_TYPE (0x1)
#define VER_TYPE (0x2)
#define LINHA_TYPE (0x3)
#define LINHAS_TYPE (0x4)
#define EDIT_TYPE (0x5)
#define COMPILAR_TYPE (0x6)

#define LCD_TYPE (0x10)
#define LLS_TYPE (0x11)

// Códigos de resposta
#define ACK_TYPE (0x8)
#define NACK_TYPE (0x9)
#define LINHA_CONTENT_TYPE (0xA)
#define LS_CONTENT_TYPE (0xB)
#define ARQ_CONTENT_TYPE (0xC)
#define END_TRANS_TYPE (0xD)
#define ERROR_TYPE (0xF)

// Códigos de erro
#define NO_PERM (0x1)
#define NO_DIR (0x2)
#define NO_ARQ (0x3)
#define NO_LINE (0x4)

typedef unsigned char byte_t;

typedef struct kermit_pckt_t
{
    byte_t init_marker;
    byte_t dest_addr : 2;
    byte_t origin_addr : 2;
    byte_t size : 4;
    byte_t seq : 4;
    byte_t type : 4;
    byte_t msg[MSG_SIZE + 1];
    byte_t parity;
} kermit_pckt_t;

void gen_kermit_pckt(kermit_pckt_t *kpckt, int dest_addr, int origin_addr,
                     int seq, int type, void *args, size_t num_args, size_t args_size);

void print_kermit_pckt(kermit_pckt_t *kpckt);

int valid_kermit_pckt(kermit_pckt_t *kpckt);

int verify_parity(kermit_pckt_t *kpckt);

#endif