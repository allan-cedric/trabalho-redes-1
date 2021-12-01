// Allan Cedric G. B. Alves da Silva - GRR20190351

#include "kermit.h"

void gen_kermit_pckt(kermit_pckt_t *kpckt, int dest_addr, int origin_addr,
                     int seq, int type, void *data, size_t num_data, size_t data_size)
{
    memset(kpckt, 0, sizeof(*kpckt)); // Inicializa em 0 o pacote kermit

    // Definições iniciais do pacote
    kpckt->init_marker = INIT_MARKER;
    kpckt->dest_addr = dest_addr;
    kpckt->origin_addr = origin_addr;
    kpckt->size = ((num_data * data_size) < DATA_SIZE ? num_data * data_size : DATA_SIZE);
    kpckt->seq = seq;
    kpckt->type = type;

    // Caso tenha dados, copia para o pacote
    if (data)
        memcpy(kpckt->data, data, kpckt->size);

    // Calcula paridade do pacote
    kpckt->parity = kpckt->size ^ kpckt->seq ^ kpckt->type;
    for (int i = 0; i < kpckt->size; i++)
        kpckt->parity ^= kpckt->data[i];
}

void print_kermit_pckt(kermit_pckt_t *kpckt)
{
    // Campos iniciais
    printf("0x%X 0x%X 0x%X 0x%X 0x%X 0x%X ",
           kpckt->init_marker, kpckt->dest_addr,
           kpckt->origin_addr, kpckt->size,
           kpckt->seq, kpckt->type);

    // Campo de dados
    printf("0x");
    for (int i = 0; i < kpckt->size; i++)
        printf("%X", kpckt->data[i]);

    printf(" 0x%X\n", kpckt->parity);
}

int valid_kermit_pckt(kermit_pckt_t *kpckt)
{
    if (kpckt->init_marker != INIT_MARKER)
        return 0;
    if (kpckt->dest_addr != CLI_ADDR && kpckt->dest_addr != SER_ADDR)
        return 0;
    if (kpckt->origin_addr != CLI_ADDR && kpckt->origin_addr != SER_ADDR)
        return 0;

    return 1;
}

int error_detection(kermit_pckt_t *kpckt)
{
    byte_t parity = kpckt->size ^ kpckt->seq ^ kpckt->type;
    for (int i = 0; i < kpckt->size; i++)
        parity ^= kpckt->data[i];
    parity ^= kpckt->parity;

    return parity;
}