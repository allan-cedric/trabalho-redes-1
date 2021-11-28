#include "kermit.h"

void gen_kermit_pckt(kermit_pckt_t *kpckt, int dest_addr, int origin_addr,
                     int seq, int type, void *args, size_t num_args, size_t args_size)
{
    memset(kpckt, 0, sizeof(*kpckt));

    kpckt->init_marker = INIT_MARKER;
    kpckt->dest_addr = dest_addr;
    kpckt->origin_addr = origin_addr;
    kpckt->size = ((num_args * args_size) < MSG_SIZE ? num_args * args_size : MSG_SIZE);
    kpckt->seq = seq;
    kpckt->type = type;

    switch (kpckt->type)
    {
    case CD_TYPE:
    case LS_CONTENT_TYPE:
    case VER_TYPE:
    case LINHA_TYPE:
    case LINHAS_TYPE:
    case LINHA_CONTENT_TYPE:
    case EDIT_TYPE:
    case ARQ_CONTENT_TYPE:
    case ERROR_TYPE:
        memcpy(kpckt->msg, args, kpckt->size);
        break;
    default: // "ACK", "NACK", "ls"
        break;
    }

    // Calcula paridade do pacote
    kpckt->parity = kpckt->size ^ kpckt->seq ^ kpckt->type;
    for (int i = 0; i < kpckt->size; i++)
        kpckt->parity ^= kpckt->msg[i];
}

void print_kermit_pckt(kermit_pckt_t *kpckt)
{
    printf("0x%X 0x%X 0x%X 0x%X 0x%X 0x%X ",
           kpckt->init_marker, kpckt->dest_addr,
           kpckt->origin_addr, kpckt->size,
           kpckt->seq, kpckt->type);

    printf("0x");
    for (int i = 0; i < kpckt->size; i++)
        printf("%X", kpckt->msg[i]);

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

int verify_parity(kermit_pckt_t *kpckt)
{
    byte_t parity = kpckt->size ^ kpckt->seq ^ kpckt->type;
    for (int i = 0; i < kpckt->size; i++)
        parity ^= kpckt->msg[i];
    parity ^= kpckt->parity;

    return parity;
}