#include "kermit.h"

void print_kermit_pckt(kermit_pckt_t *kpckt)
{
    printf("0x%X 0x%X 0x%X 0x%X 0x%X 0x%X ",
           kpckt->init_marker, kpckt->dest_addr,
           kpckt->origin_addr, kpckt->size,
           kpckt->seq, kpckt->type);

    printf("0x");
    for (int i = 0; i < strlen((const char *)kpckt->msg); i++)
        printf("%X", kpckt->msg[i]);

    printf(" 0x%X\n", kpckt->parity);
}

int right_kermit_pckt(kermit_pckt_t *kpckt)
{
    if (kpckt->init_marker != INIT_MARKER)
        return 0;
    if (kpckt->dest_addr != CLI_ADDR && kpckt->dest_addr != SER_ADDR)
        return 0;
    if (kpckt->origin_addr != CLI_ADDR && kpckt->origin_addr != SER_ADDR)
        return 0;
    return 1;
}