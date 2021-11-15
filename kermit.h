#ifndef __KERMIT_H__
#define __KERMIT_H__

#include "rawSocket.h"

#define INIT_MARKER (0x7E)
#define CLI_ADDR (0x1)
#define SER_ADDR (0x2)

typedef unsigned char byte_t;

typedef struct kermit_pckt_t
{
    byte_t init_marker;
    byte_t dest_addr : 2;
    byte_t origin_addr : 2;
    byte_t size : 4;
    byte_t seq : 4;
    byte_t type : 4;
    byte_t msg[16];
    byte_t parity;
} kermit_pckt_t;

void print_kermit_pckt(kermit_pckt_t *kpckt);

int right_kermit_pckt(kermit_pckt_t *kpckt);

#endif