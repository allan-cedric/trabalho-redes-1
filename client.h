#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "kermit.h"

/*!
    @brief  Lê um comando do cliente

    @return Codificação inteira do comando, senão -1 caso o comando não exista
*/
int read_client_command();

void *read_client_args(int cmd_type);

int valid_kermit_pckt_for_cli(kermit_pckt_t *kpckt);

#endif