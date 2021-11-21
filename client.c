#include "client.h"

int read_client_command()
{
    byte_t new_cmd[BUF_SIZE];
    scanf("%s", new_cmd);

    if (!strcmp("cd", (const char *)new_cmd))
        return CD_TYPE;
    else if(!strcmp("lcd", (const char *)new_cmd))
        return LCD_TYPE;
    else if(!strcmp("ls", (const char *)new_cmd))
        return LS_TYPE;
    else if(!strcmp("lls", (const char *)new_cmd))
        return LLS_TYPE;

    while (getchar() != '\n'); // Limpa stdin
    return -1;
}

void *read_client_args(int cmd_type)
{
    void *args = NULL;
    switch (cmd_type)
    {
    case CD_TYPE:
    case LCD_TYPE:
        args = malloc(BUF_SIZE);
        scanf("%s", (byte_t *)args);
        while (getchar() != '\n'); // Limpa stdin
        break;
    default:
        break;
    }
    return args;
}

int valid_kermit_pckt_for_cli(kermit_pckt_t *kpckt)
{
    if (valid_kermit_pckt(kpckt))
        return (kpckt->origin_addr == SER_ADDR && kpckt->dest_addr == CLI_ADDR);
    return 0;
}