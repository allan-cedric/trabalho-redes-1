#include "client.h"

// --- Estrutura para conexão raw socket ---
struct sockaddr_ll addr;
socklen_t addr_len;
int socket_fd;

// --- Variáveis de controle ---
int cmd_type;                             // Tipo do comando
void *cmd_args;                           // Argumentos do comando
unsigned int seq_send = -1, seq_recv = 0; // Sequencialização

void client_init()
{
    printf("Creating a socket...\n");
    socket_fd = rawsocket_connection("lo", &addr);
    printf("Socket (fd=%i) created successfully!\n\n", socket_fd);

    addr_len = sizeof(addr);

    printf("********************************\n");
    printf(" Welcome to the Remote C Editor\n");
    printf("********************************\n\n");
}

void read_client_input()
{
    printf("[Client] > ");
    while ((cmd_type = read_client_command()) < 0)
    {
        fprintf(stderr, "error: command not found\n");
        printf("[Client] > ");
    }
    cmd_args = read_client_args();
}

int read_client_command()
{
    byte_t new_cmd[BUF_SIZE];
    scanf("%s", new_cmd);

    if (!strcmp("cd", (const char *)new_cmd))
        return CD_TYPE;
    else if (!strcmp("lcd", (const char *)new_cmd))
        return LCD_TYPE;
    else if (!strcmp("ls", (const char *)new_cmd))
        return LS_TYPE;
    else if (!strcmp("lls", (const char *)new_cmd))
        return LLS_TYPE;

    while (getchar() != '\n'); // Limpa stdin
    return -1;
}

void *read_client_args()
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

int client_standalone_commands()
{
    if (cmd_type == LCD_TYPE)
    {
        if (chdir((const char *)cmd_args))
        {
            if (errno == EACCES)
                fprintf(stderr, "error: permission denied\n");
            else
                fprintf(stderr, "error: directory does not exist\n");
        }
        return 1;
    }
    else if (cmd_type == LLS_TYPE)
    {
        byte_t buf[MSG_SIZE + 1];

        FILE *arq = popen("ls", "r");
        if (!arq)
        {
            fprintf(stderr, "error: popen\n");
            exit(1);
        }

        while (fgets((char *)buf, MSG_SIZE, arq))
            printf("%s", buf);

        fclose(arq);

        return 1;
    }
    return 0;
}

void client_command_kermit_pckt(kermit_pckt_t *kpckt)
{
    seq_send++;
    switch (cmd_type)
    {
    case CD_TYPE:
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, cmd_type, cmd_args, 1,
                        strlen((const char *)cmd_args));
        free(cmd_args);
        cmd_args = NULL;
        break;
    case LS_TYPE:
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, cmd_type, cmd_args, 0, 0);
        break;
    default:
        break;
    }
}

void send_kpckt_to_server(kermit_pckt_t *kpckt)
{
    int ret = sendto_rawsocket(socket_fd, kpckt, sizeof(*kpckt), &addr, addr_len);
    if (ret < 0)
    {
        fprintf(stderr, "error: package not sent to raw socket\n");
        client_close();
        exit(ERROR_CODE);
    }
    else if (ret == 0)
    {
        fprintf(stderr, "end of connection");
        client_close();
        exit(ERROR_CODE);
    }
}

int recv_kpckt_from_server(kermit_pckt_t *kpckt)
{
    double send_time = timestamp();
    while ((timestamp() - send_time) < TIMEOUT)
    {
        int ret = recvfrom_rawsocket(socket_fd, kpckt, sizeof(*kpckt), &addr, &addr_len);
        if (ret > 0)
        {
            if (valid_kpckt_for_client(kpckt))
            {
                if (kpckt->seq == seq_recv) // Evita mensagens duplicadas em sequência
                {
                    seq_recv = (kpckt->seq + 1) % MAX_SEQ;
                    return 0;
                }
            }
        }
    }
    return 1;
}

int valid_kpckt_for_client(kermit_pckt_t *kpckt)
{
    if (valid_kermit_pckt(kpckt))
        return (kpckt->origin_addr == SER_ADDR && kpckt->dest_addr == CLI_ADDR);
    return 0;
}

int kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    byte_t parity = verify_parity(kpckt_recv);

    if (!parity)
    {
        if (kpckt_recv->type == ACK_TYPE)
            return 0;
        else if (kpckt_recv->type == ERROR_TYPE)
        {
            int *value = (int *)kpckt_recv->msg;
            switch (*value)
            {
            case NO_PERM:
                fprintf(stderr, "[Client] error: permission denied\n");
                break;
            case NO_DIR:
                fprintf(stderr, "[Client] error: directory does not exist\n");
                break;
            default:
                break;
            }
            return 0;
        }
        else if (kpckt_recv->type == LINHA_CONTENT_TYPE ||
                 kpckt_recv->type == LS_CONTENT_TYPE ||
                 kpckt_recv->type == ARQ_CONTENT_TYPE)
        {
            printf("%s", kpckt_recv->msg);
        }

        if (kpckt_recv->type != NACK_TYPE)
        {
            seq_send++;
            gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
        }
    }
    else // Mensagem veio corrompida
    {
        seq_send++;
        gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
    }
    return 1;
}

void client_close()
{
    close(socket_fd);
}