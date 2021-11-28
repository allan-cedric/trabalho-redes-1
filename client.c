#include "client.h"

// --- Estrutura para conexão raw socket ---
int socket_fd;

// --- Variáveis de controle ---
int is_from_nack = 0;
int cmd_type;              // Tipo do comando
void **cmd_args;           // Argumentos do comando
unsigned int seq_recv = 0; // Sequencialização
int seq_send = -1;
unsigned int buf_ptr = 0;

void clean_stdin()
{
    while (getchar() != '\n')
        ;
}

void client_init()
{
    printf("Creating a socket...\n");
    socket_fd = rawsocket_connection("lo");
    printf("Socket (fd=%i) created successfully!\n\n", socket_fd);

    printf("********************************\n");
    printf(" Welcome to the Remote C Editor\n");
    printf("********************************\n\n");
}

void read_client_input()
{
    while (1)
    {
        printf("[Client] > ");
        if ((cmd_type = read_client_command()) < 0)
        {
            fprintf(stderr, "error: command not found\n");
            continue;
        }
        if (read_client_args())
            fprintf(stderr, "error: bad arguments\n");
        else
            break;
    }
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
    else if (!strcmp("ver", (const char *)new_cmd))
        return VER_TYPE;
    else if (!strcmp("linha", (const char *)new_cmd))
        return LINHA_TYPE;
    else if (!strcmp("linhas", (const char *)new_cmd))
        return LINHAS_TYPE;
    else if (!strcmp("edit", (const char *)new_cmd))
        return EDIT_TYPE;
    else if (!strcmp("compilar", (const char *)new_cmd))
        return COMPILAR_TYPE;

    clean_stdin();

    return -1;
}

int read_client_args()
{
    int ret;
    byte_t str[BUF_SIZE];
    cmd_args = NULL;
    switch (cmd_type)
    {
    case CD_TYPE:
    case LCD_TYPE:
    case VER_TYPE:
        cmd_args = malloc(sizeof(void *));
        cmd_args[0] = malloc(BUF_SIZE);

        ret = scanf("%s", (byte_t *)cmd_args[0]);
        clean_stdin();
        if (ret < 1)
        {
            free(cmd_args[0]);
            cmd_args[0] = NULL;

            free(cmd_args);
            cmd_args = NULL;

            return -1;
        }

        break;
    case LINHA_TYPE:
        cmd_args = malloc(sizeof(void *) * 2);
        cmd_args[0] = malloc(BUF_SIZE);
        cmd_args[1] = malloc(sizeof(int));

        ret = scanf("%i %s", (int *)cmd_args[1], (byte_t *)cmd_args[0]);
        clean_stdin();
        if (ret < 2)
        {
            free(cmd_args[0]);
            cmd_args[0] = NULL;

            free(cmd_args[1]);
            cmd_args[1] = NULL;

            free(cmd_args);
            cmd_args = NULL;

            return -1;
        }

        break;
    case LINHAS_TYPE:
        cmd_args = malloc(sizeof(void *) * 2);
        cmd_args[0] = malloc(BUF_SIZE);
        cmd_args[1] = malloc(sizeof(int) * 2);

        ret = scanf("%i %i %s", (int *)cmd_args[1], (int *)(cmd_args[1] + sizeof(int)),
                    (byte_t *)cmd_args[0]);
        clean_stdin();
        if (ret < 3)
        {
            free(cmd_args[0]);
            cmd_args[0] = NULL;

            free(cmd_args[1]);
            cmd_args[1] = NULL;

            free(cmd_args);
            cmd_args = NULL;

            return -1;
        }
        break;
    case EDIT_TYPE:
        cmd_args = malloc(sizeof(void *) * 3);
        cmd_args[0] = malloc(BUF_SIZE);
        cmd_args[1] = malloc(sizeof(int));
        cmd_args[2] = malloc(BUF_SIZE);

        ret = scanf("%i %s %[^\n]s", (int *)cmd_args[1], (byte_t *)cmd_args[0], str);
        memcpy(cmd_args[2], str + sizeof(byte_t), strlen((const char *)str) - 2);
        clean_stdin();
        if (ret < 3 || str[0] != '"' || str[strlen((const char *)str) - 1] != '"')
        {
            free(cmd_args[0]);
            cmd_args[0] = NULL;

            free(cmd_args[1]);
            cmd_args[1] = NULL;

            free(cmd_args[2]);
            cmd_args[2] = NULL;

            free(cmd_args);
            cmd_args = NULL;

            return -1;
        }
        break;
    case COMPILAR_TYPE:
        cmd_args = malloc(sizeof(void *) * 2);
        cmd_args[0] = malloc(BUF_SIZE);
        cmd_args[1] = malloc(BUF_SIZE);

        memset(cmd_args[0], 0, BUF_SIZE);
        memset(cmd_args[1], 0, BUF_SIZE);

        ret = scanf("%[^\n]s", str);
        if (ret < 1)
        {
            free(cmd_args[0]);
            cmd_args[0] = NULL;

            free(cmd_args[1]);
            cmd_args[1] = NULL;

            free(cmd_args);
            cmd_args = NULL;

            return -1;
        }else
        {
            byte_t *last_whitespace = NULL;
            for(int i = 0; i < strlen((const char *)str); i++)
            {
                if(str[i] <= 32)
                    last_whitespace = str + i;
            }

            memcpy(cmd_args[0], last_whitespace + 1, strlen((const char *)(last_whitespace + 1)));
            memcpy(cmd_args[1], str, strlen((const char *)str) - strlen((const char *)last_whitespace));
        }

        break;
    default:
        break;
    }
    return 0;
}

int client_standalone_commands()
{
    if (cmd_type == LCD_TYPE)
    {
        if (chdir((const char *)cmd_args[0]))
        {
            if (errno == EACCES)
                fprintf(stderr, "error: permission denied\n");
            else
                fprintf(stderr, "error: directory does not exist\n");
        }
        free(cmd_args[0]);
        cmd_args[0] = NULL;
        free(cmd_args);
        cmd_args = NULL;
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

        while (fgets((char *)buf, MSG_SIZE + 1, arq))
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
    case VER_TYPE:
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, cmd_type, cmd_args[0], 1,
                        strlen((const char *)cmd_args[0]));
        free(cmd_args[0]);
        cmd_args[0] = NULL;
        free(cmd_args);
        cmd_args = NULL;
        break;
    case LS_TYPE:
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, cmd_type, NULL, 0, 0);
        break;
    case LINHA_TYPE:
    case LINHAS_TYPE:
    case EDIT_TYPE:
    case COMPILAR_TYPE:
        buf_ptr = 0;
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, cmd_type, cmd_args[0], 1,
                        strlen((const char *)cmd_args[0]));
        free(cmd_args[0]);
        cmd_args[0] = NULL;
        break;
    default:
        break;
    }
}

void send_kpckt_to_server(kermit_pckt_t *kpckt)
{
    int ret = sendto_rawsocket(socket_fd, kpckt, sizeof(*kpckt));
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
        int ret = recvfrom_rawsocket(socket_fd, kpckt, sizeof(*kpckt));
        if (ret > 0)
        {
            if (valid_kpckt_for_client(kpckt))
            {
                if (kpckt->seq == seq_recv) // Evita mensagens duplicadas em sequência
                {
                    seq_recv = (kpckt->seq + 1) % MAX_SEQ;
                    return 0;
                }
                if (is_from_nack)
                {
                    is_from_nack = 0;
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
        {
            switch (cmd_type)
            {
            case LINHA_CONTENT_TYPE:
            case VER_TYPE:
                printf("\n");
                break;
            case LINHA_TYPE:
                seq_send++;
                gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, LINHA_CONTENT_TYPE,
                                cmd_args[1], 1, sizeof(int));
                free(cmd_args[1]);
                cmd_args[1] = NULL;
                free(cmd_args);
                cmd_args = NULL;

                cmd_type = LINHA_CONTENT_TYPE;
                return 1;
            case LINHAS_TYPE:
                seq_send++;
                gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, LINHA_CONTENT_TYPE,
                                cmd_args[1], 2, sizeof(int));
                free(cmd_args[1]);
                cmd_args[1] = NULL;
                free(cmd_args);
                cmd_args = NULL;

                cmd_type = LINHA_CONTENT_TYPE;
                return 1;
            case EDIT_TYPE:
                seq_send++;
                gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, LINHA_TYPE,
                                cmd_args[1], 1, sizeof(int));
                free(cmd_args[1]);
                cmd_args[1] = NULL;

                cmd_type = BUF_TYPE;
                return 1;
                break;
            case BUF_TYPE:
                seq_send++;
                if (buf_ptr < strlen((const char *)cmd_args[2]))
                {
                    gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                    cmd_args[2] + buf_ptr, 1, strlen((const char *)(cmd_args[2] + buf_ptr)));
                    buf_ptr += MSG_SIZE;
                }
                else
                {
                    gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);

                    free(cmd_args[2]);
                    cmd_args[2] = NULL;
                    free(cmd_args);
                    cmd_args = NULL;

                    cmd_type = END_TRANS_TYPE;
                }
                return 1;
                break;
            case COMPILAR_TYPE:
                seq_send++;
                if (buf_ptr < strlen((const char *)cmd_args[1]))
                {
                    gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                    cmd_args[1] + buf_ptr, 1, strlen((const char *)(cmd_args[1] + buf_ptr)));
                    buf_ptr += MSG_SIZE;
                }
                else
                {
                    gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);

                    free(cmd_args[1]);
                    cmd_args[1] = NULL;
                    free(cmd_args);
                    cmd_args = NULL;

                    cmd_type = END_TRANS_TYPE;
                }
                return 1;
                break;
            default:
                break;
            }
            return 0;
        }
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
            case NO_ARQ:
                fprintf(stderr, "[Client] error: file does not exist\n");
                break;
            default:
                break;
            }
            return 0;
        }
        else if (kpckt_recv->type == LS_CONTENT_TYPE || kpckt_recv->type == ARQ_CONTENT_TYPE)
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
        is_from_nack = 1;
        seq_send++;
        gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
    }
    return 1;
}

void client_close()
{
    close(socket_fd);
}