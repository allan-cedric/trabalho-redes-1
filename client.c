// Allan Cedric G. B. Alves da Silva - GRR20190351

#include "client.h"

// Descritor de arquivo do raw socket
int socket_fd;

// --- Variáveis de controle ---
int is_from_nack = 0;      // Flag que indica se foi enviado um NACK
void **cmd_args;           // Argumentos de um comando
unsigned int seq_recv = 0; // Sequencialização
int seq_send = 0;
unsigned int buf_ptr = 0; // Ponteiro auxiliar para varrer dados de um buffer

void clean_stdin()
{
    while (getchar() != '\n');
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

int read_client_input()
{
    int cmd_type;
    while (1)
    {
        printf("[Client] > ");
        if ((cmd_type = read_client_command()) < 0)
            fprintf(stderr, "error: command not found\n");
        else if (read_client_args(cmd_type))
            fprintf(stderr, "error: bad arguments\n");
        else
            break;
    }
    return cmd_type;
}

int read_client_command()
{
    byte_t new_cmd[BUF_SIZE];
    memset(new_cmd, 0, BUF_SIZE);

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

int read_client_args(int cmd_type)
{
    int ret;              // Valores de retorno do scanf
    byte_t str[BUF_SIZE]; // String auxiliar para leitura de argumentos
    memset(str, 0, BUF_SIZE);

    cmd_args = NULL;
    switch (cmd_type)
    {
        case CD_TYPE:
        case LCD_TYPE:
        case VER_TYPE:
            cmd_args = malloc(sizeof(void *));
            allocation_test(cmd_args);

            cmd_args[0] = malloc(BUF_SIZE); // Nome do diretório/arquivo
            allocation_test(cmd_args[0]);

            memset(cmd_args[0], 0, BUF_SIZE);

            ret = scanf("%s", (byte_t *)cmd_args[0]);
            clean_stdin();
            if (ret != 1)
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
            allocation_test(cmd_args);

            cmd_args[0] = malloc(BUF_SIZE);    // Nome do arquivo
            allocation_test(cmd_args[0]);

            cmd_args[1] = malloc(sizeof(int)); // Número da linha
            allocation_test(cmd_args[1]);

            memset(cmd_args[0], 0, BUF_SIZE);
            memset(cmd_args[1], 0, sizeof(int));

            ret = scanf("%i %s", (int *)cmd_args[1], (byte_t *)cmd_args[0]);
            clean_stdin();
            if (ret != 2)
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
            allocation_test(cmd_args);

            cmd_args[0] = malloc(BUF_SIZE);        // Nome do arquivo
            allocation_test(cmd_args[0]);

            cmd_args[1] = malloc(sizeof(int) * 2); // Número da linha inicial e da linha final
            allocation_test(cmd_args[1]);

            memset(cmd_args[0], 0, BUF_SIZE);
            memset(cmd_args[1], 0, sizeof(int) * 2);

            ret = scanf("%i %i %s", (int *)cmd_args[1],
                        (int *)(cmd_args[1] + sizeof(int)), (byte_t *)cmd_args[0]);
            clean_stdin();
            if (ret != 3)
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
            allocation_test(cmd_args);

            cmd_args[0] = malloc(BUF_SIZE);    // Nome do arquivo
            allocation_test(cmd_args[0]);

            cmd_args[1] = malloc(sizeof(int)); // Número da linha
            allocation_test(cmd_args[1]);

            cmd_args[2] = malloc(BUF_SIZE);    // Conteúdo textual
            allocation_test(cmd_args[2]);

            memset(cmd_args[0], 0, BUF_SIZE);
            memset(cmd_args[1], 0, sizeof(int));
            memset(cmd_args[2], 0, BUF_SIZE);

            ret = scanf("%i %s %[^\n]s", (int *)cmd_args[1], (byte_t *)cmd_args[0], str);
            clean_stdin();
            if (ret != 3 || str[0] != '"' || str[strlen((const char *)str) - 1] != '"')
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

            // Copia os bytes de str, ignorando a aspa inicial e final
            memcpy(cmd_args[2], str + sizeof(byte_t), strlen((const char *)str) - 2);
            break;
        case COMPILAR_TYPE:
            cmd_args = malloc(sizeof(void *) * 2);
            allocation_test(cmd_args);

            cmd_args[0] = malloc(BUF_SIZE); // Nome do arquivo
            allocation_test(cmd_args[0]);

            cmd_args[1] = malloc(BUF_SIZE); // Opções/Flags
            allocation_test(cmd_args[1]);

            memset(cmd_args[0], 0, BUF_SIZE);
            memset(cmd_args[1], 0, BUF_SIZE);

            ret = scanf("%[^\n]s", str);
            if (ret != 1)
            {
                free(cmd_args[0]);
                cmd_args[0] = NULL;

                free(cmd_args[1]);
                cmd_args[1] = NULL;

                free(cmd_args);
                cmd_args = NULL;

                return -1;
            }
            else
            {
                byte_t *last_whitespace = NULL; // Aponta para o último espaço em branco
                for (int i = 0; i < strlen((const char *)str); i++)
                {
                    if (str[i] <= ' ')
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

int client_standalone_commands(int cmd_type)
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
        byte_t buf[DATA_SIZE + 1];
        memset(buf, 0, DATA_SIZE + 1);

        FILE *arq = popen("ls", "r");
        if (!arq)
        {
            fprintf(stderr, "error: popen\n");
            exit(1);
        }

        while (fgets((char *)buf, DATA_SIZE + 1, arq))
            printf("%s", buf);

        fclose(arq);

        return 1;
    }
    return 0;
}

void client_command_kermit_pckt(kermit_pckt_t *kpckt, int cmd_type)
{
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
    seq_send++;
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
                    seq_recv = (kpckt->seq + 1) % NUM_SEQ;
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

int client_kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send, int *event_type)
{
    byte_t parity = error_detection(kpckt_recv);

    if (!parity)
    {
        if (kpckt_recv->type == ACK_TYPE)
        {
            switch (*event_type)
            {
                case LINHA_TYPE: // Envia o argumento da linha
                    linha_type_handler(kpckt_send, event_type);
                    return 1;
                case LINHAS_TYPE: // Envia o argumento das linhas
                    linhas_type_handler(kpckt_send, event_type);
                    return 1;
                case EDIT_TYPE: // Envia o argumento da linha
                    edit_type_handler(kpckt_send, event_type);
                    return 1;
                case BUF_TYPE: // Envia dados para o servidor
                    buf_type_handler(kpckt_send, event_type);
                    return 1;
                case COMPILAR_TYPE: // Envia as opções/flags do compilador
                    compilar_type_handler(kpckt_send, event_type);
                    return 1;
                default:
                    return 0;
            }
        }
        else if (kpckt_recv->type == ERROR_TYPE)
        {
            int *value = (int *)kpckt_recv->data;
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
                case NO_LINE:
                    fprintf(stderr, "[Client] error: line does not exist\n");
                    break;
                default:
                    break;
            }
            return 0;
        }
        else if (kpckt_recv->type == LS_CONTENT_TYPE || kpckt_recv->type == ARQ_CONTENT_TYPE)
            printf("%s", kpckt_recv->data);

        if (kpckt_recv->type != NACK_TYPE) // Envia um ACK se recebeu algo com sucesso
        {
            gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            seq_send++;
        }
    }
    else // Mensagem veio corrompida
    {
        is_from_nack = 1;
        gen_kermit_pckt(kpckt_send, SER_ADDR, CLI_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
        seq_send++;
    }
    return 1;
}

void linha_type_handler(kermit_pckt_t *kpckt, int *event_type)
{
    gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, LINHA_ARG_TYPE,
                    cmd_args[1], 1, sizeof(int));
    seq_send++;
    
    free(cmd_args[1]);
    cmd_args[1] = NULL;
    free(cmd_args);
    cmd_args = NULL;

    *event_type = LINHA_ARG_TYPE;
}

void linhas_type_handler(kermit_pckt_t *kpckt, int *event_type)
{
    gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, LINHA_ARG_TYPE,
                    cmd_args[1], 2, sizeof(int));
    seq_send++;

    free(cmd_args[1]);
    cmd_args[1] = NULL;
    free(cmd_args);
    cmd_args = NULL;

    *event_type = LINHA_ARG_TYPE;
}

void edit_type_handler(kermit_pckt_t *kpckt, int *event_type)
{
    gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, LINHA_ARG_TYPE,
                    cmd_args[1], 1, sizeof(int));
    seq_send++;

    free(cmd_args[1]);
    cmd_args[1] = NULL;

    *event_type = BUF_TYPE;
}

void buf_type_handler(kermit_pckt_t *kpckt, int *event_type)
{
    if (buf_ptr < strlen((const char *)cmd_args[2]))
    {
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, ARQ_CONTENT_TYPE,
                        cmd_args[2] + buf_ptr, 1, strlen((const char *)(cmd_args[2] + buf_ptr)));
        buf_ptr += DATA_SIZE;
    }
    else
    {
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);

        free(cmd_args[2]);
        cmd_args[2] = NULL;
        free(cmd_args);
        cmd_args = NULL;

        *event_type = END_TRANS_TYPE;
    }
    seq_send++;
}

void compilar_type_handler(kermit_pckt_t *kpckt, int *event_type)
{
    if (buf_ptr < strlen((const char *)cmd_args[1]))
    {
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, ARQ_CONTENT_TYPE,
                        cmd_args[1] + buf_ptr, 1, strlen((const char *)(cmd_args[1] + buf_ptr)));
        buf_ptr += DATA_SIZE;
    }
    else
    {
        gen_kermit_pckt(kpckt, SER_ADDR, CLI_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);

        free(cmd_args[1]);
        cmd_args[1] = NULL;
        free(cmd_args);
        cmd_args = NULL;

        *event_type = END_TRANS_TYPE;
    }
    seq_send++;
}

void client_close()
{
    close(socket_fd);
}