#include "server.h"

// --- Estrutura para conexão raw socket ---
int socket_fd;

// --- Variáveis de controle ---
int is_from_nack = 0;
unsigned int seq_send = 0, seq_recv = 0;
byte_t buf[MSG_SIZE + 1];
FILE *arq = NULL;

void server_init()
{
    printf("Initializing server...\n");
    printf("Creating a socket...\n");
    socket_fd = rawsocket_connection("lo");
    printf("Socket (fd=%i) created successfully!\n\n", socket_fd);

    printf("Server initialized successfully!\n");
}

void wait_kpckt_from_client(kermit_pckt_t *kpckt)
{
    while (1)
    {
        int ret = recvfrom_rawsocket(socket_fd, kpckt, sizeof(*kpckt));
        if (ret > 0)
        {
            if (valid_kpckt_for_server(kpckt))
            {
                if (kpckt->seq == seq_recv)
                {
                    seq_recv = (kpckt->seq + 1) % MAX_SEQ;
                    break;
                }
                if (is_from_nack)
                {
                    is_from_nack = 0;
                    break;
                }
            }
        }
    }
}

int recv_kpckt_from_client(kermit_pckt_t *kpckt)
{
    double send_time = timestamp();
    while ((timestamp() - send_time) < TIMEOUT)
    {
        int ret = recvfrom_rawsocket(socket_fd, kpckt, sizeof(*kpckt));
        if (ret > 0)
        {
            if (valid_kpckt_for_server(kpckt))
            {
                if (kpckt->seq == seq_recv)
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

void server_kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    byte_t parity = verify_parity(kpckt_recv);

    if (!parity)
    {
        switch (kpckt_recv->type)
        {
        case CD_TYPE:
            cd_handler(kpckt_recv, kpckt_send);
            send_kpckt_to_client(kpckt_send);
            break;
        case LS_TYPE:
            ls_handler(kpckt_recv, kpckt_send);
            while (1)
            {
                send_kpckt_to_client(kpckt_send);

                if (kpckt_send->type == ACK_TYPE && kpckt_recv->type == ACK_TYPE)
                    break;

                printf("[Server] Send: ");
                print_kermit_pckt(kpckt_send);

                int is_timeout = recv_kpckt_from_client(kpckt_recv);
                if (is_timeout)
                {
                    fprintf(stderr, "[Server] timeout: sending back...\n");
                    continue;
                }

                printf("[Server] Received: ");
                print_kermit_pckt(kpckt_recv);

                parity = verify_parity(kpckt_recv);
                if (!parity)
                    ls_handler(kpckt_recv, kpckt_send);
                else
                {
                    is_from_nack = 1;
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
                    seq_send++;
                }
            }
            break;
        case VER_TYPE:
            if (!access((const char *)kpckt_recv->msg, R_OK))
            {
                ver_handler(kpckt_recv, kpckt_send);
                while (1)
                {
                    send_kpckt_to_client(kpckt_send);

                    if (kpckt_send->type == ACK_TYPE && kpckt_recv->type == ACK_TYPE)
                        break;

                    printf("[Server] Send: ");
                    print_kermit_pckt(kpckt_send);

                    int is_timeout = recv_kpckt_from_client(kpckt_recv);
                    if (is_timeout)
                    {
                        fprintf(stderr, "[Server] timeout: sending back...\n");
                        continue;
                    }

                    printf("[Server] Received: ");
                    print_kermit_pckt(kpckt_recv);

                    parity = verify_parity(kpckt_recv);
                    if (!parity)
                        ver_handler(kpckt_recv, kpckt_send);
                    else
                    {
                        is_from_nack = 1;
                        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
                        seq_send++;
                    }
                }
            }
            else
            {
                int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                                ERROR_TYPE, &error_code, 1, sizeof(int));
                send_kpckt_to_client(kpckt_send);
                seq_send++;
            }
            break;
        case LINHA_TYPE:
            if (!access((const char *)kpckt_recv->msg, R_OK))
            {
                linha_handler(kpckt_recv, kpckt_send);
                while (1)
                {
                    send_kpckt_to_client(kpckt_send);

                    if (kpckt_send->type == ACK_TYPE && kpckt_recv->type == ACK_TYPE)
                        break;

                    printf("[Server] Send: ");
                    print_kermit_pckt(kpckt_send);

                    int is_timeout = recv_kpckt_from_client(kpckt_recv);
                    if (is_timeout)
                    {
                        fprintf(stderr, "[Server] timeout: sending back...\n");
                        continue;
                    }

                    printf("[Server] Received: ");
                    print_kermit_pckt(kpckt_recv);

                    parity = verify_parity(kpckt_recv);
                    if (!parity)
                        linha_handler(kpckt_recv, kpckt_send);
                    else
                    {
                        is_from_nack = 1;
                        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
                        seq_send++;
                    }
                }
            }
            else
            {
                int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                                ERROR_TYPE, &error_code, 1, sizeof(int));
                send_kpckt_to_client(kpckt_send);
                seq_send++;
            }
            break;
        case LINHAS_TYPE:
            if (!access((const char *)kpckt_recv->msg, R_OK))
            {
                linhas_handler(kpckt_recv, kpckt_send);
                while (1)
                {
                    send_kpckt_to_client(kpckt_send);

                    if (kpckt_send->type == ACK_TYPE && kpckt_recv->type == ACK_TYPE)
                        break;

                    printf("[Server] Send: ");
                    print_kermit_pckt(kpckt_send);

                    int is_timeout = recv_kpckt_from_client(kpckt_recv);
                    if (is_timeout)
                    {
                        fprintf(stderr, "[Server] timeout: sending back...\n");
                        continue;
                    }

                    printf("[Server] Received: ");
                    print_kermit_pckt(kpckt_recv);

                    parity = verify_parity(kpckt_recv);
                    if (!parity)
                        linhas_handler(kpckt_recv, kpckt_send);
                    else
                    {
                        is_from_nack = 1;
                        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
                        seq_send++;
                    }
                }
            }
            else
            {
                int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                                ERROR_TYPE, &error_code, 1, sizeof(int));
                send_kpckt_to_client(kpckt_send);
                seq_send++;
            }
            break;
        case EDIT_TYPE:
            if (!access((const char *)kpckt_recv->msg, R_OK))
            {
                edit_handler(kpckt_recv, kpckt_send);
                while (1)
                {
                    send_kpckt_to_client(kpckt_send);

                    if (kpckt_send->type == ACK_TYPE && kpckt_recv->type == END_TRANS_TYPE)
                        break;

                    printf("[Server] Send: ");
                    print_kermit_pckt(kpckt_send);

                    int is_timeout = recv_kpckt_from_client(kpckt_recv);
                    if (is_timeout)
                    {
                        fprintf(stderr, "[Server] timeout: sending back...\n");
                        continue;
                    }

                    printf("[Server] Received: ");
                    print_kermit_pckt(kpckt_recv);

                    parity = verify_parity(kpckt_recv);
                    if (!parity)
                        edit_handler(kpckt_recv, kpckt_send);
                    else
                    {
                        is_from_nack = 1;
                        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
                        seq_send++;
                    }
                }
            }
            else
            {
                int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                                ERROR_TYPE, &error_code, 1, sizeof(int));
                send_kpckt_to_client(kpckt_send);
                seq_send++;
            }
            break;
        case COMPILAR_TYPE:
            if (!access((const char *)kpckt_recv->msg, R_OK))
            {
                compilar_handler(kpckt_recv, kpckt_send);
                while (1)
                {
                    send_kpckt_to_client(kpckt_send);

                    if (kpckt_send->type == ACK_TYPE && kpckt_recv->type == ACK_TYPE)
                        break;

                    printf("[Server] Send: ");
                    print_kermit_pckt(kpckt_send);

                    int is_timeout = recv_kpckt_from_client(kpckt_recv);
                    if (is_timeout)
                    {
                        fprintf(stderr, "[Server] timeout: sending back...\n");
                        continue;
                    }

                    printf("[Server] Received: ");
                    print_kermit_pckt(kpckt_recv);

                    parity = verify_parity(kpckt_recv);
                    if (!parity)
                        compilar_handler(kpckt_recv, kpckt_send);
                    else
                    {
                        is_from_nack = 1;
                        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
                        seq_send++;
                    }
                }
            }
            else
            {
                int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                                ERROR_TYPE, &error_code, 1, sizeof(int));
                send_kpckt_to_client(kpckt_send);
                seq_send++;
            }
            break;
        case NACK_TYPE:
            send_kpckt_to_client(kpckt_send);
            break;
        }
    }
    else
    {
        is_from_nack = 1;
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
        send_kpckt_to_client(kpckt_send);
        seq_send++;
    }
}

void send_kpckt_to_client(kermit_pckt_t *kpckt)
{
    int ret = sendto_rawsocket(socket_fd, kpckt, sizeof(*kpckt));
    if (ret < 0)
    {
        fprintf(stderr, "error: package not sent to raw socket\n");
        server_close();
        exit(ERROR_CODE);
    }
    else if (ret == 0)
    {
        fprintf(stderr, "end of connection");
        server_close();
        exit(ERROR_CODE);
    }
}

int valid_kpckt_for_server(kermit_pckt_t *kpckt)
{
    if (valid_kermit_pckt(kpckt))
        return (kpckt->origin_addr == CLI_ADDR && kpckt->dest_addr == SER_ADDR);
    return 0;
}

void server_close()
{
    close(socket_fd);
}

void cd_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (!chdir((const char *)kpckt_recv->msg))
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        int error_code = (errno == EACCES ? NO_PERM : NO_DIR);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                        ERROR_TYPE, &error_code, 1, sizeof(int));
    }
    seq_send++;
}

void ls_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        switch (kpckt_recv->type)
        {
        case LS_TYPE:
            arq = popen("ls", "r");
            if (!arq)
            {
                fprintf(stderr, "error: popen\n");
                exit(1);
            }
            fgets((char *)buf, MSG_SIZE + 1, arq);

            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, LS_CONTENT_TYPE,
                            buf, 1, strlen((const char *)buf));
            break;
        case ACK_TYPE:
            if (!fgets((char *)buf, MSG_SIZE + 1, arq))
            {
                memset(buf, 0, MSG_SIZE + 1);
                fclose(arq);
                arq = NULL;

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
            }
            else
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, LS_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));
            break;
        default:
            break;
        }
    }

    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void ver_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        byte_t cmd_cat[BUF_SIZE];

        switch (kpckt_recv->type)
        {
        case VER_TYPE:
            memset(cmd_cat, 0, BUF_SIZE);

            sprintf((char *)cmd_cat, "cat -n %s", kpckt_recv->msg);

            arq = popen((const char *)cmd_cat, "r");
            if (!arq)
            {
                fprintf(stderr, "error: popen\n");
                exit(1);
            }
            fgets((char *)buf, MSG_SIZE + 1, arq);

            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                            buf, 1, strlen((const char *)buf));
            break;
        case ACK_TYPE:
            if (!fgets((char *)buf, MSG_SIZE + 1, arq))
            {
                memset(buf, 0, MSG_SIZE + 1);
                fclose(arq);
                arq = NULL;

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
            }
            else
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));
            break;
        default:
            break;
        }
    }

    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void linha_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        byte_t cmd_sed[BUF_SIZE];

        switch (kpckt_recv->type)
        {
        case LINHA_TYPE:
            memcpy(buf, kpckt_recv->msg, kpckt_recv->size);
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            break;
        case LINHA_CONTENT_TYPE:
            memset(cmd_sed, 0, BUF_SIZE);

            int *line = (int *)(kpckt_recv->msg);
            sprintf((char *)cmd_sed, "sed '%iq;d' %s", *line, buf);

            memset(buf, 0, MSG_SIZE + 1);
            arq = popen((const char *)cmd_sed, "r");
            if (!arq)
            {
                fprintf(stderr, "error: popen\n");
                exit(1);
            }
            fgets((char *)buf, MSG_SIZE + 1, arq);

            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                            buf, 1, strlen((const char *)buf));

            break;
        case ACK_TYPE:
            if (!fgets((char *)buf, MSG_SIZE + 1, arq))
            {
                memset(buf, 0, MSG_SIZE + 1);
                fclose(arq);
                arq = NULL;

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
            }
            else
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));
            break;
        default:
            break;
        }
    }
    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void linhas_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        byte_t cmd_sed[BUF_SIZE];

        switch (kpckt_recv->type)
        {
        case LINHAS_TYPE:
            memcpy(buf, kpckt_recv->msg, kpckt_recv->size);
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            break;
        case LINHA_CONTENT_TYPE:
            memset(cmd_sed, 0, BUF_SIZE);

            int *init_line = (int *)(kpckt_recv->msg);
            int *last_line = (int *)(kpckt_recv->msg + sizeof(int));

            sprintf((char *)cmd_sed, "sed -n '%i,%ip;%iq' %s", *init_line, *last_line,
                    (*last_line) + 1, buf);

            memset(buf, 0, MSG_SIZE + 1);
            arq = popen((const char *)cmd_sed, "r");
            if (!arq)
            {
                fprintf(stderr, "error: popen\n");
                exit(1);
            }

            fgets((char *)buf, MSG_SIZE + 1, arq);

            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                            buf, 1, strlen((const char *)buf));

            break;
        case ACK_TYPE:
            if (!fgets((char *)buf, MSG_SIZE + 1, arq))
            {
                memset(buf, 0, MSG_SIZE + 1);
                fclose(arq);
                arq = NULL;

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
            }
            else
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));
            break;
        default:
            break;
        }
    }
    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void edit_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    static byte_t buf_arq[BUF_SIZE];
    static int line;
    static byte_t buf_line[BUF_SIZE];

    if (kpckt_recv->type == END_TRANS_TYPE)
    {
        byte_t cmd_sed[BUF_SIZE * 3];
        memset(cmd_sed, 0, BUF_SIZE * 3);

        sprintf((char *)cmd_sed, "sed -i '%is/.*/%s/' %s", line, buf_line, buf_arq);

        arq = popen((const char *)cmd_sed, "r");
        if (!arq)
        {
            fprintf(stderr, "error: popen\n");
            exit(1);
        }
        fclose(arq);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    }
    else
    {
        switch (kpckt_recv->type)
        {
        case EDIT_TYPE:
            memset(buf_arq, 0, BUF_SIZE);
            memset(buf_line, 0, BUF_SIZE);
            memcpy(buf_arq, kpckt_recv->msg, kpckt_recv->size);
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            break;
        case LINHA_TYPE:
            memcpy(&line, kpckt_recv->msg, kpckt_recv->size);
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            break;
        case ARQ_CONTENT_TYPE:
            memcpy(buf_line + strlen((const char *)buf_line), kpckt_recv->msg, kpckt_recv->size);
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            break;
        default:
            break;
        }
    }
    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void compilar_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    static byte_t buf_arq[BUF_SIZE];
    static byte_t buf_opt[BUF_SIZE];
    byte_t buf_feedback[MSG_SIZE + 1];

    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else if (kpckt_recv->type == END_TRANS_TYPE)
    {
        byte_t cmd_gcc[BUF_SIZE * 3];
        memset(cmd_gcc, 0, BUF_SIZE * 3);

        sprintf((char *)cmd_gcc, "gcc %s %s 2>&1 | cat", buf_opt, buf_arq);

        arq = popen((const char *)cmd_gcc, "r");
        if (!arq)
        {
            fprintf(stderr, "error: popen\n");
            exit(1);
        }

        fgets((char *)buf_feedback, MSG_SIZE + 1, arq);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                        buf_feedback, 1, strlen((const char *)buf_feedback));
    }
    else
    {
        switch (kpckt_recv->type)
        {
        case COMPILAR_TYPE:
            memset(buf_arq, 0, BUF_SIZE);
            memset(buf_opt, 0, BUF_SIZE);
            memcpy(buf_arq, kpckt_recv->msg, kpckt_recv->size);
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            break;
        case ARQ_CONTENT_TYPE:
            memcpy(buf_opt + strlen((const char *)buf_opt), kpckt_recv->msg, kpckt_recv->size);
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            break;
        case ACK_TYPE:
            if (!fgets((char *)buf_feedback, MSG_SIZE + 1, arq))
            {
                fclose(arq);
                arq = NULL;

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
            }
            else
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                buf_feedback, 1, strlen((const char *)buf_feedback));
            break;
        default:
            break;
        }
    }

    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}
