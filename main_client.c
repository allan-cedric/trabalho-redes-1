#include "client.h"

int main()
{
    struct sockaddr_ll addr;

    printf("Creating a socket...\n");
    int socket_fd = rawsocket_connection("lo", &addr);
    printf("Socket (fd=%i) created successfully!\n\n", socket_fd);

    socklen_t addr_len = sizeof(addr);
    kermit_pckt_t kermit_pckt, kermit_pckt_recv;

    printf("********************************\n");
    printf(" Welcome to the Remote C Editor\n");
    printf("********************************\n\n");

    int cmd_type;
    unsigned int seq_send = 0, seq_recv = 0;
    while (1)
    {
        // --- Etapa de envio (Cliente) ---
        printf("[Client] > ");

        // Input do comando
        while ((cmd_type = read_client_command()) < 0)
        {
            fprintf(stderr, "error: command not found\n");
            printf("[Client] > ");
        }

        // Input dos argumentos
        void *cmd_args = read_client_args(cmd_type);

        if (cmd_type == LCD_TYPE)
        {
            if (chdir((const char *)cmd_args))
            {
                if (errno == EACCES)
                    fprintf(stderr, "error: permission denied\n");
                else
                    fprintf(stderr, "error: directory does not exist\n");
            }
            continue;
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

            continue;
        }

        // Preparação do pacote kermit
        switch (cmd_type)
        {
        case CD_TYPE:
            gen_kermit_pckt(&kermit_pckt, SER_ADDR, CLI_ADDR, seq_send, cmd_type, cmd_args, 1,
                            strlen((const char *)cmd_args));
            free(cmd_args);
            cmd_args = NULL;
            break;
        case LS_TYPE:
            gen_kermit_pckt(&kermit_pckt, SER_ADDR, CLI_ADDR, seq_send, cmd_type, cmd_args, 0, 0);
            break;
        default:
            break;
        }

        // Enviar o pacote + receber resposta
        int is_timeout = 1;
        while (1)
        {
            // printf("\n[Client] Send: ");
            // print_kermit_pckt(&kermit_pckt);

            double init_time = timestamp();
            int ret = sendto_rawsocket(socket_fd, &kermit_pckt, sizeof(kermit_pckt), &addr, addr_len);
            if (ret < 0)
            {
                fprintf(stderr, "error: package not sent to raw socket\n");
                close(socket_fd);
                exit(ERROR_CODE);
            }
            else if (ret == 0)
            {
                fprintf(stderr, "end of connection");
                close(socket_fd);
                exit(ERROR_CODE);
            }

            // Espera uma resposta até o timeout
            while ((timestamp() - init_time) < TIMEOUT)
            {
                ret = recvfrom_rawsocket(socket_fd, &kermit_pckt_recv,
                                         sizeof(kermit_pckt_recv), &addr, &addr_len);
                if (ret > 0)
                {
                    if (valid_kermit_pckt_for_cli(&kermit_pckt_recv))
                    {
                        if (kermit_pckt_recv.seq == seq_recv) // Evita mensagens duplicadas em sequência
                        {
                            seq_recv = (kermit_pckt_recv.seq + 1) % MAX_SEQ;
                            is_timeout = 0;
                            break;
                        }
                    }
                }
            }

            // Tratamento de timeout ou de uma resposta do servidor
            if (is_timeout)
                fprintf(stderr, "[Client] timeout: sending back...\n");
            else
            {
                // printf("[Client] Received: ");
                // print_kermit_pckt(&kermit_pckt_recv);

                byte_t parity = verify_parity(&kermit_pckt_recv);

                if (!parity)
                {
                    if (kermit_pckt_recv.type == ACK_TYPE)
                        break;
                    else if (kermit_pckt_recv.type == ERROR_TYPE)
                    {
                        int *value = (int *)kermit_pckt_recv.msg;
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
                        break;
                    }
                    else if (kermit_pckt_recv.type == LINHA_CONTENT_TYPE ||
                             kermit_pckt_recv.type == LS_CONTENT_TYPE ||
                             kermit_pckt_recv.type == ARQ_CONTENT_TYPE)
                    {
                        printf("%s", kermit_pckt_recv.msg);
                    }

                    if (kermit_pckt_recv.type != NACK_TYPE)
                    {
                        seq_send++;
                        gen_kermit_pckt(&kermit_pckt, SER_ADDR, CLI_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                    }
                }
                else // Mensagem veio corrompida
                {
                    seq_send++;
                    gen_kermit_pckt(&kermit_pckt, SER_ADDR, CLI_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
                }
            }
        }
        seq_send++;

        // Tratamento da resposta (ACK, NACK, ERRO, DADOS)
        //      ACK - Fluxo normal
        //      NACK - Retransmite (Enviar o pacote (Loop ?) - Receber resposta (Loop ?))
        //      ERRO - Fluxo normal (Informa o erro)
        //      DADOS - Fluxo normal (Informa os dados)
    }

    close(socket_fd);

    return 0;
}