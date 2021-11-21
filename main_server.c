#include "server.h"

int main()
{
    struct sockaddr_ll addr;

    printf("Initializing server...\n");
    printf("Creating a socket...\n");
    int socket_fd = rawsocket_connection("lo", &addr);
    printf("Socket (fd=%i) created successfully!\n\n", socket_fd);

    socklen_t addr_len = sizeof(addr);
    kermit_pckt_t kermit_pckt, kermit_pckt_recv;

    printf("Server initialized successfully!\n");

    unsigned int seq_send = 0, seq_recv = 0;
    void *args;
    int error_code, cmd_type, type;
    byte_t buf[MSG_SIZE + 1];
    FILE *arq;
    while (1)
    {
        // --- Etapa de recepção ---
        while (1)
        {
            if (recvfrom_rawsocket(socket_fd, &kermit_pckt_recv,
                                   sizeof(kermit_pckt_recv), &addr, &addr_len) > 0)
            {
                if (valid_kermit_pckt_for_ser(&kermit_pckt_recv)) // Evita mensagens duplicadas em sequência
                {
                    if (kermit_pckt_recv.seq == seq_recv)
                    {
                        seq_recv = (kermit_pckt_recv.seq + 1) % MAX_SEQ;
                        break;
                    }
                }
            }
        }

        printf("[Server] Received: ");
        print_kermit_pckt(&kermit_pckt_recv);

        // --- Etapa de resposta ---
        byte_t parity = verify_parity(&kermit_pckt_recv);

        if (!parity)
        {
            type = kermit_pckt_recv.type;
            if (type == ACK_TYPE && arq)
            {
                if (!fgets((char *)buf, MSG_SIZE + 1, arq))
                {
                    type = END_TRANS_TYPE;
                    fclose(arq);
                    arq = NULL;
                }
                else
                    buf[strcspn((const char *)buf, "\n")] = 0;
            }

            switch (type)
            {
            case CD_TYPE:
                cmd_type = type;
                if (!chdir((const char *)kermit_pckt_recv.msg)) // "ACK"
                    gen_kermit_pckt(&kermit_pckt, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                else // Erro
                {
                    error_code = (errno == EACCES ? NO_PERM : NO_DIR);

                    args = malloc(sizeof(int));
                    if (!args)
                    {
                        perror("memory allocation error");
                        exit(ERROR_CODE);
                    }

                    memcpy(args, &error_code, sizeof(int));

                    gen_kermit_pckt(&kermit_pckt, CLI_ADDR, SER_ADDR, seq_send,
                                    ERROR_TYPE, args, 1, sizeof(int));

                    free(args);
                    args = NULL;
                }
                break;
            case LS_TYPE:
                cmd_type = type;
                arq = popen("ls", "r");
                if (!arq)
                {
                    fprintf(stderr, "[Server] error: popen\n");
                    exit(1);
                }
                fgets((char *)buf, MSG_SIZE + 1, arq);
                buf[strcspn((const char *)buf, "\n")] = 0;

                // puts(buf);

                gen_kermit_pckt(&kermit_pckt, CLI_ADDR, SER_ADDR, seq_send, LS_CONTENT_TYPE,
                                buf, strlen((const char *)buf), sizeof(byte_t));
                break;
            case ACK_TYPE:
                switch (cmd_type)
                {
                case LS_TYPE:
                    gen_kermit_pckt(&kermit_pckt, CLI_ADDR, SER_ADDR, seq_send, LS_CONTENT_TYPE,
                                    buf, strlen((const char *)buf), sizeof(byte_t));
                    break;
                case END_TRANS_TYPE:
                    gen_kermit_pckt(&kermit_pckt, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                default:
                    break;
                }
                break;
            case END_TRANS_TYPE:
                cmd_type = type;
                gen_kermit_pckt(&kermit_pckt, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
                break;
            default:
                break;
            }

            printf("[Server] Send: ");
            print_kermit_pckt(&kermit_pckt);

            sendto_rawsocket(socket_fd, &kermit_pckt, sizeof(kermit_pckt), &addr, addr_len);

            if (type != NACK_TYPE)
                seq_send++;
        }
        else
        {
            gen_kermit_pckt(&kermit_pckt, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);

            printf("[Server] Send: ");
            print_kermit_pckt(&kermit_pckt);

            sendto_rawsocket(socket_fd, &kermit_pckt, sizeof(kermit_pckt), &addr, addr_len);

            seq_send++;
        }
    }

    close(socket_fd);

    return 0;
}