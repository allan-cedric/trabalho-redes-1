#include "server.h"

// --- Estrutura para conexão raw socket ---
struct sockaddr_ll addr;
socklen_t addr_len;
int socket_fd;

// --- Variáveis de controle ---
unsigned int seq_send = 0, seq_recv = 0;
void *args;
int error_code, cmd_type, type;
byte_t buf[MSG_SIZE + 1];
FILE *arq = NULL;

void server_init()
{
    printf("Initializing server...\n");
    printf("Creating a socket...\n");
    socket_fd = rawsocket_connection("lo", &addr);
    printf("Socket (fd=%i) created successfully!\n\n", socket_fd);

    addr_len = sizeof(addr);

    printf("Server initialized successfully!\n");
}

void wait_kpckt(kermit_pckt_t *kpckt)
{
    while (1)
    {
        if (recvfrom_rawsocket(socket_fd, kpckt, sizeof(*kpckt), &addr, &addr_len) > 0)
        {
            if (valid_kermit_pckt_for_server(kpckt))
            {
                if (kpckt->seq == seq_recv)
                {
                    seq_recv = (kpckt->seq + 1) % MAX_SEQ;
                    break;
                }
            }
        }
    }
}

void kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    byte_t parity = verify_parity(kpckt_recv);

    if (!parity)
    {
        type = kpckt_recv->type;
        if (type == ACK_TYPE && arq)
        {
            if (!fgets((char *)buf, MSG_SIZE, arq))
            {
                memset(buf, 0, MSG_SIZE + 1);
                type = END_TRANS_TYPE;
                fclose(arq);
                arq = NULL;
            }
        }

        switch (type)
        {
        case CD_TYPE:
            cmd_type = type;
            if (!chdir((const char *)kpckt_recv->msg)) // "ACK"
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
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

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
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
                fprintf(stderr, "error: popen\n");
                exit(1);
            }
            fgets((char *)buf, MSG_SIZE, arq);

            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, LS_CONTENT_TYPE,
                            buf, 1, strlen((const char *)buf));
            break;
        case ACK_TYPE:
            switch (cmd_type)
            {
            case LS_TYPE:
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, LS_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));
                break;
            case END_TRANS_TYPE:
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
            default:
                break;
            }
            break;
        case END_TRANS_TYPE:
            cmd_type = type;
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
            break;
        default:
            break;
        }

        if (type != NACK_TYPE)
            seq_send++;
    }
    else
    {
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
        seq_send++;
    }
}

void send_kpckt(kermit_pckt_t *kpckt)
{
    int ret = sendto_rawsocket(socket_fd, kpckt, sizeof(*kpckt), &addr, addr_len);
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

int valid_kermit_pckt_for_server(kermit_pckt_t *kpckt)
{
    if (valid_kermit_pckt(kpckt))
        return (kpckt->origin_addr == CLI_ADDR && kpckt->dest_addr == SER_ADDR);
    return 0;
}

void server_close()
{
    close(socket_fd);
}