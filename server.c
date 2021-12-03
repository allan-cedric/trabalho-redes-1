// Allan Cedric G. B. Alves da Silva - GRR20190351

#include "server.h"

// Estrutura para conexão raw socket
int socket_fd;

// --- Variáveis de controle ---
int is_from_nack = 0;                   // Indica se foi enviado um NACK
unsigned int timeout_count = 0;         // Conta a quantidade de timeouts consecutivos
seq_t seq = {.recv = 0, .send = 0};     // Sequencialização

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
                if (kpckt->seq == seq.recv)
                {
                    seq.recv++;
                    break;
                }
                if(is_from_nack)
                {
                    is_from_nack = 0;
                    return;
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
                if (kpckt->seq == seq.recv)
                {
                    seq.recv++;
                    timeout_count = 0;
                    return 0;
                }
                if(is_from_nack)
                {
                    is_from_nack = 0;
                    timeout_count = 0;
                    return 0;
                }
            }
        }
    }
    if(timeout_count++ >= TIMEOUT_LIMIT)
    {
        seq.recv++;
        timeout_count = 0;
        return -1;
    }
    return 1;
}

void server_kpckt_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    byte_t parity = error_detection(kpckt_recv);

    if (!parity)
    {
        switch (kpckt_recv->type)
        {
            case CD_TYPE:
                cd_handler(kpckt_recv, kpckt_send);
                break;
            case LS_TYPE:
                ls_state(kpckt_recv, kpckt_send);
                break;
            case VER_TYPE:
                ver_state(kpckt_recv, kpckt_send);
                break;
            case LINHA_TYPE:
                linha_state(kpckt_recv, kpckt_send);
                break;
            case LINHAS_TYPE:
                linhas_state(kpckt_recv, kpckt_send);
                break;
            case EDIT_TYPE:
                edit_state(kpckt_recv, kpckt_send);
                break;
            case COMPILAR_TYPE:
                compilar_state(kpckt_recv, kpckt_send);
                break;
            case NACK_TYPE:
                send_kpckt_to_client(kpckt_send);
                break;
            default:
                break;
        }
    }
    else
    {
        is_from_nack = 1;
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq.send, NACK_TYPE, NULL, 0, 0);
        send_kpckt_to_client(kpckt_send);
        seq.send++;
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