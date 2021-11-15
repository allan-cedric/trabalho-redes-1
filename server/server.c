#include "../kermit.h"

int main()
{
    struct sockaddr_ll addr;

    printf("Initializing server...\n");
    printf("Creating a socket...\n");
    int socket_fd = rawsocket_connection("lo", &addr);
    printf("Socket (fd=%i) created successfully!\n\n", socket_fd);

    socklen_t addr_len = sizeof(addr);
    kermit_pckt_t kermit_pckt, kermit_pckt_1;
    printf("Server initialized successfully!\n");

    memset(&kermit_pckt, 0, sizeof(kermit_pckt));
    while (1)
    {
        memset(&kermit_pckt_1, 0, sizeof(kermit_pckt_1));
        int ret = recvfrom_rawsocket(socket_fd, &kermit_pckt_1, sizeof(kermit_pckt_1), &addr, &addr_len);
        if (ret < 0)
        {
            perror("[Server] Error to receive");
            break;
        }
        else if (ret == 0)
        {
            printf("[Server] End of connection\n");
            break;
        }

        if (right_kermit_pckt(&kermit_pckt_1) && (kermit_pckt_1.origin_addr != SER_ADDR))
        {
            printf("[Server] Received (%i bytes): ", ret);
            print_kermit_pckt(&kermit_pckt_1);
        }
        sleep(1);
    }

    close(socket_fd);

    return 0;
}