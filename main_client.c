#include "kermit.h"

int main()
{
    struct sockaddr_ll addr;

    printf("Creating a socket...\n");
    int socket_fd = rawsocket_connection("lo", &addr);
    printf("Socket (fd=%i) created successfully!\n\n", socket_fd);

    socklen_t addr_len = sizeof(addr);
    kermit_pckt_t kermit_pckt, kermit_pckt_1;

    printf("********************************\n");
    printf(" Welcome to the Remote C Editor\n");
    printf("********************************\n\n");

    memset(&kermit_pckt, 0, sizeof(kermit_pckt));
    while (1)
    {
        kermit_pckt.init_marker = INIT_MARKER;
        kermit_pckt.dest_addr = SER_ADDR;
        kermit_pckt.origin_addr = CLI_ADDR;
        kermit_pckt.size = 0xF;
        kermit_pckt.type = 0xA;
        memset(&kermit_pckt.msg, 'k', kermit_pckt.size);
        kermit_pckt.parity = 0x1;

        int ret = sendto_rawsocket(socket_fd, &kermit_pckt, sizeof(kermit_pckt), &addr, addr_len);
        if (ret < 0)
        {
            perror("[Client] Error to send");
            break;
        }
        else if (ret == 0)
        {
            printf("[Client] End of connection\n");
            break;
        }

        printf("[Client] Sent (%i bytes): ", ret);
        print_kermit_pckt(&kermit_pckt);
        kermit_pckt.seq++;
        
        memset(&kermit_pckt_1, 0, sizeof(kermit_pckt_1));
        ret = recvfrom_rawsocket(socket_fd, &kermit_pckt_1, sizeof(kermit_pckt_1), &addr, &addr_len);
        if (ret < 0)
        {
            perror("[Client] Error to receive");
            break;
        }
        else if (ret == 0)
        {
            printf("[Client] End of connection\n");
            break;
        }

        if (right_kermit_pckt(&kermit_pckt_1) && (kermit_pckt_1.origin_addr != CLI_ADDR))
        {
            printf("[Client] Received (%i bytes): ", ret);
            print_kermit_pckt(&kermit_pckt_1);
        }

        sleep(1);
    }

    close(socket_fd);

    return 0;
}