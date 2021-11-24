#include "server.h"

int main()
{
    kermit_pckt_t pckt_send, pckt_recv;

    server_init();

    while (1)
    {
        wait_kpckt(&pckt_recv);
        printf("[Server] Received: ");
        print_kermit_pckt(&pckt_recv);

        kpckt_handler(&pckt_recv, &pckt_send);

        send_kpckt(&pckt_send);
        printf("[Server] Send: ");
        print_kermit_pckt(&pckt_send);
    }

    return 0;
}