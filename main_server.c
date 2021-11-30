#include "server.h"

int main()
{
    kermit_pckt_t pckt_send, pckt_recv;

    server_init();

    while (1)
    {
        wait_kpckt_from_client(&pckt_recv);
        printf("[Server] Recv: ");
        print_kermit_pckt(&pckt_recv);

        server_kpckt_handler(&pckt_recv, &pckt_send);

        printf("[Server] Send: ");
        print_kermit_pckt(&pckt_send);
    }

    return 0;
}