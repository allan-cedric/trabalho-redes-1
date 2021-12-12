// Allan Cedric G. B. Alves da Silva - GRR20190351

#include "server.h"

int main()
{
    if(chdir("./server/"))
    {
        fprintf(stderr, "error to access server directory\n");
        exit(EXIT_FAILURE);
    }

    kermit_pckt_t pckt_send, pckt_recv;

    server_init();

    while (1)
    {
        wait_kpckt_from_client(&pckt_recv); // Espera o pacote de um cliente
        printf("[Server] Recv: ");
        print_kermit_pckt(&pckt_recv);
        printf("\n");

        server_kpckt_handler(&pckt_recv, &pckt_send); // Trata um pacote recebido

        printf("[Server] Send: ");
        print_kermit_pckt(&pckt_send);
        printf("\n");
    }

    return 0;
}