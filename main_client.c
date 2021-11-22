#include "client.h"

int main()
{
    kermit_pckt_t pckt_send, pckt_recv;

    client_init();

    while (1)
    {
        // Entrada de dados
        read_client_input();

        // Comandos standalone
        if (client_standalone_commands())
            continue;

        // Preparação do pacote kermit para um comando
        client_command_kermit_pckt(&pckt_send);

        while (1)
        {
            // Envia o pacote ao servidor
            send_kpckt_to_server(&pckt_send);

            // Espera uma resposta do servidor
            int is_timeout = recv_kpckt_from_server(&pckt_recv);

            // Tratamento de timeout ou de uma resposta do servidor
            if (is_timeout)
                fprintf(stderr, "[Client] timeout: sending back...\n");
            else if (!kpckt_handler(&pckt_recv, &pckt_send))
                break;
        }
    }
    
    client_close();

    return 0;
}