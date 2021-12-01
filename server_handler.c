// Allan Cedric G. B. Alves da Silva - GRR20190351

#include "server_handler.h"

extern int is_from_nack;
extern unsigned int seq_send;
FILE *arq; // Descritor de arquivo auxiliar

// Procedimento auxiliar da biblioteca
int end_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (kpckt_send->type == ERROR_TYPE)
        return 1;
    return ((kpckt_send->type == ACK_TYPE) &&
            (kpckt_recv->type == ACK_TYPE || kpckt_recv->type == END_TRANS_TYPE));
}

void cmd_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send,
               void (*cmd_handler)(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send))
{
    cmd_handler(kpckt_recv, kpckt_send);
    while (1)
    {
        send_kpckt_to_client(kpckt_send);

        if (end_state(kpckt_recv, kpckt_send))
            break;

        printf("[Server] Send: ");
        print_kermit_pckt(kpckt_send);
        printf("\n");

        int is_timeout = recv_kpckt_from_client(kpckt_recv);
        if (is_timeout)
        {
            fprintf(stderr, "[Server] timeout: sending back...\n");
            continue;
        }

        printf("[Server] Recv: ");
        print_kermit_pckt(kpckt_recv);
        printf("\n");

        byte_t parity = error_detection(kpckt_recv);
        if (!parity)
            cmd_handler(kpckt_recv, kpckt_send);
        else
        {
            is_from_nack = 1;
            gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, NACK_TYPE, NULL, 0, 0);
            seq_send++;
        }
    }
}

void ls_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    cmd_state(kpckt_recv, kpckt_send, ls_handler);
}

void ver_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (!access((const char *)kpckt_recv->data, R_OK))
        cmd_state(kpckt_recv, kpckt_send, ver_handler);
    else
    {
        int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ERROR_TYPE, &error_code, 1, sizeof(int));
        send_kpckt_to_client(kpckt_send);
        seq_send++;
    }
}

void linha_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (!access((const char *)kpckt_recv->data, R_OK))
        cmd_state(kpckt_recv, kpckt_send, linha_handler);
    else
    {
        int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                        ERROR_TYPE, &error_code, 1, sizeof(int));
        send_kpckt_to_client(kpckt_send);
        seq_send++;
    }
}

void linhas_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (!access((const char *)kpckt_recv->data, R_OK))
        cmd_state(kpckt_recv, kpckt_send, linhas_handler);
    else
    {
        int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                        ERROR_TYPE, &error_code, 1, sizeof(int));
        send_kpckt_to_client(kpckt_send);
        seq_send++;
    }
}

void edit_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (!access((const char *)kpckt_recv->data, R_OK))
        cmd_state(kpckt_recv, kpckt_send, edit_handler);
    else
    {
        int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                        ERROR_TYPE, &error_code, 1, sizeof(int));
        send_kpckt_to_client(kpckt_send);
        seq_send++;
    }
}

void compilar_state(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (!access((const char *)kpckt_recv->data, R_OK))
        cmd_state(kpckt_recv, kpckt_send, compilar_handler);
    else
    {
        int error_code = (errno == EACCES ? NO_PERM : NO_ARQ);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                        ERROR_TYPE, &error_code, 1, sizeof(int));
        send_kpckt_to_client(kpckt_send);
        seq_send++;
    }
}

void cd_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (!chdir((const char *)kpckt_recv->data))
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        int error_code = (errno == EACCES ? NO_PERM : NO_DIR);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send,
                        ERROR_TYPE, &error_code, 1, sizeof(int));
    }
    send_kpckt_to_client(kpckt_send);
    seq_send++;
}

void ls_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        byte_t buf[DATA_SIZE + 1];
        memset(buf, 0, DATA_SIZE + 1);

        switch (kpckt_recv->type)
        {
            case LS_TYPE: // Executa o comando "ls" no servidor, e começa a enviar informações
                arq = popen("ls", "r");
                if (!arq)
                {
                    fprintf(stderr, "error: popen\n");
                    exit(1);
                }
                fread(buf, sizeof(byte_t), DATA_SIZE, arq);

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, LS_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));
                break;
            case ACK_TYPE: // Envia as informações resultantes do comando "ls"
                if (fread(buf, sizeof(byte_t), DATA_SIZE, arq) < 1)
                {
                    fclose(arq);
                    arq = NULL;
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
                }
                else
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                    buf, 1, strlen((const char *)buf));
                break;
            default:
                break;
        }
    }

    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void ver_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        byte_t buf[DATA_SIZE + 1];
        memset(buf, 0, DATA_SIZE + 1);

        byte_t cmd_cat[BUF_SIZE];
        memset(cmd_cat, 0, BUF_SIZE);

        switch (kpckt_recv->type)
        {
            case VER_TYPE: // Executa o comando "ver" no servidor, e começa a enviar informações
                sprintf((char *)cmd_cat, "cat -n %s", kpckt_recv->data);
                arq = popen((const char *)cmd_cat, "r");
                if (!arq)
                {
                    fprintf(stderr, "error: popen\n");
                    exit(1);
                }
                fread(buf, sizeof(byte_t), DATA_SIZE, arq);

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));

                memset(buf, 0, DATA_SIZE + 1);
                break;
            case ACK_TYPE: // Envia as informações resultantes do comando "ver"
                if (fread(buf, sizeof(byte_t), DATA_SIZE, arq) < 1)
                {
                    fclose(arq);
                    arq = NULL;
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
                }
                else
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                    buf, 1, strlen((const char *)buf));
                break;
            default:
                break;
        }
    }

    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void linha_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    static byte_t buf_arq[DATA_SIZE + 1];

    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        byte_t buf[DATA_SIZE + 1];
        memset(buf, 0, DATA_SIZE + 1);

        byte_t cmd_sed[BUF_SIZE];
        memset(cmd_sed, 0, BUF_SIZE);

        int arq_last_line;

        switch (kpckt_recv->type)
        {
            case LINHA_TYPE: // Recebe o nome do arquivo
                memset(buf_arq, 0, DATA_SIZE + 1);
                memcpy(buf_arq, kpckt_recv->data, kpckt_recv->size);
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                break;
            case LINHA_ARG_TYPE: // Recebe o parâmetro de linha, e começa a enviar os dados da linha

                // Descobre quantas linhas o arquivo possui
                sprintf((char *)cmd_sed, "sed -n '$=' %s", buf_arq);
                arq = popen((const char *)cmd_sed, "r");
                if (!arq)
                {
                    fprintf(stderr, "error: popen\n");
                    exit(1);
                }
                fscanf(arq, "%i", &arq_last_line);
                fclose(arq);
                arq = NULL;

                int *line = (int *)(kpckt_recv->data); // Linha desejada

                if ((*line >= 1) && (*line <= arq_last_line)) // Existência da linha
                {
                    sprintf((char *)cmd_sed, "sed '%iq;d' %s", *line, buf_arq);
                    arq = popen((const char *)cmd_sed, "r");
                    if (!arq)
                    {
                        fprintf(stderr, "error: popen\n");
                        exit(1);
                    }
                    fread(buf, sizeof(byte_t), DATA_SIZE, arq);
                }

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));
                break;
            case ACK_TYPE: // Envia os dados de uma linha
                if (!arq || fread(buf, sizeof(byte_t), DATA_SIZE, arq) < 1)
                {
                    if(arq)
                    {
                        fclose(arq);
                        arq = NULL;
                    }
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
                }
                else
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                    buf, 1, strlen((const char *)buf));
                break;
            default:
                break;
        }
    }
    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void linhas_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    static byte_t buf_arq[DATA_SIZE + 1];

    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE)
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else
    {
        byte_t buf[DATA_SIZE + 1];
        memset(buf, 0, DATA_SIZE + 1);

        byte_t cmd_sed[BUF_SIZE];
        memset(cmd_sed, 0, BUF_SIZE);

        int arq_last_line;

        switch (kpckt_recv->type)
        {
            case LINHAS_TYPE: // Recebe o nome do arquivo
                memset(buf_arq, 0, DATA_SIZE + 1);
                memcpy(buf_arq, kpckt_recv->data, kpckt_recv->size);
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                break;
            case LINHA_ARG_TYPE: // Recebe os 2 parâmetros de linha, e começa a enviar os dados entre linhas

                // Descobre quantas linhas o arquivo possui
                sprintf((char *)cmd_sed, "sed -n '$=' %s", buf_arq);
                arq = popen((const char *)cmd_sed, "r");
                if (!arq)
                {
                    fprintf(stderr, "error: popen\n");
                    exit(1);
                }
                fscanf(arq, "%i", &arq_last_line);
                fclose(arq);
                arq = NULL;

                int *init_line = (int *)(kpckt_recv->data); // Linha inicial desejada
                int *last_line = (int *)(kpckt_recv->data + sizeof(int)); // Linha final desejada

                if ((*init_line >= 1) && (*init_line <= arq_last_line))
                {
                    if((*last_line < 1) || (*last_line > arq_last_line))
                        *last_line = arq_last_line;

                    sprintf((char *)cmd_sed, "sed -n '%i,%ip;%iq' %s", *init_line, *last_line,
                            (*last_line) + 1, buf_arq);

                    arq = popen((const char *)cmd_sed, "r");
                    if (!arq)
                    {
                        fprintf(stderr, "error: popen\n");
                        exit(1);
                    }

                    fread(buf, sizeof(byte_t), DATA_SIZE, arq);
                }

                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                buf, 1, strlen((const char *)buf));
                break;
            case ACK_TYPE: // Envia os dados entre as linhas
                if (!arq || fread(buf, sizeof(byte_t), DATA_SIZE, arq) < 1)
                {
                    if(arq)
                    {
                        fclose(arq);
                        arq = NULL;
                    }
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
                }
                else
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                    buf, 1, strlen((const char *)buf));
                break;
            default:
                break;
        }
    }
    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void edit_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    static byte_t buf_arq[BUF_SIZE];
    static byte_t buf_line[BUF_SIZE];
    static int line, last_line;

    byte_t cmd_sed[BUF_SIZE * 3];
    memset(cmd_sed, 0, BUF_SIZE * 3);

    if (kpckt_recv->type == END_TRANS_TYPE) // Executa o comando "edit"
    {
        if (line <= last_line)
            sprintf((char *)cmd_sed, "sed -i '%i c\\%s\\' %s", line, buf_line, buf_arq);
        else
            sprintf((char *)cmd_sed, "sed -i '%i a\\%s\\' %s", last_line, buf_line, buf_arq);

        arq = popen((const char *)cmd_sed, "r");
        if (!arq)
        {
            fprintf(stderr, "error: popen\n");
            exit(1);
        }
        fclose(arq);
        arq = NULL;

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    }
    else
    {
        switch (kpckt_recv->type)
        {
            case EDIT_TYPE: // Recebe o nome do arquivo
                memset(buf_arq, 0, BUF_SIZE);
                memset(buf_line, 0, BUF_SIZE);
                memcpy(buf_arq, kpckt_recv->data, kpckt_recv->size);
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                break;
            case LINHA_ARG_TYPE: // Recebe a linha
                sprintf((char *)cmd_sed, "sed -n '$=' %s", buf_arq);
                arq = popen((const char *)cmd_sed, "r");
                if (!arq)
                {
                    fprintf(stderr, "error: popen\n");
                    exit(1);
                }
                fscanf(arq, "%i", &last_line);
                fclose(arq);
                arq = NULL;

                memcpy(&line, kpckt_recv->data, kpckt_recv->size);

                if ((line >= 1) && (line <= last_line + 1)) // Existência da linha
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                else
                {
                    int error_code = NO_LINE;
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ERROR_TYPE,
                                    &error_code, 1, sizeof(int));
                }
                break;
            case ARQ_CONTENT_TYPE: // Recebe o conteúdo textual
                memcpy(buf_line + strlen((const char *)buf_line), kpckt_recv->data, kpckt_recv->size);
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                break;
            default:
                break;
        }
    }
    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}

void compilar_handler(kermit_pckt_t *kpckt_recv, kermit_pckt_t *kpckt_send)
{
    static byte_t buf_arq[BUF_SIZE];
    static byte_t buf_opt[BUF_SIZE];
    byte_t buf_feedback[DATA_SIZE + 1];
    memset(buf_feedback, 0, DATA_SIZE + 1);

    if (kpckt_recv->type == ACK_TYPE && kpckt_send->type == END_TRANS_TYPE) // Finalização
        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
    else if (kpckt_recv->type == END_TRANS_TYPE) // Compila o arquivo
    {
        byte_t cmd_gcc[BUF_SIZE * 3];
        memset(cmd_gcc, 0, BUF_SIZE * 3);

        sprintf((char *)cmd_gcc, "gcc %s %s 2>&1 | cat", buf_opt, buf_arq);

        arq = popen((const char *)cmd_gcc, "r");
        if (!arq)
        {
            fprintf(stderr, "error: popen\n");
            exit(1);
        }

        fread(buf_feedback, sizeof(byte_t), DATA_SIZE, arq);

        gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                        buf_feedback, 1, strlen((const char *)buf_feedback));
    }
    else
    {
        switch (kpckt_recv->type)
        {
            case COMPILAR_TYPE: // Recebe o nome do arquivo
                memset(buf_arq, 0, BUF_SIZE);
                memset(buf_opt, 0, BUF_SIZE);
                memcpy(buf_arq, kpckt_recv->data, kpckt_recv->size);
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                break;
            case ARQ_CONTENT_TYPE: // Recebe as opções/flags
                memcpy(buf_opt + strlen((const char *)buf_opt), kpckt_recv->data, kpckt_recv->size);
                gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ACK_TYPE, NULL, 0, 0);
                break;
            case ACK_TYPE: // Envia warnings/erros da compilação
                if (fread(buf_feedback, sizeof(byte_t), DATA_SIZE, arq) < 1)
                {
                    fclose(arq);
                    arq = NULL;
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, END_TRANS_TYPE, NULL, 0, 0);
                }
                else
                    gen_kermit_pckt(kpckt_send, CLI_ADDR, SER_ADDR, seq_send, ARQ_CONTENT_TYPE,
                                    buf_feedback, 1, strlen((const char *)buf_feedback));
                break;
            default:
                break;
        }
    }

    if (kpckt_recv->type != NACK_TYPE)
        seq_send++;
}