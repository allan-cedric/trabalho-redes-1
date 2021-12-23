## Trabalho da disciplina de Redes 1 (CI1058) - Ciência da Computação (UFPR) - 2021

*   Autor: Allan Cedric G. B. Alves da Silva

### Sobre o projeto

*   Construção de um editor C remoto. Foram desenvolvidos uma aplicação cliente (interface de interações), uma aplicação servidor e os mecanismos de comunicação entre essas duas aplicações (*Raw Sockets*).

### Compilação

*   No terminal execute: `make`

### Arquitetura do sistema

*   Após a compilação, serão criados dois diretórios, `client/` e `server/`, cada um desses diretórios simboliza uma máquina cliente e uma máquina servidor, respectivamente. Dentro deles serão criados alguns arquivos vazios para teste. Caso deseje, podem ser criados arquivos fonte C nesses diretórios para testar de forma mais interessante. 

*   Os executáveis do cliente e do servidor estarão disponíveis no diretório desse repositório, `main_client` e `main_server`, respectivamente.

### Execução

*   Abra dois terminais no diretório desse repositório, em um execute `sudo ./main_server` e em outro `sudo ./main_client`. A partir disso, o editor C remoto roda normalmente.

*   Caso se interrompa ou aborte a execução de uma das aplicações, é necessário inicializá-las ambas novamente. Isso é devido ao fato da sequencialização esperada das mensagens entre as aplicações.

### Observações

*   **ATENÇÃO: Esse trabalho foi desenvolvido para disciplina de Redes de Computadores 1. Por essa razão, evite realizar plágio, pois além de prejudicar a si mesmo, está sabotando a própria oportunidade de aprender.**