# Allan Cedric G. B. Alves da Silva - GRR20190351

CC = gcc
CFLAGS = -Wall

LIB_OBJS = kermit.o raw_socket.o utils.o

LIB_OBJS_CLI = client.o
LIB_OBJS_SER = server.o server_handler.o

LIB_OBJ_CLI_EXEC = main_client.o
LIB_OBJ_SER_EXEC = main_server.o

CLI_EXEC = main_client
SER_EXEC = main_server

all: create_dirs $(CLI_EXEC) $(SER_EXEC)

create_dirs:
	mkdir -p client server
	mkdir -p server/dir1 server/dir2 server/dir3 client/home
	touch server/dir1/arq1 server/dir2/arq2
	touch client/arq1 client/arq2

$(CLI_EXEC): $(LIB_OBJS) $(LIB_OBJS_CLI) $(LIB_OBJ_CLI_EXEC)
	$(CC) $(LIB_OBJS) $(LIB_OBJS_CLI) $(LIB_OBJ_CLI_EXEC) -o $(CLI_EXEC)

$(SER_EXEC): $(LIB_OBJS) $(LIB_OBJS_SER) $(LIB_OBJ_SER_EXEC)
	$(CC) $(LIB_OBJS) $(LIB_OBJS_SER) $(LIB_OBJ_SER_EXEC) -o $(SER_EXEC)

$(LIB_OBJS) : %.o : %.c %.h
$(LIB_OBJS_CLI) : %.o : %.c %.h
$(LIB_OBJS_SER) : %.o : %.c %.h

$(LIB_OBJ_CLI_EXEC): %.o : %.c
$(LIB_OBJ_SER_EXEC): %.o : %.c

clean:
	rm -f */*.o *.o

purge: clean
	rm -f *.out $(CLI_EXEC) $(SER_EXEC)