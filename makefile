CC = gcc
CFLAGS = -Wall

LIB_OBJS = kermit.o raw_socket.o

CLI_OBJS = client/client.o
CLI_EXEC = main_client

SER_OBJS = server/server.o 
SER_EXEC = main_server

all: $(LIB_OBJS) $(CLI_EXEC) $(SER_EXEC)

$(LIB_OBJS) : %.o : %.c %.h

$(CLI_EXEC): $(LIB_OBJS) $(CLI_OBJS)
	$(CC) $(LIB_OBJS) $(CLI_OBJS) -o $(CLI_EXEC)

$(SER_EXEC): $(LIB_OBJS) $(SER_OBJS)
	$(CC) $(LIB_OBJS) $(SER_OBJS) -o $(SER_EXEC)

clean:
	rm -f */*.o *.o

purge: clean
	rm -f *.out $(CLI_EXEC) $(SER_EXEC)