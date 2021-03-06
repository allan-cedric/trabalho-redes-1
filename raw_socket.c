// Allan Cedric G. B. Alves da Silva - GRR20190351

#include "raw_socket.h"

int rawsocket_connection(char *device)
{
  int socket_fd;
  struct ifreq ir;
  struct sockaddr_ll addr;
  struct packet_mreq mr;

  socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); /*cria socket*/
  if (socket_fd == -1)
  {
    perror("Error to open a socket");
    exit(ERROR_CODE);
  }

  memset(&ir, 0, sizeof(struct ifreq)); /*dispositivo eth0*/
  memcpy(ir.ifr_name, device, strlen(device));
  if (ioctl(socket_fd, SIOCGIFINDEX, &ir) == -1)
  {
    perror("Error to assign a device");
    exit(ERROR_CODE);
  }

  memset(&addr, 0, sizeof(struct sockaddr_ll)); /*IP do dispositivo*/
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex = ir.ifr_ifindex;
  if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) == -1)
  {
    perror("Error to bind");
    exit(ERROR_CODE);
  }

  memset(&mr, 0, sizeof(mr)); /*Modo Promiscuo*/
  mr.mr_ifindex = ir.ifr_ifindex;
  mr.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(socket_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
  {
    perror("Error to set an option to socket");
    exit(ERROR_CODE);
  }

  // Seta procedimentos send e recv como não bloqueantes (auxilia para timeout)
  fcntl(socket_fd, F_SETFL, O_NONBLOCK);

  return socket_fd;
}

int sendto_rawsocket(int socket_fd, void *buf, size_t buf_size)
{
  return send(socket_fd, buf, buf_size, 0);
}

int recvfrom_rawsocket(int socket_fd, void *buf, size_t buf_size)
{
  return recv(socket_fd, buf, buf_size, 0);
}