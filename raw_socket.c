#include "raw_socket.h"

int rawsocket_connection(char *device, struct sockaddr_ll *addr)
{
  int socket_fd;
  struct ifreq ir;
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

  memset(addr, 0, sizeof(struct sockaddr_ll)); /*IP do dispositivo*/
  addr->sll_family = AF_PACKET;
  addr->sll_protocol = htons(ETH_P_ALL);
  addr->sll_ifindex = ir.ifr_ifindex;
  if (bind(socket_fd, (struct sockaddr *)addr, sizeof(struct sockaddr_ll)) == -1)
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

  return socket_fd;
}

int sendto_rawsocket(int socket_fd, void *buf, size_t buf_size, struct sockaddr_ll *addr, socklen_t addr_len)
{
  return sendto(socket_fd, buf, buf_size, 0, (const struct sockaddr *)addr, addr_len);
}

int recvfrom_rawsocket(int socket_fd, void *buf, size_t buf_size, struct sockaddr_ll *addr, socklen_t *addr_len)
{
  return recvfrom(socket_fd, buf, buf_size, 0, (struct sockaddr *)addr, addr_len);
}

double timestamp()
{
  struct timeval tp;
  gettimeofday(&tp, NULL);
  return ((double)(tp.tv_sec * 1000.0 + tp.tv_usec / 1000.0));
}
