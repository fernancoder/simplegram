/*
 * net.cpp
 *
 *  Created on: 2014/03/12
 *      Author: fernancoder
 */

#include "include.h"
#include "net.h"






struct connection *create_connection (const char *host, int port, struct session *session, struct connection_methods *methods) {
  struct connection *c = (connection *)malloc(sizeof(connection));
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    cout << "Can not create socket" << endl;
    exit (1);
  }

  int flags = -1;
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof (flags));
  setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof (flags));
  setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof (flags));

  struct sockaddr_in addr;
  addr.sin_family = AF_INET; 
  addr.sin_port = htons (port);
  addr.sin_addr.s_addr = inet_addr (host);


  fcntl (fd, F_SETFL, O_NONBLOCK);

  if (connect (fd, (struct sockaddr *) &addr, sizeof (addr)) == -1) {
    if (errno != EINPROGRESS) {
      cout <<  "Can not connect to " << host << ":" << port << endl;
      close (fd);
      free (c);
      return 0;
    }
  }

  struct pollfd s;
  s.fd = fd;
  s.events = POLLOUT | POLLERR | POLLRDHUP | POLLHUP;
  errno = 0;
  
  while (poll (&s, 1, 10000) <= 0 || !(s.revents & POLLOUT)) {
    if (errno == EINTR) { continue; }
    if (errno) {
      cout << "Problems in poll" << endl;
      exit (1);
    }
    cout <<  "Connect with " << host << ":" << port << " timeout" << endl;
    close (fd);
    free (c);
    return 0;
  }

  c->session = session;
  c->fd = fd; 
  c->ip = strdup (host);
  c->flags = 0;
  c->state = conn_ready;
  c->methods = methods;
  c->port = port;
  cout <<  "Connect to " << host << ":" << port << " successful" << endl;

  if (c->methods->ready) {
    c->methods->ready (c);
  }

  //c->last_receive_time = get_double_time ();
  //start_ping_timer (c);
  return c;
}

struct connection_buffer *new_connection_buffer (int size) {
  struct connection_buffer *b = (struct connection_buffer *)malloc (sizeof (*b));
  memset((void *)b, 0, sizeof(*b) );
  b->start = (unsigned char*)malloc (size);
  b->end = b->start + size;
  b->rptr = b->wptr = b->start;
  return b;
}

int write_out (struct connection *c, const void *_data, int len) {
  const unsigned char *data = (unsigned char *)_data;
  if (!len) { return 0; }
  assert (len > 0);
  int x = 0;
  if (!c->out_head) {
    struct connection_buffer *b = new_connection_buffer (1 << 20);
    c->out_head = c->out_tail = b;
  }
  while (len) {
    if (c->out_tail->end - c->out_tail->wptr >= len) {
      memcpy (c->out_tail->wptr, data, len);
      c->out_tail->wptr += len;
      c->out_bytes += len;
      return x + len;
    } else {
      int y = c->out_tail->end - c->out_tail->wptr;
      assert (y < len);
      memcpy (c->out_tail->wptr, data, y);
      x += y;
      len -= y;
      data += y;
      struct connection_buffer *b = new_connection_buffer (1 << 20);
      c->out_tail->next = b;
      b->next = 0;
      c->out_tail = b;
      c->out_bytes += y;
    }
  }
  return x;
}

void delete_connection_buffer (struct connection_buffer *b) {
  free ((void *)b->start);
  free ((void *)b);
}

int read_in (struct connection *c, void *_data, int len) {
  unsigned char *data = (unsigned char *)_data;
  if (!len) { return 0; }
  assert (len > 0);
  if (len > c->in_bytes) {
    len = c->in_bytes;
  }
  int x = 0;
  while (len) {
    int y = c->in_head->wptr - c->in_head->rptr;
    if (y > len) {
      memcpy (data, c->in_head->rptr, len);
      c->in_head->rptr += len;
      c->in_bytes -= len;
      return x + len;
    } else {
      memcpy (data, c->in_head->rptr, y);
      c->in_bytes -= y;
      x += y;
      data += y;
      len -= y;
      void *old = c->in_head;
      c->in_head = c->in_head->next;
      if (!c->in_head) {
        c->in_tail = 0;
      }
      delete_connection_buffer ((connection_buffer *)old);
    }
  }
  return x;
}
