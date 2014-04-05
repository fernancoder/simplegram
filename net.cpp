/*
 * net.cpp
 *
 *  Created on: 2014/03/12
 *      Author: fernancoder
 */

#include "include.h"
#include "tree.h"
#include "net.h"

#define event_timer_cmp(a,b) ((a)->timeout > (b)->timeout ? 1 : ((a)->timeout < (b)->timeout ? -1 : (memcmp (a, b, sizeof (struct event_timer)))))
DEFINE_TREE (timer, struct event_timer *, event_timer_cmp, 0)
struct tree_timer *timer_tree;

void insert_event_timer (struct event_timer *ev) {
  //if (verbosity > 2) {
    cout <<  "INSERT: " << ev->timeout << " " << ev->self << " " << ev->alarm << endl;
  //}
  timer_tree = tree_insert_timer (timer_tree, ev, lrand48 ());
}

void my_clock_gettime (int clock_id UU, struct timespec *T) {
  /*
#ifdef __MACH__
  // We are ignoring MONOTONIC and hope time doesn't go back to often
  clock_serv_t cclock;
  mach_timespec_t mts;
  host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
  clock_get_time(cclock, &mts);
  mach_port_deallocate(mach_task_self(), cclock);
  T->tv_sec = mts.tv_sec;
  T->tv_nsec = mts.tv_nsec;
#else*/
  assert (clock_gettime(clock_id, T) >= 0);
//#endif
}

double get_double_time (void) {
  struct timespec tv;
  my_clock_gettime (CLOCK_REALTIME, &tv);
  return tv.tv_sec + 1e-9 * tv.tv_nsec;
}

#define MAX_CONNECTIONS 100
struct connection *Connections[MAX_CONNECTIONS];
int max_connection_fd;

void rotate_port (struct connection *c) {
  switch (c->port) {
  case 443:
    c->port = 80;
    break;
  case 80:
    c->port = 25;
    break;
  case 25:
    c->port = 443;
    break;
  }
}

void delete_connection_buffer (struct connection_buffer *b) {
  free (b->start);
  free (b);
}

void start_ping_timer (struct connection *c);
void fail_connection (struct connection *c);
long long encrypt_send_message (struct connection *c, int *msg, int msg_ints, int useful);
void flush_out (struct connection *c UU);


int ping_alarm (struct connection *c) {
  //if (verbosity > 2) {
    cout << "ping alarm" << endl;
  //}
  assert (c->state == conn_ready || c->state == conn_connecting);
  if (get_double_time () - c->last_receive_time > 20 * PING_TIMEOUT) {
    //if (verbosity) {
      cout << "fail connection: reason: ping timeout" << endl;
    //}
    c->state = conn_failed;
    fail_connection (c);
  } else if (get_double_time () - c->last_receive_time > 5 * PING_TIMEOUT && c->state == conn_ready) {
    int x[3];
    x[0] = CODE_ping;
    *(long long *)(x + 1) = lrand48 () * (1ll << 32) + lrand48 ();
    encrypt_send_message (c, x, 3, 0);
    start_ping_timer (c);
  } else {
    start_ping_timer (c);
  }
  return 0;
}

void remove_event_timer (struct event_timer *ev) {
  //if (verbosity > 2) {
    cout << "REMOVE: " << ev->timeout << " " << ev->self << " " << ev->alarm << endl;
  //}
  timer_tree = tree_delete_timer (timer_tree, ev);
}

void stop_ping_timer (struct connection *c) {
  remove_event_timer (&c->ev);
}

void start_ping_timer (struct connection *c) {
  c->ev.timeout = get_double_time () + PING_TIMEOUT;
  c->ev.alarm = (int (*)(void*))ping_alarm;
  c->ev.self = c;
  insert_event_timer (&c->ev);
}

void restart_connection (struct connection *c);
int fail_alarm (void *ev) {
  ((struct connection *)ev)->in_fail_timer = 0;
  restart_connection ((connection *)ev);
  return 0;
}
void start_fail_timer (struct connection *c) {
  if (c->in_fail_timer) { return; }
  c->in_fail_timer = 1;  
  c->ev.timeout = get_double_time () + 10;
  c->ev.alarm = (int (*)(void*))fail_alarm;
  c->ev.self = c;
  insert_event_timer (&c->ev);
}

void restart_connection (struct connection *c) {
  if (c->last_connect_time == time (0)) {
    start_fail_timer (c);
    return;
  }
  
  c->last_connect_time = time (0);
  int fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    cout << "Can not create socket" << endl;
    exit (1);
  }
  assert (fd >= 0 && fd < MAX_CONNECTIONS);
  if (fd > max_connection_fd) {
    max_connection_fd = fd;
  }
  int flags = -1;
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof (flags));
  setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof (flags));
  setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof (flags));

  struct sockaddr_in addr;
  addr.sin_family = AF_INET; 
  addr.sin_port = htons (c->port);
  addr.sin_addr.s_addr = inet_addr (c->ip);


  fcntl (fd, F_SETFL, O_NONBLOCK);

  if (connect (fd, (struct sockaddr *) &addr, sizeof (addr)) == -1) {
    if (errno != EINPROGRESS) {
      cout << "Can not connect to " << c->ip << ":" << c->port << endl;
      start_fail_timer (c);
      close (fd);
      return;
    }
  }

  c->fd = fd;
  c->state = conn_connecting;
  c->last_receive_time = get_double_time ();
  start_ping_timer (c);
  Connections[fd] = c;
  
  char byte = 0xef;
  assert (write_out (c, &byte, 1) == 1);
  flush_out (c);
}

void fail_connection (struct connection *c) {
  if (c->state == conn_ready || c->state == conn_connecting) {
    stop_ping_timer (c);
  }
  rotate_port (c);
  struct connection_buffer *b = c->out_head;
  while (b) {
    struct connection_buffer *d = b;
    b = b->next;
    delete_connection_buffer (d);
  }
  b = c->in_head;
  while (b) {
    struct connection_buffer *d = b;
    b = b->next;
    delete_connection_buffer (d);
  }
  c->out_head = c->out_tail = c->in_head = c->in_tail = 0;
  c->state = conn_failed;
  c->out_bytes = c->in_bytes = 0;
  close (c->fd);
  Connections[c->fd] = 0;
  cout << "Lost connection to server... " << c->ip << ":" << c->port << endl;
  restart_connection (c);
}

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

  c->last_receive_time = get_double_time ();
  start_ping_timer (c);
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


