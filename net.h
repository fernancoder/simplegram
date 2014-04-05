/*
 * net.h
 *
 *  Created on: 2014/03/12
 *      Author: fernancoder
 */

#ifndef NET_H_
#define NET_H_

#define MAX_DC_SESSIONS 3
#define GET_DC(c) (c->session->dc)
#define PING_TIMEOUT 10
#define ACK_TIMEOUT 1

enum conn_state {
  conn_none,
  conn_connecting,
  conn_ready,
  conn_failed,
  conn_stopped
};

enum dc_state {
  st_init,
  st_reqpq_sent,
  st_reqdh_sent,
  st_client_dh_sent,
  st_authorized,
  st_error
} ;

struct event_timer {
  double timeout;
  int (*alarm)(void *self);
  void *self;
};

struct connection_buffer {
  unsigned char *start;
  unsigned char *end;
  unsigned char *rptr;
  unsigned char *wptr;
  struct connection_buffer *next;
};

struct connection {
  int fd;
  char *ip;
  int port;
  int flags;
  enum conn_state state;
  int ipv6[4];
  struct connection_buffer *in_head;
  struct connection_buffer *in_tail;
  struct connection_buffer *out_head;
  struct connection_buffer *out_tail;
  int in_bytes;
  int out_bytes;
  int packet_num;
  int out_packet_num;
  int last_connect_time;
  int in_fail_timer;
  struct connection_methods *methods;
  struct session *session;
  void *extra;
  struct event_timer ev;
  double last_receive_time;
};

struct connection_methods {
  int (*ready) (struct connection *c);
  int (*close) (struct connection *c);
  int (*execute) (struct connection *c, int op, int len);
};

struct session {
  struct dc *dc;
  long long session_id;
  int seq_no;
  struct connection *c;
  struct tree_long *ack_tree;
  struct event_timer ev;
};

struct dc {
  int id;
  int port;
  int flags;
  char *ip;
  char *user;
  struct session *sessions[MAX_DC_SESSIONS];
  char auth_key[256];
  long long auth_key_id;
  long long server_salt;

  int server_time_delta;
  double server_time_udelta;
  int has_auth;
};



//struct connection_methods auth_methods;
struct connection *create_connection (const char *host, int port, struct session *session, struct connection_methods *methods);
int write_out (struct connection *c, const void *_data, int len);
int send_all_acks (struct session *S);
void insert_msg_id (struct session *S, long long id);

void my_clock_gettime (int clock_id UU, struct timespec *T);  
double get_double_time (void);
void insert_event_timer (struct event_timer *ev);
  

#endif /* NET_H_ */