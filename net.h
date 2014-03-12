#define MAX_DC_SESSIONS 3

struct session {
  struct dc *dc;
  long long session_id;
  int seq_no;
//  struct connection *c;
//  struct tree_long *ack_tree;
//  struct event_timer ev;
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