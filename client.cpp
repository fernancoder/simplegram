#include "include.h"
#include "net.h"
#include "client.h"

enum dc_state c_state;

void flush_out (struct connection *c UU) {
}

int auth_work_start (struct connection *c UU) {
  return 1;
}

long long precise_time;


int __packet_buffer[PACKET_BUFFER_SIZE], *packet_ptr;
int *packet_buffer = __packet_buffer + 16;
int total_packets_sent;
long long total_data_sent;

int auth_success;

char nonce[256];
char new_nonce[256];
char server_nonce[256];

struct {
  long long auth_key_id;
  long long out_msg_id;
  int msg_len;
} unenc_msg_header;

void my_clock_gettime (int clock_id UU, struct timespec *T) {
/*#ifdef __MACH__
  // We are ignoring MONOTONIC and hope time doesn't go back to often
  clock_serv_t cclock;
  mach_timespec_t mts;
  host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
  clock_get_time(cclock, &mts);
  mach_port_deallocate(mach_task_self(), cclock);
  T->tv_sec = mts.tv_sec;
  T->tv_nsec = mts.tv_nsec;
#else*/
  clock_gettime(clock_id, T);
//#endif
}

double get_utime (int clock_id) {
  struct timespec T;
  my_clock_gettime (clock_id, &T);
  double res = T.tv_sec + (double) T.tv_nsec * 1e-9;
  if (clock_id == CLOCK_REALTIME) {
    precise_time = (long long) (res * (1LL << 32));
  }
  return res;
}

void secure_random (void *s, int l) {
  if (RAND_bytes ((unsigned char*)s, l) < 0) {
    if (allow_weak_random) {
      RAND_pseudo_bytes ((unsigned char*)s, l);
    } else {
      assert (0 && "End of random. If you want, you can start with -w");
    }
  }
}

int tc_close (struct connection *c, int who) {
  //if (verbosity) {
    cout << "outbound http connection #" << c->fd << ": closing by " <<  who << endl;
  //}
  return 0;
}

static inline void out_ints (const int *what, int len) {
  assert (packet_ptr + len <= packet_buffer + PACKET_BUFFER_SIZE);
  memcpy (packet_ptr, what, len * 4);
  packet_ptr += len;
}


static inline void out_int (int x) {
  assert (packet_ptr + 1 <= packet_buffer + PACKET_BUFFER_SIZE);
  *packet_ptr++ = x;
}


static inline void out_long (long long x) {
  assert (packet_ptr + 2 <= packet_buffer + PACKET_BUFFER_SIZE);
  *(long long *)packet_ptr = x;
  packet_ptr += 2;
}

void out_cstring (const char *str, long len) {
  assert (len >= 0 && len < (1 << 24));
  assert ((char *) packet_ptr + len + 8 < (char *) (packet_buffer + PACKET_BUFFER_SIZE));
  char *dest = (char *) packet_ptr;
  if (len < 254) {
    *dest++ = len;
  } else {
    *packet_ptr = (len << 8) + 0xfe;
    dest += 4;
  }
  memcpy (dest, str, len);
  dest += len;
  while ((long) dest & 3) {
    *dest++ = 0;
  }
  packet_ptr = (int *) dest;
}

#define ENCRYPT_BUFFER_INTS        16384
int encrypt_buffer[ENCRYPT_BUFFER_INTS];

#define DECRYPT_BUFFER_INTS        16384
int decrypt_buffer[ENCRYPT_BUFFER_INTS];

int encrypt_packet_buffer (void) {
  return pad_rsa_encrypt ((char *) packet_buffer, (packet_ptr - packet_buffer) * 4, (char *) encrypt_buffer, ENCRYPT_BUFFER_INTS * 4, pubKey->n, pubKey->e);
}

static inline void clear_packet (void) {
  packet_ptr = packet_buffer;
}

int rpc_send_packet (struct connection *c) {
  int len = (packet_ptr - packet_buffer) * 4;
  c->out_packet_num ++;
  long long next_msg_id = (long long) ((1LL << 32) * get_utime (CLOCK_REALTIME)) & -4;
  if (next_msg_id <= unenc_msg_header.out_msg_id) {
    unenc_msg_header.out_msg_id += 4;
  } else {
    unenc_msg_header.out_msg_id = next_msg_id;
  }
  unenc_msg_header.msg_len = len;

  int total_len = len + 20;
  assert (total_len > 0 && !(total_len & 0xfc000003));
  total_len >>= 2;
  if (total_len < 0x7f) {
    assert (write_out (c, &total_len, 1) == 1);
  } else {
    total_len = (total_len << 8) | 0x7f;
    assert (write_out (c, &total_len, 4) == 4);
  }
  write_out (c, &unenc_msg_header, 20);
  write_out (c, packet_buffer, len);
  flush_out (c);

  total_packets_sent ++;
  total_data_sent += total_len;
  return 1;
}

int send_req_pq_packet (struct connection *c) {
  assert (c_state == st_init);
  secure_random (nonce, 16);
  unenc_msg_header.out_msg_id = 0;
  clear_packet ();
  out_int (CODE_req_pq);
  out_ints ((int *)nonce, 4);
  rpc_send_packet (c);    
  c_state = st_reqpq_sent;
  return 1;
}

unsigned long long gcd (unsigned long long a, unsigned long long b) {
  return b ? gcd (b, a % b) : a;
}

int process_respq_answer (struct connection *c, char *packet, int len) {
  int i;
 // if (verbosity) {
    cout << "process_respq_answer(), len=" << len << endl;
 // }
  assert (len >= 76);
  assert (!*(long long *) packet);
  assert (*(int *) (packet + 16) == len - 20);
  assert (!(len & 3));
  assert (*(int *) (packet + 20) == CODE_resPQ);
  assert (!memcmp (packet + 24, nonce, 16));
  memcpy (server_nonce, packet + 40, 16);
  char *from = packet + 56;
  int clen = *from++;
  assert (clen <= 8);
  what = 0;
  for (i = 0; i < clen; i++) {
    what = (what << 8) + (unsigned char)*from++;
  }

  while (((unsigned long)from) & 3) ++from;

  p1 = 0, p2 = 0;

  //if (verbosity >= 2) {
    cout << what << " received" << endl;
  //}

  int it = 0;
  unsigned long long g = 0;
  for (i = 0; i < 3 || it < 1000; i++) {
    int q = ((lrand48() & 15) + 17) % what;
    unsigned long long x = (long long)lrand48 () % (what - 1) + 1, y = x;
    int lim = 1 << (i + 18);
    int j;
    for (j = 1; j < lim; j++) {
      ++it;
      unsigned long long a = x, b = x, c = q;
      while (b) {
        if (b & 1) {
          c += a;
          if (c >= what) {
            c -= what;
          }
        }
        a += a;
        if (a >= what) {
          a -= what;
        }
        b >>= 1;
      }
      x = c;
      unsigned long long z = x < y ? what + x - y : x - y;
      g = gcd (z, what);
      if (g != 1) {
        break;
      }
      if (!(j & (j - 1))) {
        y = x;
      }
    }
    if (g > 1 && g < what) break;
  }

  assert (g > 1 && g < what);
  p1 = g;
  p2 = what / g;
  if (p1 > p2) {
    unsigned t = p1; p1 = p2; p2 = t;
  }
  

  //if (verbosity) {
    cout << "p1 = " << p1 << ", p2 = " << p2 << ", " << it << "iterations" << endl;
  //}

  /// ++p1; ///

  assert (*(int *) (from) == CODE_vector);
  int fingerprints_num = *(int *)(from + 4);
  assert (fingerprints_num >= 1 && fingerprints_num <= 64 && len == fingerprints_num * 8 + 8 + (from - packet));
  long long *fingerprints = (long long *) (from + 8);
  for (i = 0; i < fingerprints_num; i++) {
    if (fingerprints[i] == pk_fingerprint) {
      //logprintf ( "found our public key at position %d\n", i);
      break;
    }
  }
  if (i == fingerprints_num) {
    cout << "fatal: don't have any matching keys (" << pk_fingerprint << "expected)" << endl;
    exit (2);
  }
  // create inner part (P_Q_inner_data)
  clear_packet ();
  packet_ptr += 5;
  out_int (CODE_p_q_inner_data);
  out_cstring (packet + 57, clen);
  //out_int (0x0f01);  // pq=15

  if (p1 < 256) {
    clen = 1;
  } else if (p1 < 65536) {
    clen = 2;
  } else if (p1 < 16777216) {
    clen = 3;
  } else {
    clen = 4;
  } 
  p1 = __builtin_bswap32 (p1);
  out_cstring ((char *)&p1 + 4 - clen, clen);
  p1 = __builtin_bswap32 (p1);

  if (p2 < 256) {
    clen = 1;
  } else if (p2 < 65536) {
    clen = 2;
  } else if (p2 < 16777216) {
    clen = 3;
  } else {
    clen = 4;
  }
  p2 = __builtin_bswap32 (p2);
  out_cstring ((char *)&p2 + 4 - clen, clen);
  p2 = __builtin_bswap32 (p2);
    
  //out_int (0x0301);  // p=3
  //out_int (0x0501);  // q=5
  out_ints ((int *) nonce, 4);
  out_ints ((int *) server_nonce, 4);
  secure_random (new_nonce, 32);
  out_ints ((int *) new_nonce, 8);
  sha1 ((unsigned char *) (packet_buffer + 5), (packet_ptr - packet_buffer - 5) * 4, (unsigned char *) packet_buffer);

  int l = encrypt_packet_buffer ();
  
  clear_packet ();
  out_int (CODE_req_DH_params);
  out_ints ((int *) nonce, 4);
  out_ints ((int *) server_nonce, 4);
  //out_int (0x0301);  // p=3
  //out_int (0x0501);  // q=5
  if (p1 < 256) {
    clen = 1;
  } else if (p1 < 65536) {
    clen = 2;
  } else if (p1 < 16777216) {
    clen = 3;
  } else {
    clen = 4;
  } 
  p1 = __builtin_bswap32 (p1);
  out_cstring ((char *)&p1 + 4 - clen, clen);
  p1 = __builtin_bswap32 (p1);
  if (p2 < 256) {
    clen = 1;
  } else if (p2 < 65536) {
    clen = 2;
  } else if (p2 < 16777216) {
    clen = 3;
  } else {
    clen = 4;
  }
  p2 = __builtin_bswap32 (p2);
  out_cstring ((char *)&p2 + 4 - clen, clen);
  p2 = __builtin_bswap32 (p2);
    
  out_long (pk_fingerprint);
  out_cstring ((char *) encrypt_buffer, l);

  c_state = st_reqdh_sent;
  
  return rpc_send_packet (c);
}

int rpc_execute (struct connection *c, int op, int len) {
  cout << "outbound rpc connection #" << c->fd << ": received rpc answer" << op << " with " << len << " content bytes" << endl;
 
/*  if (op < 0) {
    assert (read_in (c, Response, Response_len) == Response_len);
    return 0;
  }*/

  if (len >= MAX_RESPONSE_SIZE/* - 12*/ || len < 0/*12*/) {
    cout << "answer too long (" << len << " bytes), skipping" << endl;
    return 0;
  }

  int Response_len = len;

  //if (verbosity >= 2) {
    cout << "Response_len = " << Response_len << endl;
  //}
  assert (read_in (c, Response, Response_len) == Response_len);
  Response[Response_len] = 0;
  cout << "have " << Response_len << " Response bytes" << endl;


#if !defined(__MACH__) && !defined(__FreeBSD__) && !defined (__CYGWIN__)
//  setsockopt (c->fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, 4);
#endif
  int o = c_state;
  if (GET_DC(c)->flags & 1) { o = st_authorized;}
  switch (o) {
  case st_reqpq_sent:
    process_respq_answer (c, Response/* + 8*/, Response_len/* - 12*/);
#if !defined(__MACH__) && !defined(__FreeBSD__) && !defined (__CYGWIN__)
//    setsockopt (c->fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, 4);
#endif
    return 0;
  case st_reqdh_sent:
    process_dh_answer (c, Response/* + 8*/, Response_len/* - 12*/);
#if !defined(__MACH__) && !defined(__FreeBSD__) && !defined (__CYGWIN__)
//    setsockopt (c->fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, 4);
#endif
    return 0;
  case st_client_dh_sent:
    process_auth_complete (c, Response/* + 8*/, Response_len/* - 12*/);
#if !defined(__MACH__) && !defined(__FreeBSD__) && !defined (__CYGWIN__)
//    setsockopt (c->fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, 4);
#endif
    return 0;
  case st_authorized:
    if (op < 0 && op >= -999) {
      logprintf ("Server error %d\n", op);
    } else {
      process_rpc_message (c, (void *)(Response/* + 8*/), Response_len/* - 12*/);
    }
#if !defined(__MACH__) && !defined(__FreeBSD__) && !defined (__CYGWIN__)
//    setsockopt (c->fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, 4);
#endif
    return 0;
  default:
    logprintf ( "fatal: cannot receive answer in state %d\n", c_state);
    exit (2);
  }
 
  return 0;
}

int rpc_becomes_ready (struct connection *c) {

  cout << "outbound connection" << c->fd << "becomes ready" << endl;

  char byte = 0xef;
  flush_out (c);

  int o = c_state;
  if (GET_DC(c)->flags & 1) { o = st_authorized; }
  switch (o) {
    case st_init:
      send_req_pq_packet (c);
      break;
    case st_authorized:
      auth_work_start (c);
      break;
    default:
      cout << "c_state = " << c_state << endl;
  }
  return 0;
}

int rpc_close (struct connection *c) {
  return tc_close (c, 0);
}

int auth_is_success (void) {
  return auth_success;
}