#include "include.h"
#include "tree.h"
#include "net.h"
#include "client.h"

void ensure (int r) {
  if (!r) {
    //logprintf ("Open SSL error\n");
    //ERR_print_errors_fp (stderr);
    assert (0);
  }
}

void ensure_ptr (void *p) {
  if (p == NULL) {
    //out_of_memory ();
  }
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

double get_server_time (struct dc *DC) {
  if (!DC->server_time_udelta) {
    DC->server_time_udelta = get_utime (CLOCK_REALTIME) - get_utime (CLOCK_MONOTONIC);
  }
  return get_utime (CLOCK_MONOTONIC) + DC->server_time_udelta;
}

long long generate_next_msg_id (struct dc *DC) {
  long long next_id = (long long) (get_server_time (DC) * (1LL << 32)) & -4;
  if (next_id <= client_last_msg_id) {
    next_id = client_last_msg_id += 4;
  } else {
    client_last_msg_id = next_id;
  }
  return next_id;
}

int serialize_bignum (BIGNUM *b, char *buffer, int maxlen) {
  int itslen = BN_num_bytes (b);
  int reqlen;
  if (itslen < 254) {
    reqlen = itslen + 1;
  } else {
    reqlen = itslen + 4;
  }
  int newlen = (reqlen + 3) & -4;
  int pad = newlen - reqlen;
  reqlen = newlen;
  if (reqlen > maxlen) {
    return -reqlen;
  }
  if (itslen < 254) {
    *buffer++ = itslen;
  } else {
    *(int *)buffer = (itslen << 8) + 0xfe;
    buffer += 4;
  }
  int l = BN_bn2bin (b, (unsigned char *)buffer);
  assert (l == itslen);
  buffer += l;
  while (pad --> 0) {
    *buffer++ = 0;
  }
  return reqlen;
}

static inline void clear_packet (void) {
  packet_ptr = packet_buffer;
}

static inline int prefetch_strlen (void) {
  if (in_ptr >= in_end) { 
    return -1; 
  }
  unsigned l = *in_ptr;
  if ((l & 0xff) < 0xfe) { 
    l &= 0xff;
    return (in_end >= in_ptr + (l >> 2) + 1) ? (int)l : -1;
  } else if ((l & 0xff) == 0xfe) {
    l >>= 8;
    return (l >= 254 && in_end >= in_ptr + ((l + 7) >> 2)) ? (int)l : -1;
  } else {
    return -1;
  }
}

static inline int fetch_int (void) {
  assert (in_ptr + 1 <= in_end);
  //if (verbosity > 6) {
    cout << "fetch_int: 0x" << *in_ptr << " (" << *in_ptr << " ) "<< endl;
  //}
  return *(in_ptr ++);
}

static inline long long fetch_long (void) {
  assert (in_ptr + 2 <= in_end);
  long long r = *(long long *)in_ptr;
  in_ptr += 2;
  return r;
}

static inline int prefetch_int (void) {
  assert (in_ptr < in_end);
  return *(in_ptr);
}

//extern int verbosity;
static inline char *fetch_str (int len) {
  assert (len >= 0);
  //if (verbosity > 6) {
    cout << "fetch_string: len = " << len << endl;
  //}
  if (len < 254) {
    char *str = (char *) in_ptr + 1;
    in_ptr += 1 + (len >> 2);
    return str;
  } else {
    char *str = (char *) in_ptr + 4;
    in_ptr += (len + 7) >> 2;
    return str;
  }
}

static inline void out_bignum (BIGNUM *n) {
  int l = serialize_bignum (n, (char *)packet_ptr, (PACKET_BUFFER_SIZE - (packet_ptr - packet_buffer)) * 4);
  assert (l > 0);
  packet_ptr += l >> 2;
}

int fetch_bignum (BIGNUM *x) {
  int l = prefetch_strlen ();
  if (l < 0) {
    return l;
  }
  char *str = fetch_str (l);
  assert (BN_bin2bn ((unsigned char *) str, l, x) == x);
  return l;
}

static inline void hexdump_in (void) {
//  hexdump (in_ptr, in_end);
}

int check_g (unsigned char p[256], BIGNUM *g) {
  static unsigned char s[256];
  memset (s, 0, 256);
  assert (BN_num_bytes (g) <= 256);
  BN_bn2bin (g, s);
  int ok = 0;
  int i;
  for (i = 0; i < 64; i++) {
    if (s[i]) { 
      ok = 1;
      break;
    }
  }
  if (!ok) { return -1; }
  ok = 0;
  for (i = 0; i < 64; i++) {
    if (s[255 - i]) { 
      ok = 1;
      break;
    }
  }
  if (!ok) { return -1; }
  ok = 0;
  for (i = 0; i < 64; i++) {
    if (s[i] < p[i]) { 
      ok = 1;
      break;
    } else if (s[i] > p[i]) {
      cout << "i = " << i << "(" << (int)s[i] << " " << (int)p[i] << " " << endl;
      return -1;
    }
  }
  if (!ok) { return -1; }
  return 0;
}

int check_g_bn (BIGNUM *p, BIGNUM *g) {
  static unsigned char s[256];
  memset (s, 0, 256);
  assert (BN_num_bytes (p) <= 256);
  BN_bn2bin (p, s);
  return check_g (s, g);
}

int check_prime (BIGNUM *p) {
  int r = BN_is_prime (p, BN_prime_checks, 0, BN_ctx, 0);
  ensure (r >= 0);
  return r;
}

int check_DH_params (BIGNUM *p, int g) {
  if (g < 2 || g > 7) { return -1; }
  BIGNUM t;
  BN_init (&t);

  BN_init (&dh_g);
  ensure (BN_set_word (&dh_g, 4 * g));

  ensure (BN_mod (&t, p, &dh_g, BN_ctx));
  int x = BN_get_word (&t);
  assert (x >= 0 && x < 4 * g);

  BN_free (&dh_g);

  switch (g) {
  case 2:
    if (x != 7) { return -1; }
    break;
  case 3:
    if (x % 3 != 2 ) { return -1; }
    break;
  case 4:
    break;
  case 5:
    if (x % 5 != 1 && x % 5 != 4) { return -1; }
    break;
  case 6:
    if (x != 19 && x != 23) { return -1; }
    break;
  case 7:
    if (x % 7 != 3 && x % 7 != 5 && x % 7 != 6) { return -1; }
    break;
  }

  if (!check_prime (p)) { return -1; }

  BIGNUM b;
  BN_init (&b);
  ensure (BN_set_word (&b, 2));
  ensure (BN_div (&t, 0, p, &b, BN_ctx));
  if (!check_prime (&t)) { return -1; }
  BN_free (&b);
  BN_free (&t);
  return 0;
}

void flush_out (struct connection *c UU) {
}

int auth_work_start (struct connection *c UU) {
  return 1;
}



int tc_close (struct connection *c, int who) {
  //if (verbosity) {
    cout << "outbound http connection #" << c->fd << ": closing by " <<  who << endl;
  //}
  return 0;
}

int rpc_send_message (struct connection *c, void *data, int len) {
  assert (len > 0 && !(len & 0xfc000003));
  int total_len = len >> 2;
  if (total_len < 0x7f) {
    assert (write_out (c, &total_len, 1) == 1);
  } else {
    total_len = (total_len << 8) | 0x7f;
    assert (write_out (c, &total_len, 4) == 4);
  }
  c->out_packet_num ++;
  assert (write_out (c, data, len) == len);
  flush_out (c);

  total_packets_sent ++;
  total_data_sent += total_len;
  return 1;
}

void init_aes_unauth (const char server_nonce[16], const char hidden_client_nonce[32], int encrypt) {
  static unsigned char buffer[64], hash[20];
  memcpy (buffer, hidden_client_nonce, 32);
  memcpy (buffer + 32, server_nonce, 16);
  SHA1 (buffer, 48, aes_key_raw);
  memcpy (buffer + 32, hidden_client_nonce, 32);
  SHA1 (buffer, 64, aes_iv + 8);
  memcpy (buffer, server_nonce, 16);
  memcpy (buffer + 16, hidden_client_nonce, 32);
  SHA1 (buffer, 48, hash);
  memcpy (aes_key_raw + 20, hash, 12);
  memcpy (aes_iv, hash + 12, 8);
  memcpy (aes_iv + 28, hidden_client_nonce, 4);
  if (encrypt == AES_ENCRYPT) {
    AES_set_encrypt_key (aes_key_raw, 32*8, &aes_key);
  } else {
    AES_set_decrypt_key (aes_key_raw, 32*8, &aes_key);
  }
  memset (aes_key_raw, 0, sizeof (aes_key_raw));
}

void init_aes_auth (char auth_key[192], char msg_key[16], int encrypt) {
  static unsigned char buffer[48], hash[20];
  //  sha1_a = SHA1 (msg_key + substr (auth_key, 0, 32));
  //  sha1_b = SHA1 (substr (auth_key, 32, 16) + msg_key + substr (auth_key, 48, 16));
  //  sha1_с = SHA1 (substr (auth_key, 64, 32) + msg_key);
  //  sha1_d = SHA1 (msg_key + substr (auth_key, 96, 32));
  //  aes_key = substr (sha1_a, 0, 8) + substr (sha1_b, 8, 12) + substr (sha1_c, 4, 12);
  //  aes_iv = substr (sha1_a, 8, 12) + substr (sha1_b, 0, 8) + substr (sha1_c, 16, 4) + substr (sha1_d, 0, 8);
  memcpy (buffer, msg_key, 16);
  memcpy (buffer + 16, auth_key, 32);
  SHA1 (buffer, 48, hash);
  memcpy (aes_key_raw, hash, 8);
  memcpy (aes_iv, hash + 8, 12);

  memcpy (buffer, auth_key + 32, 16);
  memcpy (buffer + 16, msg_key, 16);
  memcpy (buffer + 32, auth_key + 48, 16);
  SHA1 (buffer, 48, hash);
  memcpy (aes_key_raw + 8, hash + 8, 12);
  memcpy (aes_iv + 12, hash, 8);

  memcpy (buffer, auth_key + 64, 32);
  memcpy (buffer + 32, msg_key, 16);
  SHA1 (buffer, 48, hash);
  memcpy (aes_key_raw + 20, hash + 4, 12);
  memcpy (aes_iv + 20, hash + 16, 4);

  memcpy (buffer, msg_key, 16);
  memcpy (buffer + 16, auth_key + 96, 32);
  SHA1 (buffer, 48, hash);
  memcpy (aes_iv + 24, hash, 8);
  
  if (encrypt == AES_ENCRYPT) {
    AES_set_encrypt_key (aes_key_raw, 32*8, &aes_key);
  } else {
    AES_set_decrypt_key (aes_key_raw, 32*8, &aes_key);
  }
  memset (aes_key_raw, 0, sizeof (aes_key_raw));
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

int pad_rsa_encrypt (char *from, int from_len, char *to, int size, BIGNUM *N, BIGNUM *E) {
  int pad = (255000 - from_len - 32) % 255 + 32;
  int chunks = (from_len + pad) / 255;
  int bits = BN_num_bits (N);
  assert (bits >= 2041 && bits <= 2048);
  assert (from_len > 0 && from_len <= 2550);
  assert (size >= chunks * 256);
  assert (RAND_pseudo_bytes ((unsigned char *) from + from_len, pad) >= 0);
  int i;
  BIGNUM x, y;
  BN_init (&x);
  BN_init (&y);
  rsa_encrypted_chunks += chunks;
  for (i = 0; i < chunks; i++) {
    BN_bin2bn ((unsigned char *) from, 255, &x);
    assert (BN_mod_exp (&y, &x, E, N, BN_ctx) == 1);
    unsigned l = 256 - BN_num_bytes (&y);
    assert (l <= 256);
    memset (to, 0, l);
    BN_bn2bin (&y, (unsigned char *) to + l);
    to += 256;
  }
  BN_free (&x);
  BN_free (&y);
  return chunks * 256;
}

int pad_aes_encrypt (char *from, int from_len, char *to, int size) {
  int padded_size = (from_len + 15) & -16;
  assert (from_len > 0 && padded_size <= size);
  if (from_len < padded_size) {
    assert (RAND_pseudo_bytes ((unsigned char *) from + from_len, padded_size - from_len) >= 0);
  }
  AES_ige_encrypt ((unsigned char *) from, (unsigned char *) to, padded_size, &aes_key, aes_iv, AES_ENCRYPT);
  return padded_size;
}

int pad_aes_decrypt (char *from, int from_len, char *to, int size) {
  if (from_len <= 0 || from_len > size || (from_len & 15)) {
    return -1;
  }
  AES_ige_encrypt ((unsigned char *) from, (unsigned char *) to, from_len, &aes_key, aes_iv, AES_DECRYPT); 
  return from_len;
}

void init_enc_msg (struct session *S, int useful) {
  struct dc *DC = S->dc;
  assert (DC->auth_key_id);
  enc_msg.auth_key_id = DC->auth_key_id;
//  assert (DC->server_salt);
  enc_msg.server_salt = DC->server_salt;
  if (!S->session_id) {
    secure_random (&S->session_id, 8);
  }
  enc_msg.session_id = S->session_id;
  //enc_msg.auth_key_id2 = auth_key_id;
  enc_msg.msg_id = generate_next_msg_id (DC);
  //enc_msg.msg_id -= 0x10000000LL * (lrand48 () & 15);
  //kprintf ("message id %016llx\n", enc_msg.msg_id);
  enc_msg.seq_no = S->seq_no;
  if (useful) {
    enc_msg.seq_no |= 1;
  }
  S->seq_no += 2;
};

int aes_encrypt_message (struct dc *DC, struct encrypted_message *enc) {
  unsigned char sha1_buffer[20];
  const int MINSZ = offsetof (struct encrypted_message, message);
  const int UNENCSZ = offsetof (struct encrypted_message, server_salt);
  int enc_len = (MINSZ - UNENCSZ) + enc->msg_len;
  assert (enc->msg_len >= 0 && enc->msg_len <= MAX_MESSAGE_INTS * 4 - 16 && !(enc->msg_len & 3));
  sha1 ((unsigned char *) &enc->server_salt, enc_len, sha1_buffer);
  //printf ("enc_len is %d\n", enc_len);
  //if (verbosity >= 2) {
    cout << "sending message with sha1 " << *(int *)sha1_buffer << endl;
  //}
  memcpy (enc->msg_key, sha1_buffer + 4, 16);
  init_aes_auth (DC->auth_key, enc->msg_key, AES_ENCRYPT);
  //hexdump ((char *)enc, (char *)enc + enc_len + 24);
  return pad_aes_encrypt ((char *) &enc->server_salt, enc_len, (char *) &enc->server_salt, MAX_MESSAGE_INTS * 4 + (MINSZ - UNENCSZ));
}

long long encrypt_send_message (struct connection *c, int *msg, int msg_ints, int useful) {
  struct dc *DC = GET_DC(c);
  struct session *S = c->session;
  assert (S);
  const int UNENCSZ = offsetof (struct encrypted_message, server_salt);
  if (msg_ints <= 0 || msg_ints > MAX_MESSAGE_INTS - 4) {
    return -1;
  }
  if (msg) {
    memcpy (enc_msg.message, msg, msg_ints * 4);
    enc_msg.msg_len = msg_ints * 4;
  } else {
    if ((enc_msg.msg_len & 0x80000003) || enc_msg.msg_len > MAX_MESSAGE_INTS * 4 - 16) {
      return -1;
    }
  }
  init_enc_msg (S, useful);

  //hexdump ((char *)msg, (char *)msg + (msg_ints * 4));
  int l = aes_encrypt_message (DC, &enc_msg);
  //hexdump ((char *)&enc_msg, (char *)&enc_msg + l  + 24);
  assert (l > 0);
  rpc_send_message (c, &enc_msg, l + UNENCSZ);
  
  return client_last_msg_id;
}

enum dc_state c_state;


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

int encrypt_packet_buffer_aes_unauth (const char server_nonce[16], const char hidden_client_nonce[32]) {
  init_aes_unauth (server_nonce, hidden_client_nonce, AES_ENCRYPT);
  return pad_aes_encrypt ((char *) packet_buffer, (packet_ptr - packet_buffer) * 4, (char *) encrypt_buffer, ENCRYPT_BUFFER_INTS * 4);
}

void rpc_execute_answer (struct connection *c, long long msg_id UU);

int send_all_acks (struct session *S) {
  clear_packet ();
  out_int (CODE_msgs_ack);
  out_int (CODE_vector);
  out_int (tree_count_long (S->ack_tree));
  while (S->ack_tree) {
    long long x = tree_get_min_long (S->ack_tree); 
    out_long (x);
    S->ack_tree = tree_delete_long (S->ack_tree, x);
  }
  encrypt_send_message (S->c, packet_buffer, packet_ptr - packet_buffer, 0);
  return 0;
}

void insert_msg_id (struct session *S, long long id) {
  if (!S->ack_tree) {
    S->ev.alarm = (int (*)(void*))send_all_acks;
    S->ev.self = (void *)S;
    S->ev.timeout = get_double_time () + ACK_TIMEOUT;
    insert_event_timer (&S->ev);
  }
  if (!tree_lookup_long (S->ack_tree, id)) {
    S->ack_tree = tree_insert_long (S->ack_tree, id, lrand48 ());
  }
}

void work_container (struct connection *c, long long msg_id UU) {
  //if (verbosity) {
    cout << "work_container: msg_id = " << msg_id << endl;
  //}
  assert (fetch_int () == CODE_msg_container);
  int n = fetch_int ();
  int i;
  for (i = 0; i < n; i++) {
    long long id = fetch_long (); 
    //int seqno = fetch_int (); 
    fetch_int (); // seq_no
    if (id & 1) {
      insert_msg_id (c->session, id);
    }
    int bytes = fetch_int ();
    int *t = in_end;
    in_end = in_ptr + (bytes / 4);
    rpc_execute_answer (c, id);
    assert (in_ptr == in_end);
    in_end = t;
  }
}

void work_new_session_created (struct connection *c, long long msg_id UU) {
  //if (verbosity) {
    cout << "work_new_session_created: msg_id = " << msg_id << endl;
  //}
  assert (fetch_int () == (int)CODE_new_session_created);
  fetch_long (); // first message id
  //DC->session_id = fetch_long ();
  fetch_long (); // unique_id
  GET_DC(c)->server_salt = fetch_long ();
  
}

void rpc_execute_answer (struct connection *c, long long msg_id UU) {
  //if (verbosity >= 5) {
    cout << "rpc_execute_answer: fd=" << c->fd << endl;
    hexdump_in ();
  //}
  int op = prefetch_int ();
  switch (op) {
  case CODE_msg_container:
    work_container (c, msg_id);
    return;
  case CODE_new_session_created:
    work_new_session_created (c, msg_id);
    return;
  case CODE_msgs_ack:
    //work_msgs_ack (c, msg_id);
    return;
  case CODE_rpc_result:
    //work_rpc_result (c, msg_id);
    return;
  case CODE_update_short:
    //work_update_short (c, msg_id);
    return;
  case CODE_updates:
    //work_updates (c, msg_id);
    return;
  case CODE_update_short_message:
    //work_update_short_message (c, msg_id);
    return;
  case CODE_update_short_chat_message:
    //work_update_short_chat_message (c, msg_id);
    return;
  case CODE_gzip_packed:
    //work_packed (c, msg_id);
    return;
  case CODE_bad_server_salt:
    //work_bad_server_salt (c, msg_id);
    return;
  case CODE_pong:
    //work_pong (c, msg_id);
    return;
  case CODE_msg_detailed_info:
    //work_detailed_info (c, msg_id);
    return;
  case CODE_msg_new_detailed_info:
    //work_new_detailed_info (c, msg_id);
    return;
  case CODE_updates_too_long:
    //work_updates_to_long (c, msg_id);
    return;
  case CODE_bad_msg_notification:
    //work_bad_msg_notification (c, msg_id);
    return;
  }
  cout << "Unknown message" << endl;
  hexdump_in ();
  in_ptr = in_end; // Will not fail due to assertion in_ptr == in_end
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

int process_dh_answer (struct connection *c, char *packet, int len) {
  //if (verbosity) {
    cout << "process_dh_answer(), len=" <<  len << endl;
  //}
  if (len < 116) {
    cout << p1 << " * " << p2 << " = " << what << endl;
  }
  assert (len >= 116);
  assert (!*(long long *) packet);
  assert (*(int *) (packet + 16) == len - 20);
  assert (!(len & 3));
  assert (*(int *) (packet + 20) == (int)CODE_server_DH_params_ok);
  assert (!memcmp (packet + 24, nonce, 16));
  assert (!memcmp (packet + 40, server_nonce, 16));
  init_aes_unauth (server_nonce, new_nonce, AES_DECRYPT);
  in_ptr = (int *)(packet + 56);
  in_end = (int *)(packet + len);
  int l = prefetch_strlen ();
  assert (l > 0);
  l = pad_aes_decrypt (fetch_str (l), l, (char *) decrypt_buffer, DECRYPT_BUFFER_INTS * 4 - 16);
  assert (in_ptr == in_end);
  assert (l >= 60);
  assert (decrypt_buffer[5] == (int)CODE_server_DH_inner_data);
  assert (!memcmp (decrypt_buffer + 6, nonce, 16));
  assert (!memcmp (decrypt_buffer + 10, server_nonce, 16));
  int g = decrypt_buffer[14];
  in_ptr = decrypt_buffer + 15;
  in_end = decrypt_buffer + (l >> 2);
  BN_init (&dh_prime);
  BN_init (&g_a);
  assert (fetch_bignum (&dh_prime) > 0);
  assert (fetch_bignum (&g_a) > 0);
  assert (check_g_bn (&dh_prime, &g_a) >= 0);
  int server_time = *in_ptr++;
  assert (in_ptr <= in_end);

  assert (check_DH_params (&dh_prime, g) >= 0);

  static char sha1_buffer[20];
  sha1 ((unsigned char *) decrypt_buffer + 20, (in_ptr - decrypt_buffer - 5) * 4, (unsigned char *) sha1_buffer);
  assert (!memcmp (decrypt_buffer, sha1_buffer, 20));
  assert ((char *) in_end - (char *) in_ptr < 16);

  GET_DC(c)->server_time_delta = server_time - time (0);
  GET_DC(c)->server_time_udelta = server_time - get_utime (CLOCK_MONOTONIC);
  //logprintf ( "server time is %d, delta = %d\n", server_time, server_time_delta);

  // Build set_client_DH_params answer
  clear_packet ();
  packet_ptr += 5;
  out_int (CODE_client_DH_inner_data);
  out_ints ((int *) nonce, 4);
  out_ints ((int *) server_nonce, 4);
  out_long (0LL);
  
  BN_init (&dh_g);
  ensure (BN_set_word (&dh_g, g));

  secure_random (s_power, 256);
  BIGNUM *dh_power = BN_bin2bn ((unsigned char *)s_power, 256, 0);
  ensure_ptr (dh_power);

  BIGNUM *y = BN_new ();
  ensure_ptr (y);
  ensure (BN_mod_exp (y, &dh_g, dh_power, &dh_prime, BN_ctx));
  out_bignum (y);
  BN_free (y);

  BN_init (&auth_key_num);
  ensure (BN_mod_exp (&auth_key_num, &g_a, dh_power, &dh_prime, BN_ctx));
  l = BN_num_bytes (&auth_key_num);
  assert (l >= 250 && l <= 256);
  assert (BN_bn2bin (&auth_key_num, (unsigned char *)GET_DC(c)->auth_key));
  memset (GET_DC(c)->auth_key + l, 0, 256 - l);
  BN_free (dh_power);
  BN_free (&auth_key_num);
  BN_free (&dh_g);
  BN_free (&g_a);
  BN_free (&dh_prime);

  //hexdump (auth_key, auth_key + 256);
 
  sha1 ((unsigned char *) (packet_buffer + 5), (packet_ptr - packet_buffer - 5) * 4, (unsigned char *) packet_buffer);

  //hexdump ((char *)packet_buffer, (char *)packet_ptr);

  l = encrypt_packet_buffer_aes_unauth (server_nonce, new_nonce);

  clear_packet ();
  out_int (CODE_set_client_DH_params);
  out_ints ((int *) nonce, 4);
  out_ints ((int *) server_nonce, 4);
  out_cstring ((char *) encrypt_buffer, l);

  c_state = st_client_dh_sent;

  return rpc_send_packet (c);
}


int process_auth_complete (struct connection *c UU, char *packet, int len) {
  //if (verbosity) {
    cout << "process_dh_answer(), len=" << len << endl;
  //}
  assert (len == 72);
  assert (!*(long long *) packet);
  assert (*(int *) (packet + 16) == len - 20);
  assert (!(len & 3));
  assert (*(int *) (packet + 20) == CODE_dh_gen_ok);
  assert (!memcmp (packet + 24, nonce, 16));
  assert (!memcmp (packet + 40, server_nonce, 16));
  static unsigned char tmp[44], sha1_buffer[20];
  memcpy (tmp, new_nonce, 32);
  tmp[32] = 1;
  //GET_DC(c)->auth_key_id = *(long long *)(sha1_buffer + 12);

  //bl_do_set_auth_key_id (GET_DC(c)->id, (unsigned char *)GET_DC(c)->auth_key);
  sha1 ((unsigned char *)GET_DC(c)->auth_key, 256, sha1_buffer);

  memcpy (tmp + 33, sha1_buffer, 8);
  sha1 (tmp, 41, sha1_buffer);
  assert (!memcmp (packet + 56, sha1_buffer + 4, 16));
  GET_DC(c)->server_salt = *(long long *)server_nonce ^ *(long long *)new_nonce;
  
  //if (verbosity >= 3) {
    cout << "auth_key_id=" << GET_DC(c)->auth_key_id << endl;
  //}
  //kprintf ("OK\n");

  //c->status = conn_error;
  //sleep (1);

  c_state = st_authorized;
  //return 1;
  //if (verbosity) {
    cout << "Auth success" << endl;
  //}
  auth_success ++;
  GET_DC(c)->flags |= 1;
  //************************************************************* write_auth_file ();
  
  return 1;
}

int process_rpc_message (struct connection *c UU, struct encrypted_message *enc, int len) {
  const int MINSZ = offsetof (struct encrypted_message, message);
  const int UNENCSZ = offsetof (struct encrypted_message, server_salt);
  //if (verbosity) {
    cout << "process_rpc_message(), len=" << len << endl;
  //}
  assert (len >= MINSZ && (len & 15) == (UNENCSZ & 15));
  struct dc *DC = GET_DC(c);
  assert (enc->auth_key_id == DC->auth_key_id);
  assert (DC->auth_key_id);
  init_aes_auth (DC->auth_key + 8, enc->msg_key, AES_DECRYPT);
  int l = pad_aes_decrypt ((char *)&enc->server_salt, len - UNENCSZ, (char *)&enc->server_salt, len - UNENCSZ);
  assert (l == len - UNENCSZ);
  //assert (enc->auth_key_id2 == enc->auth_key_id);
  assert (!(enc->msg_len & 3) && enc->msg_len > 0 && enc->msg_len <= len - MINSZ && len - MINSZ - enc->msg_len <= 12);
  static unsigned char sha1_buffer[20];
  sha1 ((const unsigned char*)&enc->server_salt, enc->msg_len + (MINSZ - UNENCSZ), sha1_buffer);
  assert (!memcmp (&enc->msg_key, sha1_buffer + 4, 16));
  //assert (enc->server_salt == server_salt); //in fact server salt can change
  if (DC->server_salt != enc->server_salt) {
    DC->server_salt = enc->server_salt;
    //*************************************write_auth_file ();
  }
  
  int this_server_time = enc->msg_id >> 32LL;
  if (!DC->server_time_delta) {
    DC->server_time_delta = this_server_time - get_utime (CLOCK_REALTIME);
    DC->server_time_udelta = this_server_time - get_utime (CLOCK_MONOTONIC);
  }
  double st = get_server_time (DC);
  if (this_server_time < st - 300 || this_server_time > st + 30) {
    cout << "salt = " << enc->server_salt << ", session_id = " << enc->session_id << " msg_id = " << enc->msg_id << ", seq_no = " << enc->seq_no << ", st = " << st << ", now = " << get_utime (CLOCK_REALTIME) << endl;
    in_ptr = enc->message;
    in_end = in_ptr + (enc->msg_len / 4);
    hexdump_in ();
  }

  assert (this_server_time >= st - 300 && this_server_time <= st + 30);
  //assert (enc->msg_id > server_last_msg_id && (enc->msg_id & 3) == 1);
  //if (verbosity >= 1) {
    cout << "received mesage id " << enc->msg_id << endl;
    hexdump_in ();
  //}
  server_last_msg_id = enc->msg_id;

  //*(long long *)(longpoll_query + 3) = *(long long *)((char *)(&enc->msg_id) + 0x3c);
  //*(long long *)(longpoll_query + 5) = *(long long *)((char *)(&enc->msg_id) + 0x3c);

  assert (l >= (MINSZ - UNENCSZ) + 8);
  //assert (enc->message[0] == CODE_rpc_result && *(long long *)(enc->message + 1) == client_last_msg_id);
  ++good_messages;
  
  in_ptr = enc->message;
  in_end = in_ptr + (enc->msg_len / 4);
 
  if (enc->msg_id & 1) {
    insert_msg_id (c->session, enc->msg_id);
  }
  assert (c->session->session_id == enc->session_id);
  rpc_execute_answer (c, enc->msg_id);
  assert (in_ptr == in_end);
  return 0;
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
      cout << "Server error " << op << endl;
    } else {
      process_rpc_message (c, (encrypted_message *)(Response/* + 8*/), Response_len/* - 12*/);
    }
#if !defined(__MACH__) && !defined(__FreeBSD__) && !defined (__CYGWIN__)
//    setsockopt (c->fd, IPPROTO_TCP, TCP_QUICKACK, (int[]){0}, 4);
#endif
    return 0;
  default:
    cout << "fatal: cannot receive answer in statec " << c_state << endl;
    exit (2);
  }
 
  return 0;
}


int rpc_becomes_ready (struct connection *c) {

  cout << "outbound connection " << c->fd << " becomes ready" << endl;

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