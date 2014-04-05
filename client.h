char Response[MAX_RESPONSE_SIZE];

int allow_weak_random;
unsigned long long what;
unsigned p1, p2;
int *in_ptr, *in_end;
BIGNUM dh_prime, dh_g, g_a, dh_power, auth_key_num;
char s_power [256];

char *rsa_public_key_name; // = "tg.pub";
RSA *pubKey;
long long pk_fingerprint;

long long rsa_encrypted_chunks, rsa_decrypted_chunks;
BN_CTX *BN_ctx;

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

unsigned char aes_key_raw[32], aes_iv[32];
AES_KEY aes_key;

struct encrypted_message {
  // unencrypted header
  long long auth_key_id;
  char msg_key[16];
  // encrypted part, starts with encrypted header
  long long server_salt;
  long long session_id;
  // long long auth_key_id2; // removed
  // first message follows
  long long msg_id;
  int seq_no;
  int msg_len;   // divisible by 4
  int message[MAX_MESSAGE_INTS];
};

long long client_last_msg_id, server_last_msg_id;
int longpoll_count, good_messages;

int read_in (struct connection *c, void *_data, int len);

struct encrypted_message enc_msg;

#define long_cmp(a,b) ((a) > (b) ? 1 : (a) == (b) ? 0 : -1)
DEFINE_TREE(long,long long,long_cmp,0)