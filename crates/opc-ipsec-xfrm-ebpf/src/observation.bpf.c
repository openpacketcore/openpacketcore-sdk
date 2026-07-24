// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
/*
 * Post-authentication, post-final-replay-check ESP-in-UDP peer observation.
 *
 * This object deliberately uses fentry/fexit rather than XFRM_MSG_MAPPING:
 * Linux emits the latter before the final replay recheck, so a concurrently
 * replayed packet can otherwise manufacture a relocation candidate.
 *
 * Kernel layouts below are intentionally minimal CO-RE views. They are not
 * copied host layouts: every access carrying kernel provenance has a BTF
 * field relocation and the build rejects an object with no CO-RE records.
 */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

#define SEC(name) __attribute__((section(name), used))
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define PRESERVE_ACCESS_INDEX __attribute__((preserve_access_index))
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_F_NO_PREALLOC 1

#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_HOPOPTS 0
#define IPPROTO_UDP 17
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ESP 50
#define IPPROTO_AH 51
#define IPPROTO_DSTOPTS 60

#define UDP_ENCAP_ESPINUDP 2
#define CRYPTO_DONE 2
#define XFRM_STATE_DEAD 5
#define XFRM_SA_DIR_IN 1

#define AUTHORITY_OK 0
#define AUTHORITY_OFFLOAD 1
#define AUTHORITY_REPLAY_DISABLED 2
#define AUTHORITY_UNAUTHENTICATED 3
#define AUTHORITY_UNSUPPORTED_ENCAP 4
#define AUTHORITY_UNSUPPORTED_SA 5
#define AUTHORITY_MALFORMED_PACKET 6
#define AUTHORITY_STATE_MISSING 7
#define AUTHORITY_NAMESPACE_UNKNOWN 8
#define AUTHORITY_COUNTER_EXHAUSTED 9
#define AUTHORITY_LIFECYCLE_CHANGED 10

#define STAT_RECHECK_ACCEPTED 0
#define STAT_UNREGISTERED 1
#define STAT_CURRENT_SOURCE 2
#define STAT_DUPLICATE_SOURCE 3
#define STAT_EVENTS 4
#define STAT_RING_DROPPED 5
#define STAT_PARSE_FAILED 6
#define STAT_OFFLOAD 7
#define STAT_REPLAY_DISABLED 8
#define STAT_UNAUTHENTICATED 9
#define STAT_UNSUPPORTED_SA 10
#define STAT_INTERNAL_FAILURE 11
#define STAT_COUNT 12

#define ACTIVE_SOURCE_GATE (1ULL << 63)
#define ACTIVE_COUNT_MASK (~ACTIVE_SOURCE_GATE)
#define MAX_EXTENSION_HEADERS 8
#define MAX_ATOMIC_ATTEMPTS 64

enum bpf_enum_value_kind {
  BPF_ENUMVAL_EXISTS = 0,
  BPF_ENUMVAL_VALUE = 1,
};

enum bpf_field_info_kind {
  BPF_FIELD_EXISTS = 2,
};

#define CORE_ENUM_EXISTS(enum_type, enum_value)                                \
  __builtin_preserve_enum_value(*(typeof(enum_type) *)enum_value,              \
                                BPF_ENUMVAL_EXISTS)
#define CORE_ENUM_VALUE(enum_type, enum_value)                                 \
  __builtin_preserve_enum_value(*(typeof(enum_type) *)enum_value,              \
                                BPF_ENUMVAL_VALUE)
#define CORE_FIELD_EXISTS(accessor)                                            \
  __builtin_preserve_field_info(accessor, BPF_FIELD_EXISTS)

static void *(*const bpf_map_lookup_elem)(void *map,
                                          const void *key) = (void *)1;
static long (*const bpf_probe_read_kernel)(
    void *dst, u32 size, const void *unsafe_ptr) = (void *)113;
static void *(*const bpf_ringbuf_reserve)(void *ringbuf, u64 size,
                                          u64 flags) = (void *)131;
static void (*const bpf_ringbuf_submit)(void *data, u64 flags) = (void *)132;
static void (*const bpf_ringbuf_discard)(void *data, u64 flags) = (void *)133;
static long (*const bpf_for_each_map_elem)(void *map, void *callback,
                                           void *context,
                                           u64 flags) = (void *)164;

#define CORE_ADDRESS(accessor) __builtin_preserve_access_index(accessor)
#define CORE_READ(destination, accessor)                                       \
  bpf_probe_read_kernel((destination), sizeof(*(destination)),                 \
                        CORE_ADDRESS(accessor))

struct net {
  u64 net_cookie;
} PRESERVE_ACCESS_INDEX;

typedef struct {
  struct net *net;
} possible_net_t;

typedef union {
  u32 a4;
  u32 a6[4];
  u8 bytes[16];
} xfrm_address_t;

struct xfrm_id {
  xfrm_address_t daddr;
  u32 spi;
  u8 proto;
} PRESERVE_ACCESS_INDEX;

struct xfrm_mark {
  u32 v;
  u32 m;
} PRESERVE_ACCESS_INDEX;

struct xfrm_encap_tmpl {
  u16 encap_type;
  u16 encap_sport;
  u16 encap_dport;
  xfrm_address_t encap_oa;
} PRESERVE_ACCESS_INDEX;

struct xfrm_replay_state_esn {
  u32 bmp_len;
  u32 oseq;
  u32 seq;
  u32 oseq_hi;
  u32 seq_hi;
  u32 replay_window;
} PRESERVE_ACCESS_INDEX;

enum xfrm_replay_mode {
  XFRM_REPLAY_MODE_LEGACY = 0,
  XFRM_REPLAY_MODE_BMP = 1,
  XFRM_REPLAY_MODE_ESN = 2,
};

enum skb_ext_id {
  SKB_EXT_SEC_PATH = 1,
};

struct xfrm_dev_offload {
  void *dev;
} PRESERVE_ACCESS_INDEX;

struct xfrm_state_walk {
  u8 state;
} PRESERVE_ACCESS_INDEX;

struct xfrm_state {
  possible_net_t xs_net;
  struct xfrm_id id;
  struct xfrm_mark mark;
  u32 if_id;
  struct xfrm_state_walk km;
  struct {
    u32 reqid;
    u8 mode;
    u8 replay_window;
    u8 aalgo;
    u8 ealgo;
    u8 calgo;
    u8 flags;
    u16 family;
    xfrm_address_t saddr;
  } props;
  void *aalg;
  void *ealg;
  void *calg;
  void *aead;
  const char *geniv;
  u16 new_mapping_sport;
  u32 new_mapping;
  u32 mapping_maxage;
  struct xfrm_encap_tmpl *encap;
  u32 nat_keepalive_interval;
  long long nat_keepalive_expiration;
  xfrm_address_t *coaddr;
  struct xfrm_state *tunnel;
  u32 tunnel_users;
  struct {
    u32 oseq;
    u32 seq;
    u32 bitmap;
  } replay;
  struct xfrm_replay_state_esn *replay_esn;
  struct {
    u32 oseq;
    u32 seq;
    u32 bitmap;
  } preplay;
  struct xfrm_replay_state_esn *preplay_esn;
  enum xfrm_replay_mode repl_mode;
  u32 xflags;
  u32 replay_maxage;
  u32 replay_maxdiff;
  char omitted_before_xso[1];
  struct xfrm_dev_offload xso;
  u8 dir;
} PRESERVE_ACCESS_INDEX;

struct skb_ext;

struct sk_buff {
  char cb[48];
  u8 active_extensions;
  int skb_iif;
  u16 transport_header;
  u16 network_header;
  u32 tail;
  unsigned char *head;
  struct skb_ext *extensions;
} PRESERVE_ACCESS_INDEX;

struct skb_ext {
  u32 refcnt;
  u8 offset[5];
  u8 chunks;
  char data[0];
} PRESERVE_ACCESS_INDEX;

struct xfrm_offload {
  struct {
    u32 low;
    u32 hi;
  } seq;
  u32 flags;
  u32 status;
  u32 orig_mac_len;
  u8 proto;
  u8 inner_ipproto;
} PRESERVE_ACCESS_INDEX;

struct sec_path {
  int len;
  int olen;
  int verified_cnt;
  struct xfrm_state *xvec[6];
  struct xfrm_offload ovec[1];
} PRESERVE_ACCESS_INDEX;

struct xfrm_skb_cb {
  char header[24];
  union {
    struct {
      u32 low;
      u32 hi;
    } output;
    struct {
      u32 low;
      u32 hi;
    } input;
  } seq;
} PRESERVE_ACCESS_INDEX;

struct observation_sa_key {
  u64 net_cookie;
  u32 mark_value;
  u32 mark_mask;
  u32 if_id;
  u32 spi_be;
  u16 family;
  u8 protocol;
  u8 direction;
  u8 reserved[4];
  u8 destination[16];
};

struct observation_registration {
  u64 source_scope;
  u64 epoch;
  u64 lifecycle_generation;
  u64 armed;
};

struct observation_lifecycle {
  u64 generation;
};

struct observation_state_key {
  struct observation_sa_key sa;
  u64 epoch;
};

struct observation_state {
  u64 active;
  u64 cursor;
  u64 dropped;
  u64 authority_lost;
  u16 last_source_family;
  u16 last_source_port_be;
  u8 last_source_valid;
  u8 reserved[3];
  u8 last_source_address[16];
};

struct observation_record {
  struct observation_sa_key key;
  u64 source_scope;
  u64 epoch;
  u64 cursor;
  u64 dropped_total;
  u32 sequence_low;
  u32 sequence_high;
  u32 ingress_ifindex;
  u16 outer_source_family;
  u16 outer_source_port;
  u8 outer_source_address[16];
};

struct observation_source_state {
  u64 authority_lost;
  u64 failures;
};

struct observed_source {
  u16 family;
  u16 port_be;
  u16 port_host;
  u16 reserved;
  u8 address[16];
};

_Static_assert(sizeof(struct observation_sa_key) == 48, "SA key ABI");
_Static_assert(sizeof(struct observation_registration) == 32,
               "registration ABI");
_Static_assert(sizeof(struct observation_lifecycle) == 8, "lifecycle ABI");
_Static_assert(sizeof(struct observation_state_key) == 56, "state key ABI");
_Static_assert(sizeof(struct observation_state) == 56, "state ABI");
_Static_assert(sizeof(struct observation_record) == 112, "record ABI");
_Static_assert(sizeof(struct observation_source_state) == 16, "source ABI");
_Static_assert(__builtin_offsetof(struct observation_sa_key, destination) == 32,
               "SA key address offset");
_Static_assert(__builtin_offsetof(struct observation_registration,
                                  lifecycle_generation) == 16,
               "registration lifecycle offset");
_Static_assert(__builtin_offsetof(struct observation_registration, armed) == 24,
               "registration armed offset");
_Static_assert(__builtin_offsetof(struct observation_state, authority_lost) ==
                   24,
               "state authority offset");
_Static_assert(__builtin_offsetof(struct observation_state,
                                  last_source_address) == 40,
               "state source offset");
_Static_assert(__builtin_offsetof(struct observation_record, source_scope) ==
                   48,
               "record scope offset");
_Static_assert(__builtin_offsetof(struct observation_record, sequence_low) ==
                   80,
               "record sequence offset");
_Static_assert(__builtin_offsetof(struct observation_record,
                                  outer_source_address) == 96,
               "record address offset");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct observation_sa_key);
  __type(value, struct observation_registration);
} XFRM_OBS_REGS SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct observation_state_key);
  __type(value, struct observation_state);
} XFRM_OBS_STATE SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} XFRM_OBS_EVENTS SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, STAT_COUNT);
  __type(key, u32);
  __type(value, u64);
} XFRM_OBS_STATS SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct observation_source_state);
} XFRM_OBS_SOURCE SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct observation_sa_key);
  __type(value, struct observation_lifecycle);
} XFRM_OBS_LIFE SEC(".maps");

static ALWAYS_INLINE u16 byte_swap_u16(u16 value) {
  return __builtin_bswap16(value);
}

static ALWAYS_INLINE u32 byte_swap_u32(u32 value) {
  return __builtin_bswap32(value);
}

static ALWAYS_INLINE void copy_address(u8 destination[16], const u8 source[16],
                                       u16 family) {
  if (family == AF_INET) {
    __builtin_memcpy(destination, source, 4);
    __builtin_memset(&destination[4], 0, 12);
  } else {
    __builtin_memcpy(destination, source, 16);
  }
}

static ALWAYS_INLINE int address_equal(const u8 left[16], const u8 right[16],
                                       u16 family) {
  if (left[0] != right[0] || left[1] != right[1] || left[2] != right[2] ||
      left[3] != right[3])
    return 0;
  if (family == AF_INET)
    return 1;
  return left[4] == right[4] && left[5] == right[5] && left[6] == right[6] &&
         left[7] == right[7] && left[8] == right[8] && left[9] == right[9] &&
         left[10] == right[10] && left[11] == right[11] &&
         left[12] == right[12] && left[13] == right[13] &&
         left[14] == right[14] && left[15] == right[15];
}

static ALWAYS_INLINE void increment_stat(u32 index) {
  u64 *counter = bpf_map_lookup_elem(&XFRM_OBS_STATS, &index);

  if (counter)
    (*counter)++;
}

/*
 * Increment without ever publishing a wrapped intermediate value. A bounded
 * CAS retry is required because several CPUs can account explicit loss while
 * the source-tuple gate is owned elsewhere.
 */
static ALWAYS_INLINE int increment_nonwrapping(u64 *value, u64 maximum,
                                               u64 *updated) {
#pragma clang loop unroll(disable)
  for (u32 attempt = 0; attempt < MAX_ATOMIC_ATTEMPTS; attempt++) {
    u64 observed = __sync_val_compare_and_swap(value, 0, 0);

    if (observed == maximum)
      return -1;
    if (__sync_val_compare_and_swap(value, observed, observed + 1) ==
        observed) {
      if (updated)
        *updated = observed + 1;
      return 0;
    }
  }
  return -1;
}

static ALWAYS_INLINE void lose_source_authority(u64 reason) {
  u32 index = 0;
  struct observation_source_state *source =
      bpf_map_lookup_elem(&XFRM_OBS_SOURCE, &index);

  if (!source)
    return;
  __sync_val_compare_and_swap(&source->authority_lost, AUTHORITY_OK, reason);
  increment_nonwrapping(&source->failures, ~0ULL, 0);
}

static ALWAYS_INLINE void lose_sa_authority(struct observation_state *state,
                                            u64 reason) {
  __sync_val_compare_and_swap(&state->authority_lost, AUTHORITY_OK, reason);
}

static ALWAYS_INLINE int build_sa_key(struct xfrm_state *x,
                                      struct observation_sa_key *key) {
  struct net *net = 0;
  xfrm_address_t destination = {};
  u8 kernel_direction = 0;

  if (CORE_READ(&net, &x->xs_net.net) || !net)
    return -1;
  if (CORE_READ(&key->net_cookie, &net->net_cookie) || key->net_cookie == 0)
    return -1;
  if (CORE_READ(&key->mark_value, &x->mark.v) ||
      CORE_READ(&key->mark_mask, &x->mark.m) ||
      CORE_READ(&key->if_id, &x->if_id) ||
      CORE_READ(&key->spi_be, &x->id.spi) ||
      CORE_READ(&key->family, &x->props.family) ||
      CORE_READ(&key->protocol, &x->id.proto) ||
      CORE_READ(&destination, &x->id.daddr))
    return -1;
  if (CORE_FIELD_EXISTS(x->dir) && CORE_READ(&kernel_direction, &x->dir))
    return -1;

  /* __xfrm_state_insert sanitizes this only after its fentry hook runs. */
  key->mark_value &= key->mark_mask;
  /*
   * Legacy installs omit XFRMA_SA_DIR and retain zero. The replay hooks prove
   * input semantics, so canonicalize zero to the SDK's inbound key while
   * preserving explicit OUT (and unknown future values) as nonmatching.
   */
  key->direction = kernel_direction == 0 ? XFRM_SA_DIR_IN : kernel_direction;
  copy_address(key->destination, destination.bytes, key->family);
  return 0;
}

static ALWAYS_INLINE int
registrations_equal(const struct observation_registration *left,
                    const struct observation_registration *right) {
  return left && right && left->source_scope == right->source_scope &&
         left->epoch == right->epoch &&
         left->lifecycle_generation == right->lifecycle_generation &&
         left->armed == right->armed && left->source_scope != 0 &&
         left->epoch != 0 && left->lifecycle_generation != 0 &&
         left->armed <= 1;
}

static ALWAYS_INLINE int increment_active(struct observation_state *state) {
#pragma clang loop unroll(disable)
  for (u32 attempt = 0; attempt < MAX_ATOMIC_ATTEMPTS; attempt++) {
    u64 observed = __sync_val_compare_and_swap(&state->active, 0, 0);
    u64 count = observed & ACTIVE_COUNT_MASK;

    if (count == ACTIVE_COUNT_MASK)
      return -1;
    if (__sync_val_compare_and_swap(&state->active, observed, observed + 1) ==
        observed)
      return 0;
  }
  return -1;
}

/*
 * Returns one admitted state pointer. The active count closes teardown's map
 * lifetime race; the second registration lookup closes lifecycle ABA.
 */
static ALWAYS_INLINE struct observation_state *
admit_lifecycle(const struct observation_sa_key *key,
                struct observation_registration *registration) {
  struct observation_registration *published =
      bpf_map_lookup_elem(&XFRM_OBS_REGS, key);
  struct observation_state_key state_key = {};
  struct observation_state *state;
  struct observation_lifecycle *lifecycle;

  if (!published) {
    increment_stat(STAT_UNREGISTERED);
    return 0;
  }
  __builtin_memcpy(registration, published, sizeof(*registration));
  if (registration->source_scope == 0 || registration->epoch == 0 ||
      registration->lifecycle_generation == 0 || registration->armed > 1) {
    lose_source_authority(AUTHORITY_STATE_MISSING);
    increment_stat(STAT_INTERNAL_FAILURE);
    return 0;
  }

  state_key.sa = *key;
  state_key.epoch = registration->epoch;
  state = bpf_map_lookup_elem(&XFRM_OBS_STATE, &state_key);
  if (!state) {
    /*
     * A missing state is benign when teardown removed the registration
     * between the two lookups. It is terminal only while the same
     * authority is still published.
     */
    published = bpf_map_lookup_elem(&XFRM_OBS_REGS, key);
    if (registrations_equal(registration, published)) {
      lose_source_authority(AUTHORITY_STATE_MISSING);
      increment_stat(STAT_INTERNAL_FAILURE);
    }
    return 0;
  }

  if (registration->armed == 0)
    return 0;
  lifecycle = bpf_map_lookup_elem(&XFRM_OBS_LIFE, key);
  if (!lifecycle || __sync_val_compare_and_swap(&lifecycle->generation, 0, 0) !=
                        registration->lifecycle_generation) {
    published = bpf_map_lookup_elem(&XFRM_OBS_REGS, key);
    if (registrations_equal(registration, published))
      lose_sa_authority(state, AUTHORITY_LIFECYCLE_CHANGED);
    return 0;
  }

  if (increment_active(state)) {
    lose_sa_authority(state, AUTHORITY_COUNTER_EXHAUSTED);
    increment_stat(STAT_INTERNAL_FAILURE);
    return 0;
  }

  published = bpf_map_lookup_elem(&XFRM_OBS_REGS, key);
  lifecycle = bpf_map_lookup_elem(&XFRM_OBS_LIFE, key);
  if (!registrations_equal(registration, published) || !lifecycle ||
      __sync_val_compare_and_swap(&lifecycle->generation, 0, 0) !=
          registration->lifecycle_generation) {
    if (registrations_equal(registration, published))
      lose_sa_authority(state, AUTHORITY_LIFECYCLE_CHANGED);
    __sync_fetch_and_sub(&state->active, 1);
    return 0;
  }
  return state;
}

static ALWAYS_INLINE void release_lifecycle(struct observation_state *state) {
  __sync_fetch_and_sub(&state->active, 1);
}

static ALWAYS_INLINE int
lifecycle_is_current(const struct observation_sa_key *key,
                     const struct observation_registration *registration,
                     struct observation_state *state) {
  struct observation_registration *published;
  struct observation_lifecycle *lifecycle;

  if (__sync_val_compare_and_swap(&state->authority_lost, 0, 0) != AUTHORITY_OK)
    return 0;
  published = bpf_map_lookup_elem(&XFRM_OBS_REGS, key);
  lifecycle = bpf_map_lookup_elem(&XFRM_OBS_LIFE, key);
  return registrations_equal(registration, published) &&
         registration->armed == 1 && lifecycle &&
         __sync_val_compare_and_swap(&lifecycle->generation, 0, 0) ==
             registration->lifecycle_generation;
}

static ALWAYS_INLINE int packet_crypto_done(struct sk_buff *skb) {
  u8 active = 0;
  struct skb_ext *extensions = 0;
  u8 offset = 0;
  const u8 *offsets;
  u64 sec_path_id;
  struct sec_path *path;
  int len = 0;
  int olen = 0;
  u32 flags = 0;

  if (!CORE_ENUM_EXISTS(enum skb_ext_id, SKB_EXT_SEC_PATH))
    return -1;
  sec_path_id = CORE_ENUM_VALUE(enum skb_ext_id, SKB_EXT_SEC_PATH);
  if (sec_path_id >= 8)
    return -1;
  if (CORE_READ(&active, &skb->active_extensions))
    return -1;
  if (!(active & (1U << sec_path_id)))
    return 0;
  if (CORE_READ(&extensions, &skb->extensions) || !extensions)
    return -1;
  offsets = CORE_ADDRESS(&extensions->offset[0]);
  if (bpf_probe_read_kernel(&offset, sizeof(offset), offsets + sec_path_id) ||
      offset == 0)
    return -1;

  path = (struct sec_path *)((u8 *)extensions + ((u32)offset << 3));
  if (CORE_READ(&len, &path->len) || CORE_READ(&olen, &path->olen))
    return -1;
  if (olen == 0)
    return 0;
  if (olen != 1 || len != olen)
    return -1;
  if (CORE_READ(&flags, &path->ovec[0].flags))
    return -1;
  return (flags & CRYPTO_DONE) != 0;
}

static ALWAYS_INLINE u64 sa_authority_reason(struct xfrm_state *x,
                                             struct sk_buff *skb) {
  void *offload_device = 0;
  int crypto_done;
  u8 replay_window = 0;
  enum xfrm_replay_mode replay_mode;
  struct xfrm_replay_state_esn *replay_esn = 0;
  u32 esn_replay_window = 0;
  void *authentication = 0;
  void *aead = 0;
  struct xfrm_encap_tmpl *encap = 0;
  u16 encap_type = 0;
  u8 protocol = 0;
  u16 family = 0;

  if (CORE_READ(&offload_device, &x->xso.dev))
    return AUTHORITY_UNSUPPORTED_SA;
  if (offload_device)
    return AUTHORITY_OFFLOAD;
  crypto_done = packet_crypto_done(skb);
  if (crypto_done < 0)
    return AUTHORITY_UNSUPPORTED_SA;
  if (crypto_done)
    return AUTHORITY_OFFLOAD;

  if (CORE_READ(&replay_mode, &x->repl_mode) ||
      CORE_READ(&replay_window, &x->props.replay_window) ||
      CORE_READ(&replay_esn, &x->replay_esn))
    return AUTHORITY_REPLAY_DISABLED;
  if (!CORE_ENUM_EXISTS(enum xfrm_replay_mode, XFRM_REPLAY_MODE_LEGACY) ||
      !CORE_ENUM_EXISTS(enum xfrm_replay_mode, XFRM_REPLAY_MODE_BMP) ||
      !CORE_ENUM_EXISTS(enum xfrm_replay_mode, XFRM_REPLAY_MODE_ESN))
    return AUTHORITY_REPLAY_DISABLED;
  if ((u64)replay_mode ==
      CORE_ENUM_VALUE(enum xfrm_replay_mode, XFRM_REPLAY_MODE_LEGACY)) {
    if (replay_window == 0)
      return AUTHORITY_REPLAY_DISABLED;
  } else if ((u64)replay_mode ==
                 CORE_ENUM_VALUE(enum xfrm_replay_mode, XFRM_REPLAY_MODE_BMP) ||
             (u64)replay_mode ==
                 CORE_ENUM_VALUE(enum xfrm_replay_mode, XFRM_REPLAY_MODE_ESN)) {
    if (!replay_esn ||
        CORE_READ(&esn_replay_window, &replay_esn->replay_window) ||
        esn_replay_window == 0)
      return AUTHORITY_REPLAY_DISABLED;
  } else {
    return AUTHORITY_REPLAY_DISABLED;
  }

  if (CORE_READ(&authentication, &x->aalg) || CORE_READ(&aead, &x->aead))
    return AUTHORITY_UNAUTHENTICATED;
  if (!authentication && !aead)
    return AUTHORITY_UNAUTHENTICATED;

  if (CORE_READ(&protocol, &x->id.proto) ||
      CORE_READ(&family, &x->props.family))
    return AUTHORITY_UNSUPPORTED_SA;
  if (protocol != IPPROTO_ESP || (family != AF_INET && family != AF_INET6))
    return AUTHORITY_UNSUPPORTED_SA;

  if (CORE_READ(&encap, &x->encap) || !encap)
    return AUTHORITY_UNSUPPORTED_ENCAP;
  if (CORE_READ(&encap_type, &encap->encap_type))
    return AUTHORITY_UNSUPPORTED_ENCAP;
  if (encap_type != UDP_ENCAP_ESPINUDP)
    return AUTHORITY_UNSUPPORTED_ENCAP;
  return AUTHORITY_OK;
}

static ALWAYS_INLINE void
account_authority_reason(struct observation_state *state, u64 reason) {
  if (reason == AUTHORITY_OK)
    return;
  lose_sa_authority(state, reason);
  if (reason == AUTHORITY_OFFLOAD)
    increment_stat(STAT_OFFLOAD);
  else if (reason == AUTHORITY_REPLAY_DISABLED)
    increment_stat(STAT_REPLAY_DISABLED);
  else if (reason == AUTHORITY_UNAUTHENTICATED)
    increment_stat(STAT_UNAUTHENTICATED);
  else
    increment_stat(STAT_UNSUPPORTED_SA);
}

static ALWAYS_INLINE int
read_kernel_bytes(void *destination, const unsigned char *source, u32 length) {
  return bpf_probe_read_kernel(destination, length, source);
}

static ALWAYS_INLINE int head_range_valid(u32 offset, u32 length, u32 tail) {
  return offset <= tail && length <= tail - offset;
}

static ALWAYS_INLINE int parse_outer_source(struct sk_buff *skb, u16 family,
                                            u32 expected_spi_be,
                                            struct observed_source *source) {
  unsigned char *head = 0;
  u16 network_header = 0;
  u32 tail = 0;
  u32 cursor_offset;
  const unsigned char *cursor;
  u8 ipv4[20] = {};
  u8 ipv6[40] = {};
  u8 extension[8] = {};
  u8 udp[12] = {};
  u8 next_header;
  u32 header_length;

  if (CORE_READ(&head, &skb->head) || !head ||
      CORE_READ(&network_header, &skb->network_header) ||
      CORE_READ(&tail, &skb->tail))
    return -1;
  cursor_offset = network_header;
  cursor = head + cursor_offset;

  if (family == AF_INET) {
    if (!head_range_valid(cursor_offset, sizeof(ipv4), tail))
      return -1;
    if (read_kernel_bytes(ipv4, cursor, sizeof(ipv4)))
      return -1;
    if ((ipv4[0] >> 4) != 4)
      return -1;
    /* Permit DF, but reject reserved/MF flags and every fragment offset. */
    if ((ipv4[6] & 0xbf) != 0 || ipv4[7] != 0)
      return -1;
    header_length = (u32)(ipv4[0] & 0x0f) * 4;
    if (header_length < sizeof(ipv4) || header_length > 60)
      return -1;
    if (!head_range_valid(cursor_offset, header_length, tail))
      return -1;
    next_header = ipv4[9];
    source->family = AF_INET;
    copy_address(source->address, &ipv4[12], AF_INET);
    cursor_offset += header_length;
    cursor = head + cursor_offset;
  } else if (family == AF_INET6) {
    if (!head_range_valid(cursor_offset, sizeof(ipv6), tail))
      return -1;
    if (read_kernel_bytes(ipv6, cursor, sizeof(ipv6)))
      return -1;
    if ((ipv6[0] >> 4) != 6)
      return -1;
    next_header = ipv6[6];
    source->family = AF_INET6;
    copy_address(source->address, &ipv6[8], AF_INET6);
    cursor_offset += sizeof(ipv6);
    cursor = head + cursor_offset;

#pragma clang loop unroll(disable)
    for (u32 index = 0; index < MAX_EXTENSION_HEADERS; index++) {
      if (next_header == IPPROTO_UDP)
        break;
      if (!head_range_valid(cursor_offset, sizeof(extension), tail))
        return -1;
      if (read_kernel_bytes(extension, cursor, sizeof(extension)))
        return -1;
      if (next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_ROUTING ||
          next_header == IPPROTO_DSTOPTS) {
        next_header = extension[0];
        header_length = ((u32)extension[1] + 1) * 8;
      } else if (next_header == IPPROTO_FRAGMENT) {
        /*
         * XFRM receives reassembled traffic. Refuse a non-zero
         * fragment offset rather than attributing a partial packet.
         */
        if (extension[2] != 0 || extension[3] != 0)
          return -1;
        next_header = extension[0];
        header_length = 8;
      } else if (next_header == IPPROTO_AH) {
        next_header = extension[0];
        header_length = ((u32)extension[1] + 2) * 4;
      } else {
        return -1;
      }
      if (header_length < 8 || header_length > 1024)
        return -1;
      if (!head_range_valid(cursor_offset, header_length, tail))
        return -1;
      cursor_offset += header_length;
      cursor = head + cursor_offset;
    }
  } else {
    return -1;
  }

  if (next_header != IPPROTO_UDP)
    return -1;
  if (!head_range_valid(cursor_offset, sizeof(udp), tail))
    return -1;
  if (read_kernel_bytes(udp, cursor, sizeof(udp)))
    return -1;
  source->port_host = ((u16)udp[0] << 8) | udp[1];
  source->port_be = byte_swap_u16(source->port_host);
  if (source->port_be == 0)
    return -1;
  if (udp[8] != ((const u8 *)&expected_spi_be)[0] ||
      udp[9] != ((const u8 *)&expected_spi_be)[1] ||
      udp[10] != ((const u8 *)&expected_spi_be)[2] ||
      udp[11] != ((const u8 *)&expected_spi_be)[3])
    return -1;
  return 0;
}

static ALWAYS_INLINE int
source_is_current(struct xfrm_state *x, const struct observed_source *source) {
  xfrm_address_t current_address = {};
  struct xfrm_encap_tmpl *encap = 0;
  u16 current_port_be = 0;

  if (CORE_READ(&current_address, &x->props.saddr) ||
      CORE_READ(&encap, &x->encap) || !encap ||
      CORE_READ(&current_port_be, &encap->encap_sport))
    return -1;
  if (current_port_be != source->port_be)
    return 0;
  return address_equal(current_address.bytes, source->address, source->family);
}

static ALWAYS_INLINE int
source_is_duplicate(const struct observation_state *state,
                    const struct observed_source *source) {
  if (!state->last_source_valid ||
      state->last_source_family != source->family ||
      state->last_source_port_be != source->port_be)
    return 0;
  return address_equal(state->last_source_address, source->address,
                       source->family);
}

static ALWAYS_INLINE int acquire_source_gate(struct observation_state *state) {
#pragma clang loop unroll(full)
  for (u32 attempt = 0; attempt < 4; attempt++) {
    u64 observed = __sync_fetch_and_or(&state->active, ACTIVE_SOURCE_GATE);

    if (!(observed & ACTIVE_SOURCE_GATE))
      return 1;
  }
  return 0;
}

static ALWAYS_INLINE void release_source_gate(struct observation_state *state) {
  __sync_fetch_and_and(&state->active, ACTIVE_COUNT_MASK);
}

static ALWAYS_INLINE int allocate_cursor(struct observation_state *state,
                                         u64 *cursor) {
  if (increment_nonwrapping(&state->cursor, ~0ULL, cursor)) {
    lose_sa_authority(state, AUTHORITY_COUNTER_EXHAUSTED);
    increment_stat(STAT_INTERNAL_FAILURE);
    return -1;
  }
  return 0;
}

static ALWAYS_INLINE void
account_delivery_loss(struct observation_state *state) {
  if (increment_nonwrapping(&state->dropped, ~0ULL, 0)) {
    lose_sa_authority(state, AUTHORITY_COUNTER_EXHAUSTED);
    increment_stat(STAT_INTERNAL_FAILURE);
  } else {
    increment_stat(STAT_RING_DROPPED);
  }
}

static ALWAYS_INLINE void
account_lifecycle_delivery_loss(struct observation_state *state) {
  if (increment_nonwrapping(&state->dropped, ~0ULL, 0)) {
    lose_sa_authority(state, AUTHORITY_COUNTER_EXHAUSTED);
    increment_stat(STAT_INTERNAL_FAILURE);
  }
}

static ALWAYS_INLINE void
remember_source(struct observation_state *state,
                const struct observed_source *source) {
  state->last_source_family = source->family;
  state->last_source_port_be = source->port_be;
  copy_address(state->last_source_address, source->address, source->family);
  state->last_source_valid = 1;
}

static ALWAYS_INLINE void
poison_live_lifecycle(const struct observation_sa_key *key,
                      struct observation_lifecycle *lifecycle) {
  struct observation_registration registration = {};
  struct observation_registration *published;
  struct observation_state_key state_key = {};
  struct observation_state *state = 0;

  published = bpf_map_lookup_elem(&XFRM_OBS_REGS, key);
  if (published) {
    __builtin_memcpy(&registration, published, sizeof(registration));
    if (registration.epoch != 0) {
      state_key.sa = *key;
      state_key.epoch = registration.epoch;
      state = bpf_map_lookup_elem(&XFRM_OBS_STATE, &state_key);
    }
  }

  if (increment_nonwrapping(&lifecycle->generation, ~0ULL, 0)) {
    lose_source_authority(AUTHORITY_COUNTER_EXHAUSTED);
    if (state)
      lose_sa_authority(state, AUTHORITY_COUNTER_EXHAUSTED);
    increment_stat(STAT_INTERNAL_FAILURE);
    return;
  }
  if (state)
    lose_sa_authority(state, AUTHORITY_LIFECYCLE_CHANGED);
}

static ALWAYS_INLINE void
poison_exact_lifecycle(const struct observation_sa_key *key) {
  struct observation_lifecycle *lifecycle =
      bpf_map_lookup_elem(&XFRM_OBS_LIFE, key);

  if (lifecycle) {
    poison_live_lifecycle(key, lifecycle);
    return;
  }

  /*
   * Untracked SAs are intentionally ignored. A published registration
   * without its generation map entry is an internal fail-closed violation.
   */
  if (bpf_map_lookup_elem(&XFRM_OBS_REGS, key)) {
    lose_source_authority(AUTHORITY_STATE_MISSING);
    increment_stat(STAT_INTERNAL_FAILURE);
  }
}

static ALWAYS_INLINE int poison_exact_from_context(u64 *context) {
  struct xfrm_state *x = (struct xfrm_state *)(unsigned long)context[0];
  struct observation_sa_key key = {};

  if (!x || build_sa_key(x, &key)) {
    lose_source_authority(AUTHORITY_NAMESPACE_UNKNOWN);
    increment_stat(STAT_INTERNAL_FAILURE);
    return 0;
  }
  poison_exact_lifecycle(&key);
  return 0;
}

SEC("fentry/__xfrm_state_insert")
int opc_xfrm_insert(u64 *context) { return poison_exact_from_context(context); }

SEC("fentry/__xfrm_state_delete")
int opc_xfrm_delete(u64 *context) {
  struct xfrm_state *x = (struct xfrm_state *)(unsigned long)context[0];
  u8 state = 0;

  if (!x)
    return 0;
  if (CORE_READ(&state, &x->km.state)) {
    lose_source_authority(AUTHORITY_UNSUPPORTED_SA);
    increment_stat(STAT_INTERNAL_FAILURE);
    return 0;
  }
  /* __xfrm_state_delete is a no-op for an already-dead old object. */
  if (state == XFRM_STATE_DEAD)
    return 0;
  return poison_exact_from_context(context);
}

struct update_scan_context {
  struct observation_sa_key request;
};

static ALWAYS_INLINE int
update_identity_matches(const struct observation_sa_key *request,
                        const struct observation_sa_key *candidate) {
  if (candidate->net_cookie == 0 || candidate->spi_be == 0 ||
      candidate->protocol != IPPROTO_ESP ||
      candidate->direction != XFRM_SA_DIR_IN ||
      (candidate->mark_value & candidate->mark_mask) != candidate->mark_value ||
      candidate->reserved[0] != 0 || candidate->reserved[1] != 0 ||
      candidate->reserved[2] != 0 || candidate->reserved[3] != 0)
    return -1;
  if (request->net_cookie != candidate->net_cookie ||
      request->spi_be != candidate->spi_be ||
      request->family != candidate->family ||
      request->protocol != candidate->protocol ||
      request->direction != candidate->direction ||
      (request->mark_value & candidate->mark_mask) != candidate->mark_value)
    return 0;
  return address_equal(request->destination, candidate->destination,
                       request->family);
}

static long poison_matching_update(void *map, const void *raw_key,
                                   void *raw_lifecycle, void *raw_context) {
  const struct observation_sa_key *candidate = raw_key;
  struct observation_lifecycle *lifecycle = raw_lifecycle;
  struct update_scan_context *context = raw_context;
  int matches;

  (void)map;
  matches = update_identity_matches(&context->request, candidate);
  if (matches < 0) {
    lose_source_authority(AUTHORITY_STATE_MISSING);
    increment_stat(STAT_INTERNAL_FAILURE);
    return 1;
  }
  if (matches)
    poison_live_lifecycle(candidate, lifecycle);
  return 0;
}

SEC("fentry/xfrm_state_update")
int opc_xfrm_update(u64 *context) {
  struct xfrm_state *x = (struct xfrm_state *)(unsigned long)context[0];
  struct update_scan_context scan = {};
  long visited;

  if (!x || build_sa_key(x, &scan.request)) {
    lose_source_authority(AUTHORITY_NAMESPACE_UNKNOWN);
    increment_stat(STAT_INTERNAL_FAILURE);
    return 0;
  }
  if (scan.request.direction != XFRM_SA_DIR_IN)
    return 0;
  /*
   * Update lookup ignores if_id and applies the installed state's mark mask.
   * The lifecycle map is bounded, so scan every exact key and poison all
   * candidates that the request can select. Overlapping masks intentionally
   * fail closed rather than guessing which kernel hash entry wins.
   */
  visited = bpf_for_each_map_elem(&XFRM_OBS_LIFE,
                                  (void *)poison_matching_update, &scan, 0);
  if (visited < 0) {
    lose_source_authority(AUTHORITY_STATE_MISSING);
    increment_stat(STAT_INTERNAL_FAILURE);
  }
  return 0;
}

SEC("fentry/xfrm_replay_check")
int opc_xfrm_guard(u64 *context) {
  struct xfrm_state *x = (struct xfrm_state *)(unsigned long)context[0];
  struct sk_buff *skb = (struct sk_buff *)(unsigned long)context[1];
  struct observation_sa_key key = {};
  struct observation_registration registration = {};
  struct observation_state *state;
  u64 reason;

  if (!x || !skb)
    return 0;
  if (build_sa_key(x, &key)) {
    lose_source_authority(AUTHORITY_NAMESPACE_UNKNOWN);
    increment_stat(STAT_INTERNAL_FAILURE);
    return 0;
  }
  state = admit_lifecycle(&key, &registration);
  if (!state)
    return 0;
  reason = sa_authority_reason(x, skb);
  account_authority_reason(state, reason);
  release_lifecycle(state);
  return 0;
}

SEC("fexit/xfrm_replay_recheck")
int opc_xfrm_obs(u64 *context) {
  struct xfrm_state *x = (struct xfrm_state *)(unsigned long)context[0];
  struct sk_buff *skb = (struct sk_buff *)(unsigned long)context[1];
  u32 net_sequence_be = (u32)context[2];
  s32 result = (s32)context[3];
  struct observation_sa_key key = {};
  struct observation_registration registration = {};
  struct observation_state *state;
  struct observed_source source = {};
  struct observation_record *record;
  struct xfrm_skb_cb *control;
  u32 sequence_high_be = 0;
  u32 ingress_ifindex = 0;
  u64 cursor = 0;
  u64 reason;
  int current;
  u64 dropped;

  if (result != 0 || !x || !skb)
    return 0;
  increment_stat(STAT_RECHECK_ACCEPTED);
  if (build_sa_key(x, &key)) {
    lose_source_authority(AUTHORITY_NAMESPACE_UNKNOWN);
    increment_stat(STAT_INTERNAL_FAILURE);
    return 0;
  }
  state = admit_lifecycle(&key, &registration);
  if (!state)
    return 0;

  reason = sa_authority_reason(x, skb);
  if (reason != AUTHORITY_OK) {
    account_authority_reason(state, reason);
    goto out;
  }
  /*
   * The fentry guard may already have terminated this lifecycle on the same
   * packet. It is also possible to publish a registration while async
   * crypto is in flight, so fexit performs the complete checks above and
   * independently refuses every previously terminal lifecycle.
   */
  if (__sync_val_compare_and_swap(&state->authority_lost, 0, 0) != AUTHORITY_OK)
    goto out;
  if (parse_outer_source(skb, key.family, key.spi_be, &source)) {
    lose_sa_authority(state, AUTHORITY_MALFORMED_PACKET);
    increment_stat(STAT_PARSE_FAILED);
    goto out;
  }
  current = source_is_current(x, &source);
  if (current < 0) {
    lose_sa_authority(state, AUTHORITY_MALFORMED_PACKET);
    increment_stat(STAT_PARSE_FAILED);
    goto out;
  }
  if (current) {
    increment_stat(STAT_CURRENT_SOURCE);
    goto out;
  }

  control = (struct xfrm_skb_cb *)CORE_ADDRESS(&skb->cb[0]);
  if (CORE_READ(&sequence_high_be, &control->seq.input.hi) ||
      CORE_READ(&ingress_ifindex, &skb->skb_iif) || ingress_ifindex == 0) {
    lose_sa_authority(state, AUTHORITY_MALFORMED_PACKET);
    increment_stat(STAT_PARSE_FAILED);
    goto out;
  }

  /*
   * A non-spinning atomic gate serializes the private 20-byte tuple. If a
   * busy gate cannot be acquired in the verifier-bounded attempts, account
   * an explicit lost observation and let a later authenticated packet retry.
   */
  if (!acquire_source_gate(state)) {
    if (!allocate_cursor(state, &cursor))
      account_delivery_loss(state);
    goto out;
  }
  if (source_is_duplicate(state, &source)) {
    increment_stat(STAT_DUPLICATE_SOURCE);
    release_source_gate(state);
    goto out;
  }
  if (allocate_cursor(state, &cursor)) {
    release_source_gate(state);
    goto out;
  }

  dropped = __sync_val_compare_and_swap(&state->dropped, 0, 0);
  if (!lifecycle_is_current(&key, &registration, state)) {
    account_lifecycle_delivery_loss(state);
    release_source_gate(state);
    goto out;
  }
  record = bpf_ringbuf_reserve(&XFRM_OBS_EVENTS, sizeof(*record), 0);
  if (!record) {
    account_delivery_loss(state);
    release_source_gate(state);
    goto out;
  }
  __builtin_memset(record, 0, sizeof(*record));
  record->key = key;
  record->source_scope = registration.source_scope;
  record->epoch = registration.epoch;
  record->cursor = cursor;
  record->dropped_total = dropped;
  record->sequence_low = byte_swap_u32(net_sequence_be);
  record->sequence_high = byte_swap_u32(sequence_high_be);
  record->ingress_ifindex = ingress_ifindex;
  record->outer_source_family = source.family;
  record->outer_source_port = source.port_host;
  copy_address(record->outer_source_address, source.address, source.family);
  if (!lifecycle_is_current(&key, &registration, state)) {
    bpf_ringbuf_discard(record, 0);
    account_lifecycle_delivery_loss(state);
    release_source_gate(state);
    goto out;
  }
  bpf_ringbuf_submit(record, 0);
  remember_source(state, &source);
  increment_stat(STAT_EVENTS);
  release_source_gate(state);

out:
  release_lifecycle(state);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
