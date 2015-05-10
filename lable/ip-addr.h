/* 
  Base on and follow the iproute2 style
  license: GNU General Public License

  Aaron Yi Ding, University of Helsinki
  yding@cs.helsinki.fi

  last update: 29.10.2010

  reference:
  libnetlink
  utils
  ll_map
  rtm_map
  rt_names
  ip_common

  ipx_pton
  ipx_ntop

  dnet_ntop
  dnet_pton

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <asm/types.h>
#include <linux/pkt_sched.h>
#include <time.h>
#include <sys/time.h>
#include <linux/rtnetlink.h>
#include <resolv.h>
#include <net/if_arp.h>
#include <errno.h>
#include <sys/uio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <net/if.h>




/*
  ip_common
*/

extern int print_linkinfo(const struct sockaddr_nl *who,
			  struct nlmsghdr *n,
			  void *arg);
extern int print_addrinfo(const struct sockaddr_nl *who,
			  struct nlmsghdr *n,
			  void *arg);
extern int print_addrlabel(const struct sockaddr_nl *who,
			   struct nlmsghdr *n, void *arg);
extern int print_neigh(const struct sockaddr_nl *who,
		       struct nlmsghdr *n, void *arg);
extern int print_ntable(const struct sockaddr_nl *who,
			struct nlmsghdr *n, void *arg);
extern int ipaddr_list(int argc, char **argv);
extern int ipaddr_list_link(int argc, char **argv);
extern int iproute_monitor(int argc, char **argv);
extern void iplink_usage(void) __attribute__((noreturn));
extern void iproute_reset_filter(void);
extern void ipaddr_reset_filter(int);
extern void ipneigh_reset_filter(void);
extern void ipntable_reset_filter(void);
extern int print_route(const struct sockaddr_nl *who,
		       struct nlmsghdr *n, void *arg);
extern int print_prefix(const struct sockaddr_nl *who,
			struct nlmsghdr *n, void *arg);
extern int print_rule(const struct sockaddr_nl *who,
		      struct nlmsghdr *n, void *arg);
extern int do_ipaddr(int argc, char **argv);
extern int do_ipaddrlabel(int argc, char **argv);
extern int do_iproute(int argc, char **argv);
extern int do_iprule(int argc, char **argv);
extern int do_ipneigh(int argc, char **argv);
extern int do_ipntable(int argc, char **argv);
extern int do_iptunnel(int argc, char **argv);
extern int do_ip6tunnel(int argc, char **argv);
extern int do_iptuntap(int argc, char **argv);
extern int do_iplink(int argc, char **argv);
extern int do_ipmonitor(int argc, char **argv);
extern int do_multiaddr(int argc, char **argv);
extern int do_multiroute(int argc, char **argv);
extern int do_multirule(int argc, char **argv);
extern int do_xfrm(int argc, char **argv);

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;
	if (tb[RTA_TABLE])
		table = *(__u32*) RTA_DATA(tb[RTA_TABLE]);
	return table;
}

extern struct rtnl_handle rth;

struct link_util
{
	struct link_util	*next;
	const char		*id;
	int			maxattr;
	int			(*parse_opt)(struct link_util *, int, char **,
					     struct nlmsghdr *);
	void			(*print_opt)(struct link_util *, FILE *,
					     struct rtattr *[]);
	void			(*print_xstats)(struct link_util *, FILE *,
					     struct rtattr *);
};

struct link_util *get_link_kind(const char *kind);

#ifndef	INFINITY_LIFE_TIME
#define     INFINITY_LIFE_TIME      0xFFFFFFFFU
#endif


/*
   rt_names
*/

#ifndef RT_NAMES_H_
#define RT_NAMES_H_ 1


char* rtnl_rtprot_n2a(int id, char *buf, int len);
char* rtnl_rtscope_n2a(int id, char *buf, int len);
char* rtnl_rttable_n2a(__u32 id, char *buf, int len);
char* rtnl_rtrealm_n2a(int id, char *buf, int len);
char* rtnl_dsfield_n2a(int id, char *buf, int len);
int rtnl_rtprot_a2n(__u32 *id, char *arg);
int rtnl_rtscope_a2n(__u32 *id, char *arg);
int rtnl_rttable_a2n(__u32 *id, char *arg);
int rtnl_rtrealm_a2n(__u32 *id, char *arg);
int rtnl_dsfield_a2n(__u32 *id, char *arg);

const char *inet_proto_n2a(int proto, char *buf, int len);
int inet_proto_a2n(char *buf);


const char * ll_type_n2a(int type, char *buf, int len);

const char *ll_addr_n2a(unsigned char *addr, int alen, int type, char *buf, int blen);
int ll_addr_a2n(char *lladdr, int len, char *arg);

const char * ll_proto_n2a(unsigned short id, char *buf, int len);
int ll_proto_a2n(unsigned short *id, char *buf);


#endif

/*
  utils
*/

#ifndef __UTILS_H__
#define __UTILS_H__ 1



extern int preferred_family;
extern int show_stats;
extern int show_details;
extern int show_raw;
extern int resolve_hosts;
extern int oneline;
extern int timestamp;
extern char * _SL_;

#ifndef IPPROTO_ESP
#define IPPROTO_ESP	50
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH	51
#endif
#ifndef IPPROTO_COMP
#define IPPROTO_COMP	108
#endif
#ifndef IPSEC_PROTO_ANY
#define IPSEC_PROTO_ANY	255
#endif

#define SPRINT_BSIZE 64
#define SPRINT_BUF(x)	char x[SPRINT_BSIZE]

extern void incomplete_command(void) __attribute__((noreturn));

#define NEXT_ARG() do { argv++; if (--argc <= 0) incomplete_command(); } while(0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define PREV_ARG() do { argv--; argc++; } while(0)

typedef struct
{
	__u8 family;
	__u8 bytelen;
	__s16 bitlen;
	__u32 flags;
	__u32 data[8];
} inet_prefix;

#define PREFIXLEN_SPECIFIED 1

#define DN_MAXADDL 20
#ifndef AF_DECnet
#define AF_DECnet 12
#endif

struct dn_naddr
{
        unsigned short          a_len;
        unsigned char a_addr[DN_MAXADDL];
};

#define IPX_NODE_LEN 6

struct ipx_addr {
	u_int32_t ipx_net;
	u_int8_t  ipx_node[IPX_NODE_LEN];
};

extern __u32 get_addr32(const char *name);
extern int get_addr_1(inet_prefix *dst, const char *arg, int family);
extern int get_prefix_1(inet_prefix *dst, char *arg, int family);
extern int get_addr(inet_prefix *dst, const char *arg, int family);
extern int get_prefix(inet_prefix *dst, char *arg, int family);
extern int mask2bits(__u32 netmask);

extern int get_integer(int *val, const char *arg, int base);
extern int get_unsigned(unsigned *val, const char *arg, int base);
extern int get_jiffies(unsigned *val, const char *arg, int base, int *raw);
#define get_byte get_u8
#define get_ushort get_u16
#define get_short get_s16
extern int get_u64(__u64 *val, const char *arg, int base);
extern int get_u32(__u32 *val, const char *arg, int base);
extern int get_u16(__u16 *val, const char *arg, int base);
extern int get_s16(__s16 *val, const char *arg, int base);
extern int get_u8(__u8 *val, const char *arg, int base);
extern int get_s8(__s8 *val, const char *arg, int base);

extern char* hexstring_n2a(const __u8 *str, int len, char *buf, int blen);
extern __u8* hexstring_a2n(const char *str, __u8 *buf, int blen);

extern const char *format_host(int af, int len, const void *addr,
			       char *buf, int buflen);
extern const char *rt_addr_n2a(int af, int len, const void *addr,
			       char *buf, int buflen);

void missarg(const char *) __attribute__((noreturn));
void invarg(const char *, const char *) __attribute__((noreturn));
void duparg(const char *, const char *) __attribute__((noreturn));
void duparg2(const char *, const char *) __attribute__((noreturn));
int matches(const char *arg, const char *pattern);
extern int inet_addr_match(const inet_prefix *a, const inet_prefix *b, int bits);

const char *dnet_ntop(int af, const void *addr, char *str, size_t len);
int dnet_pton(int af, const char *src, void *addr);

const char *ipx_ntop(int af, const void *addr, char *str, size_t len);
int ipx_pton(int af, const char *src, void *addr);

extern int __iproute2_hz_internal;
extern int __get_hz(void);

static __inline__ int get_hz(void)
{
	if (__iproute2_hz_internal == 0)
		__iproute2_hz_internal = __get_hz();
	return __iproute2_hz_internal;
}

extern int __iproute2_user_hz_internal;
extern int __get_user_hz(void);

static __inline__ int get_user_hz(void)
{
	if (__iproute2_user_hz_internal == 0)
		__iproute2_user_hz_internal = __get_user_hz();
	return __iproute2_user_hz_internal;
}

static inline __u32 nl_mgrp(__u32 group)
{
	if (group > 31 ) {
		fprintf(stderr, "Use setsockopt for this group %d\n", group);
		exit(-1);
	}
	return group ? (1 << (group - 1)) : 0;
}


int print_timestamp(FILE *fp);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

extern int cmdlineno;
extern ssize_t getcmdline(char **line, size_t *len, FILE *in);
extern int makeargs(char *line, char *argv[], int maxargs);

struct iplink_req;
int iplink_parse(int argc, char **argv, struct iplink_req *req,
		char **name, char **type, char **link, char **dev);
#endif /* __UTILS_H__ */


/*
  ll_map
*/

#ifndef __LL_MAP_H__
#define __LL_MAP_H__ 1

extern int ll_remember_index(const struct sockaddr_nl *who,
			     struct nlmsghdr *n, void *arg);
extern int ll_init_map(struct rtnl_handle *rth);
extern unsigned ll_name_to_index(const char *name);
extern const char *ll_index_to_name(unsigned idx);
extern const char *ll_idx_n2a(unsigned idx, char *buf);
extern int ll_index_to_type(unsigned idx);
extern unsigned ll_index_to_flags(unsigned idx);
extern unsigned ll_index_to_addr(unsigned idx, unsigned char *addr,
				 unsigned alen);

#endif /* __LL_MAP_H__ */

/*
  rtm_map
*/

#ifndef __RTM_MAP_H__
#define __RTM_MAP_H__ 1

char *rtnl_rtntype_n2a(int id, char *buf, int len);
int rtnl_rtntype_a2n(int *id, char *arg);

int get_rt_realms(__u32 *realms, char *arg);


#endif /* __RTM_MAP_H__ */



/*
  libnetlink
*/

#ifndef __LIBNETLINK_H__
#define __LIBNETLINK_H__ 1


struct rtnl_handle
{
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
};

extern int rcvbuf;

extern int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions);
extern int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions, int protocol);
extern void rtnl_close(struct rtnl_handle *rth);
extern int rtnl_wilddump_request(struct rtnl_handle *rth, int fam, int type);
extern int rtnl_dump_request(struct rtnl_handle *rth, int type, void *req, int len);

typedef int (*rtnl_filter_t)(const struct sockaddr_nl *,
			     struct nlmsghdr *n, void *);

struct rtnl_dump_filter_arg
{
	rtnl_filter_t filter;
	void *arg1;
	rtnl_filter_t junk;
	void *arg2;
};

extern int rtnl_dump_filter_l(struct rtnl_handle *rth,
			      const struct rtnl_dump_filter_arg *arg);
extern int rtnl_dump_filter(struct rtnl_handle *rth, rtnl_filter_t filter,
			    void *arg1,
			    rtnl_filter_t junk,
			    void *arg2);

extern int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
		     unsigned groups, struct nlmsghdr *answer,
		     rtnl_filter_t junk,
		     void *jarg);
extern int rtnl_send(struct rtnl_handle *rth, const char *buf, int);
extern int rtnl_send_check(struct rtnl_handle *rth, const char *buf, int);

extern int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data);
extern int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen);
extern int addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len);
extern struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type);
extern int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest);
extern struct rtattr *addattr_nest_compat(struct nlmsghdr *n, int maxlen, int type, const void *data, int len);
extern int addattr_nest_compat_end(struct nlmsghdr *n, struct rtattr *nest);
extern int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data);
extern int rta_addattr_l(struct rtattr *rta, int maxlen, int type, const void *data, int alen);

extern int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
extern int parse_rtattr_byindex(struct rtattr *tb[], int max, struct rtattr *rta, int len);
extern int __parse_rtattr_nested_compat(struct rtattr *tb[], int max, struct rtattr *rta, int len);

#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta)))

#define parse_rtattr_nested_compat(tb, max, rta, data, len) \
({	data = RTA_PAYLOAD(rta) >= len ? RTA_DATA(rta) : NULL; \
	__parse_rtattr_nested_compat(tb, max, rta, len); })

extern int rtnl_listen(struct rtnl_handle *, rtnl_filter_t handler,
		       void *jarg);
extern int rtnl_from_file(FILE *, rtnl_filter_t handler,
		       void *jarg);

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifndef IFA_RTA
#define IFA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#endif
#ifndef IFA_PAYLOAD
#define IFA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
#endif

#ifndef IFLA_RTA
#define IFLA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif
#ifndef IFLA_PAYLOAD
#define IFLA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#endif

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif

#ifndef NDTA_RTA
#define NDTA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndtmsg))))
#endif
#ifndef NDTA_PAYLOAD
#define NDTA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndtmsg))
#endif

#endif /* __LIBNETLINK_H__ */
