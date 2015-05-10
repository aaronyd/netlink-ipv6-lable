/*
  Base on and follow the iproute2 style
  license: GNU General Public License

  Aaron Yi Ding, University of Helsinki
  yding@cs.helsinki.fi

  last update: 29.10.2010

  functions declared ip-addr.h

  libnetlink
  utils
  ll_map
  rtm_map
  rt_names

  ipx_pton
  ipx_ntop

  dnet_pton
  dnet_ntop
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

#include "ip-addr.h"


/*
  utils.c
*/

int get_integer(int *val, const char *arg, int base)
{
	long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtol(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > INT_MAX || res < INT_MIN)
		return -1;
	*val = res;
	return 0;
}

int mask2bits(__u32 netmask)
{
	unsigned bits = 0;
	__u32 mask = ntohl(netmask);
	__u32 host = ~mask;

	/* a valid netmask must be 2^n - 1 */
	if ((host & (host + 1)) != 0)
		return -1;

	for (; mask; mask <<= 1)
		++bits;
	return bits;
}

static int get_netmask(unsigned *val, const char *arg, int base)
{
	inet_prefix addr;

	if (!get_unsigned(val, arg, base))
		return 0;

	/* try coverting dotted quad to CIDR */
	if (!get_addr_1(&addr, arg, AF_INET) && addr.family == AF_INET) {
		int b = mask2bits(addr.data[0]);
		
		if (b >= 0) {
			*val = b;
			return 0;
		}
	}

	return -1;
}

int get_unsigned(unsigned *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > UINT_MAX)
		return -1;
	*val = res;
	return 0;
}

/*
 * get_jiffies is "translated" from a similar routine "get_time" in
 * tc_util.c.  we don't use the exact same routine because tc passes
 * microseconds to the kernel and the callers of get_jiffies want 
 * to pass jiffies, and have a different assumption for the units of
 * a "raw" number.
 */

int get_jiffies(unsigned *jiffies, const char *arg, int base, int *raw)
{
	double t;
	unsigned long res;
	char *p;

	if (strchr(arg,'.') != NULL) {
		t = strtod(arg,&p);
		if (t < 0.0)
			return -1;
	}
	else {
		res = strtoul(arg,&p,base);
		if (res > UINT_MAX)
			return -1;
		t = (double)res;
	}
	if (p == arg)
		return -1;

	if (__iproute2_hz_internal == 0)
                __iproute2_hz_internal = __get_hz();
	
	*raw = 1;

	if (*p) {
		*raw = 0;
                if (strcasecmp(p, "s") == 0 || strcasecmp(p, "sec")==0 ||
                    strcasecmp(p, "secs")==0)
                        t *= __iproute2_hz_internal;
                else if (strcasecmp(p, "ms") == 0 || strcasecmp(p, "msec")==0 ||
                         strcasecmp(p, "msecs") == 0)
                        t *= __iproute2_hz_internal/1000.0;
                else if (strcasecmp(p, "us") == 0 || strcasecmp(p, "usec")==0 ||
                         strcasecmp(p, "usecs") == 0)
                        t *= __iproute2_hz_internal/1000000.0;
                else if (strcasecmp(p, "ns") == 0 || strcasecmp(p, "nsec")==0 ||
                         strcasecmp(p, "nsecs") == 0)
                        t *= __iproute2_hz_internal/1000000000.0;
		else if (strcasecmp(p, "j") == 0 || strcasecmp(p, "hz") == 0 ||
			 strcasecmp(p,"jiffies") == 0)
			t *= 1.0; /* allow suffix, do nothing */
                else
                        return -1;
        }

	/* emulate ceil() without having to bring-in -lm and always be >= 1 */

	*jiffies = t;
	if (*jiffies < t)
		*jiffies += 1;
	
        return 0;

}

int get_u64(__u64 *val, const char *arg, int base)
{
	unsigned long long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoull(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res == 0xFFFFFFFFULL)
 		return -1;
 	*val = res;
 	return 0;
}

int get_u32(__u32 *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFFFFFFFFUL)
		return -1;
	*val = res;
	return 0;
}

int get_u16(__u16 *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFFFF)
		return -1;
	*val = res;
	return 0;
}

int get_u8(__u8 *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFF)
		return -1;
	*val = res;
	return 0;
}

int get_s16(__s16 *val, const char *arg, int base)
{
	long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtol(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0x7FFF || res < -0x8000)
		return -1;
	*val = res;
	return 0;
}

int get_s8(__s8 *val, const char *arg, int base)
{
	long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtol(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0x7F || res < -0x80)
		return -1;
	*val = res;
	return 0;
}

/* This uses a non-standard parsing (ie not inet_aton, or inet_pton)
 * because of legacy choice to parse 10.8 as 10.8.0.0 not 10.0.0.8
 */
static int get_addr_ipv4(__u8 *ap, const char *cp)
{
	int i;

	for (i = 0; i < 4; i++) {
		unsigned long n;
		char *endp;
		
		n = strtoul(cp, &endp, 0);
		if (n > 255)
			return -1;	/* bogus network value */

		if (endp == cp) /* no digits */
			return -1;

		ap[i] = n;

		if (*endp == '\0')
			break;

		if (i == 3 || *endp != '.')
			return -1; 	/* extra characters */
		cp = endp + 1;
	}

	return 1;
}

int get_addr_1(inet_prefix *addr, const char *name, int family)
{
	memset(addr, 0, sizeof(*addr));

	if (strcmp(name, "default") == 0 ||
	    strcmp(name, "all") == 0 ||
	    strcmp(name, "any") == 0) {
		if (family == AF_DECnet)
			return -1;
		addr->family = family;
		addr->bytelen = (family == AF_INET6 ? 16 : 4);
		addr->bitlen = -1;
		return 0;
	}

	if (strchr(name, ':')) {
		addr->family = AF_INET6;
		if (family != AF_UNSPEC && family != AF_INET6)
			return -1;
		if (inet_pton(AF_INET6, name, addr->data) <= 0)
			return -1;
		addr->bytelen = 16;
		addr->bitlen = -1;
		return 0;
	}

	if (family == AF_DECnet) {
		struct dn_naddr dna;
		addr->family = AF_DECnet;
		if (dnet_pton(AF_DECnet, name, &dna) <= 0)
			return -1;
		memcpy(addr->data, dna.a_addr, 2);
		addr->bytelen = 2;
		addr->bitlen = -1;
		return 0;
	}

	addr->family = AF_INET;
	if (family != AF_UNSPEC && family != AF_INET)
		return -1;

	if (get_addr_ipv4((__u8 *)addr->data, name) <= 0)
		return -1;

	addr->bytelen = 4;
	addr->bitlen = -1;
	return 0;
}

int get_prefix_1(inet_prefix *dst, char *arg, int family)
{
	int err;
	unsigned plen;
	char *slash;

	memset(dst, 0, sizeof(*dst));

	if (strcmp(arg, "default") == 0 ||
	    strcmp(arg, "any") == 0 ||
	    strcmp(arg, "all") == 0) {
		if (family == AF_DECnet)
			return -1;
		dst->family = family;
		dst->bytelen = 0;
		dst->bitlen = 0;
		return 0;
	}

	slash = strchr(arg, '/');
	if (slash)
		*slash = 0;

	err = get_addr_1(dst, arg, family);
	if (err == 0) {
		switch(dst->family) {
			case AF_INET6:
				dst->bitlen = 128;
				break;
			case AF_DECnet:
				dst->bitlen = 16;
				break;
			default:
			case AF_INET:
				dst->bitlen = 32;
		}
		if (slash) {
			if (get_netmask(&plen, slash+1, 0)
					|| plen > dst->bitlen) {
				err = -1;
				goto done;
			}
			dst->flags |= PREFIXLEN_SPECIFIED;
			dst->bitlen = plen;
		}
	}
done:
	if (slash)
		*slash = '/';
	return err;
}

int get_addr(inet_prefix *dst, const char *arg, int family)
{
	if (family == AF_PACKET) {
		fprintf(stderr, "Error: \"%s\" may be inet address, but it is not allowed in this context.\n", arg);
		exit(1);
	}
	if (get_addr_1(dst, arg, family)) {
		fprintf(stderr, "Error: an inet address is expected rather than \"%s\".\n", arg);
		exit(1);
	}
	return 0;
}

int get_prefix(inet_prefix *dst, char *arg, int family)
{
	if (family == AF_PACKET) {
		fprintf(stderr, "Error: \"%s\" may be inet prefix, but it is not allowed in this context.\n", arg);
		exit(1);
	}
	if (get_prefix_1(dst, arg, family)) {
		fprintf(stderr, "Error: an inet prefix is expected rather than \"%s\".\n", arg);
		exit(1);
	}
	return 0;
}

__u32 get_addr32(const char *name)
{
	inet_prefix addr;
	if (get_addr_1(&addr, name, AF_INET)) {
		fprintf(stderr, "Error: an IP address is expected rather than \"%s\"\n", name);
		exit(1);
	}
	return addr.data[0];
}

void incomplete_command(void)
{
	fprintf(stderr, "Command line is not complete. Try option \"help\"\n");
	exit(-1);
}

void missarg(const char *key)
{
	fprintf(stderr, "Error: argument \"%s\" is required\n", key);
	exit(-1);
}

void invarg(const char *msg, const char *arg)
{
	fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n", arg, msg);
	exit(-1);
}

void duparg(const char *key, const char *arg)
{
	fprintf(stderr, "Error: duplicate \"%s\": \"%s\" is the second value.\n", key, arg);
	exit(-1);
}

void duparg2(const char *key, const char *arg)
{
	fprintf(stderr, "Error: either \"%s\" is duplicate, or \"%s\" is a garbage.\n", key, arg);
	exit(-1);
}

int matches(const char *cmd, const char *pattern)
{
	int len = strlen(cmd);
	if (len > strlen(pattern))
		return -1;
	return memcmp(pattern, cmd, len);
}

int inet_addr_match(const inet_prefix *a, const inet_prefix *b, int bits)
{
	const __u32 *a1 = a->data;
	const __u32 *a2 = b->data;
	int words = bits >> 0x05;

	bits &= 0x1f;

	if (words)
		if (memcmp(a1, a2, words << 2))
			return -1;

	if (bits) {
		__u32 w1, w2;
		__u32 mask;

		w1 = a1[words];
		w2 = a2[words];

		mask = htonl((0xffffffff) << (0x20 - bits));

		if ((w1 ^ w2) & mask)
			return 1;
	}

	return 0;
}

int __iproute2_hz_internal;

int __get_hz(void)
{
	char name[1024];
	int hz = 0;
	FILE *fp;

	if (getenv("HZ"))
		return atoi(getenv("HZ")) ? : HZ;

	if (getenv("PROC_NET_PSCHED")) {
		snprintf(name, sizeof(name)-1, "%s", getenv("PROC_NET_PSCHED"));
	} else if (getenv("PROC_ROOT")) {
		snprintf(name, sizeof(name)-1, "%s/net/psched", getenv("PROC_ROOT"));
	} else {
		strcpy(name, "/proc/net/psched");
	}
	fp = fopen(name, "r");

	if (fp) {
		unsigned nom, denom;
		if (fscanf(fp, "%*08x%*08x%08x%08x", &nom, &denom) == 2)
			if (nom == 1000000)
				hz = denom;
		fclose(fp);
	}
	if (hz)
		return hz;
	return HZ;
}

int __iproute2_user_hz_internal;

int __get_user_hz(void)
{
	return sysconf(_SC_CLK_TCK);
}

const char *rt_addr_n2a(int af, int len, const void *addr, char *buf, int buflen)
{
	switch (af) {
	case AF_INET:
	case AF_INET6:
		return inet_ntop(af, addr, buf, buflen);
	case AF_IPX:
		return ipx_ntop(af, addr, buf, buflen);
	case AF_DECnet:
	{
		struct dn_naddr dna = { 2, { 0, 0, }};
		memcpy(dna.a_addr, addr, 2);
		return dnet_ntop(af, &dna, buf, buflen);
	}
	default:
		return "???";
	}
}

#ifdef RESOLVE_HOSTNAMES
struct namerec
{
	struct namerec *next;
	const char *name;
	inet_prefix addr;
};

#define NHASH 257
static struct namerec *nht[NHASH];

static const char *resolve_address(const void *addr, int len, int af)
{
	struct namerec *n;
	struct hostent *h_ent;
	unsigned hash;
	static int notfirst;


	if (af == AF_INET6 && ((__u32*)addr)[0] == 0 &&
	    ((__u32*)addr)[1] == 0 && ((__u32*)addr)[2] == htonl(0xffff)) {
		af = AF_INET;
		addr += 12;
		len = 4;
	}

	hash = *(__u32 *)(addr + len - 4) % NHASH;

	for (n = nht[hash]; n; n = n->next) {
		if (n->addr.family == af &&
		    n->addr.bytelen == len &&
		    memcmp(n->addr.data, addr, len) == 0)
			return n->name;
	}
	if ((n = malloc(sizeof(*n))) == NULL)
		return NULL;
	n->addr.family = af;
	n->addr.bytelen = len;
	n->name = NULL;
	memcpy(n->addr.data, addr, len);
	n->next = nht[hash];
	nht[hash] = n;
	if (++notfirst == 1)
		sethostent(1);
	fflush(stdout);

	if ((h_ent = gethostbyaddr(addr, len, af)) != NULL)
		n->name = strdup(h_ent->h_name);

	/* Even if we fail, "negative" entry is remembered. */
	return n->name;
}
#endif


const char *format_host(int af, int len, const void *addr,
			char *buf, int buflen)
{
#ifdef RESOLVE_HOSTNAMES
	if (resolve_hosts) {
		const char *n;

		if (len <= 0) {
			switch (af) {
			case AF_INET:
				len = 4;
				break;
			case AF_INET6:
				len = 16;
				break;
			case AF_IPX:
				len = 10;
				break;
#ifdef AF_DECnet
			/* I see no reasons why gethostbyname
			   may not work for DECnet */
			case AF_DECnet:
				len = 2;
				break;
#endif
			default: ;
			}
		}
		if (len > 0 &&
		    (n = resolve_address(addr, len, af)) != NULL)
			return n;
	}
#endif
	return rt_addr_n2a(af, len, addr, buf, buflen);
}


char *hexstring_n2a(const __u8 *str, int len, char *buf, int blen)
{
	char *ptr = buf;
	int i;

	for (i=0; i<len; i++) {
		if (blen < 3)
			break;
		sprintf(ptr, "%02x", str[i]);
		ptr += 2;
		blen -= 2;
		if (i != len-1 && blen > 1) {
			*ptr++ = ':';
			blen--;
		}
	}
	return buf;
}

__u8* hexstring_a2n(const char *str, __u8 *buf, int blen)
{
	int cnt = 0;

	for (;;) {
		unsigned acc;
		char ch;

		acc = 0;

		while ((ch = *str) != ':' && ch != 0) {
			if (ch >= '0' && ch <= '9')
				ch -= '0';
			else if (ch >= 'a' && ch <= 'f')
				ch -= 'a'-10;
			else if (ch >= 'A' && ch <= 'F')
				ch -= 'A'-10;
			else
				return NULL;
			acc = (acc<<4) + ch;
			str++;
		}

		if (acc > 255)
			return NULL;
		if (cnt < blen) {
			buf[cnt] = acc;
			cnt++;
		}
		if (ch == 0)
			break;
		++str;
	}
	if (cnt < blen)
		memset(buf+cnt, 0, blen-cnt);
	return buf;
}

int print_timestamp(FILE *fp)
{
	struct timeval tv;
	char *tstr;

	memset(&tv, 0, sizeof(tv));
	gettimeofday(&tv, NULL);

	tstr = asctime(localtime(&tv.tv_sec));
	tstr[strlen(tstr)-1] = 0;
	fprintf(fp, "Timestamp: %s %lu usec\n", tstr, tv.tv_usec);
	return 0;
}

int cmdlineno;

/* Like glibc getline but handle continuation lines and comments */
ssize_t getcmdline(char **linep, size_t *lenp, FILE *in)
{
	ssize_t cc;
	char *cp;

	if ((cc = getline(linep, lenp, in)) < 0)
		return cc;	/* eof or error */
	++cmdlineno;

	cp = strchr(*linep, '#');
	if (cp)
		*cp = '\0';

	while ((cp = strstr(*linep, "\\\n")) != NULL) {
		char *line1 = NULL;
		size_t len1 = 0;
		size_t cc1;

		if ((cc1 = getline(&line1, &len1, in)) < 0) {
			fprintf(stderr, "Missing continuation line\n");
			return cc1;
		}

		++cmdlineno;
		*cp = 0;

		cp = strchr(line1, '#');
		if (cp)
			*cp = '\0';

		*lenp = strlen(*linep) + strlen(line1) + 1;
		*linep = realloc(*linep, *lenp);
		if (!*linep) {
			fprintf(stderr, "Out of memory\n");
			*lenp = 0;
			return -1;
		}
		cc += cc1 - 2;
		strcat(*linep, line1);
		free(line1);
	}
	return cc;
}

/* split command line into argument vector */
int makeargs(char *line, char *argv[], int maxargs)
{
	static const char ws[] = " \t\r\n";
	char *cp;
	int argc = 0;

	for (cp = strtok(line, ws); cp; cp = strtok(NULL, ws)) {
		if (argc >= (maxargs - 1)) {
			fprintf(stderr, "Too many arguments to command\n");
			exit(1);
		}
		argv[argc++] = cp;
	}
	argv[argc] = NULL;

	return argc;
}




/*
  ll_map.c
*/


extern unsigned int if_nametoindex (const char *);

struct idxmap
{
	struct idxmap * next;
	unsigned	index;
	int		type;
	int		alen;
	unsigned	flags;
	unsigned char	addr[20];
	char		name[16];
};

static struct idxmap *idxmap[16];

int ll_remember_index(const struct sockaddr_nl *who,
		      struct nlmsghdr *n, void *arg)
{
	int h;
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct idxmap *im, **imp;
	struct rtattr *tb[IFLA_MAX+1];

	if (n->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(ifi)))
		return -1;


	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));
	if (tb[IFLA_IFNAME] == NULL)
		return 0;

	h = ifi->ifi_index&0xF;

	for (imp=&idxmap[h]; (im=*imp)!=NULL; imp = &im->next)
		if (im->index == ifi->ifi_index)
			break;

	if (im == NULL) {
		im = malloc(sizeof(*im));
		if (im == NULL)
			return 0;
		im->next = *imp;
		im->index = ifi->ifi_index;
		*imp = im;
	}

	im->type = ifi->ifi_type;
	im->flags = ifi->ifi_flags;
	if (tb[IFLA_ADDRESS]) {
		int alen;
		im->alen = alen = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
		if (alen > sizeof(im->addr))
			alen = sizeof(im->addr);
		memcpy(im->addr, RTA_DATA(tb[IFLA_ADDRESS]), alen);
	} else {
		im->alen = 0;
		memset(im->addr, 0, sizeof(im->addr));
	}
	strcpy(im->name, RTA_DATA(tb[IFLA_IFNAME]));
	return 0;
}

const char *ll_idx_n2a(unsigned idx, char *buf)
{
	struct idxmap *im;

	if (idx == 0)
		return "*";
	for (im = idxmap[idx&0xF]; im; im = im->next)
		if (im->index == idx)
			return im->name;
	snprintf(buf, 16, "if%d", idx);
	return buf;
}


const char *ll_index_to_name(unsigned idx)
{
	static char nbuf[16];

	return ll_idx_n2a(idx, nbuf);
}

int ll_index_to_type(unsigned idx)
{
	struct idxmap *im;

	if (idx == 0)
		return -1;
	for (im = idxmap[idx&0xF]; im; im = im->next)
		if (im->index == idx)
			return im->type;
	return -1;
}

unsigned ll_index_to_flags(unsigned idx)
{
	struct idxmap *im;

	if (idx == 0)
		return 0;

	for (im = idxmap[idx&0xF]; im; im = im->next)
		if (im->index == idx)
			return im->flags;
	return 0;
}

unsigned ll_index_to_addr(unsigned idx, unsigned char *addr,
			  unsigned alen)
{
	struct idxmap *im;

	if (idx == 0)
		return 0;

	for (im = idxmap[idx&0xF]; im; im = im->next) {
		if (im->index == idx) {
			if (alen > sizeof(im->addr))
				alen = sizeof(im->addr);
			if (alen > im->alen)
				alen = im->alen;
			memcpy(addr, im->addr, alen);
			return alen;
		}
	}
	return 0;
}

unsigned ll_name_to_index(const char *name)
{
	static char ncache[16];
	static int icache;
	struct idxmap *im;
	int i;
	unsigned idx;

	if (name == NULL)
		return 0;
	if (icache && strcmp(name, ncache) == 0)
		return icache;
	for (i=0; i<16; i++) {
		for (im = idxmap[i]; im; im = im->next) {
			if (strcmp(im->name, name) == 0) {
				icache = im->index;
				strcpy(ncache, name);
				return im->index;
			}
		}
	}

	idx = if_nametoindex(name);
	if (idx == 0)
		sscanf(name, "if%u", &idx);
	return idx;
}

int ll_init_map(struct rtnl_handle *rth)
{
	if (rtnl_wilddump_request(rth, AF_UNSPEC, RTM_GETLINK) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(rth, ll_remember_index, &idxmap, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}
	return 0;
}


/*
  rtm_map.c
*/


char *rtnl_rtntype_n2a(int id, char *buf, int len)
{
	switch (id) {
	case RTN_UNSPEC:
		return "none";
	case RTN_UNICAST:
		return "unicast";
	case RTN_LOCAL:
		return "local";
	case RTN_BROADCAST:
		return "broadcast";
	case RTN_ANYCAST:
		return "anycast";
	case RTN_MULTICAST:
		return "multicast";
	case RTN_BLACKHOLE:
		return "blackhole";
	case RTN_UNREACHABLE:
		return "unreachable";
	case RTN_PROHIBIT:
		return "prohibit";
	case RTN_THROW:
		return "throw";
	case RTN_NAT:
		return "nat";
	case RTN_XRESOLVE:
		return "xresolve";
	default:
		snprintf(buf, len, "%d", id);
		return buf;
	}
}


int rtnl_rtntype_a2n(int *id, char *arg)
{
	char *end;
	unsigned long res;

	if (strcmp(arg, "local") == 0)
		res = RTN_LOCAL;
	else if (strcmp(arg, "nat") == 0)
		res = RTN_NAT;
	else if (matches(arg, "broadcast") == 0 ||
		 strcmp(arg, "brd") == 0)
		res = RTN_BROADCAST;
	else if (matches(arg, "anycast") == 0)
		res = RTN_ANYCAST;
	else if (matches(arg, "multicast") == 0)
		res = RTN_MULTICAST;
	else if (matches(arg, "prohibit") == 0)
		res = RTN_PROHIBIT;
	else if (matches(arg, "unreachable") == 0)
		res = RTN_UNREACHABLE;
	else if (matches(arg, "blackhole") == 0)
		res = RTN_BLACKHOLE;
	else if (matches(arg, "xresolve") == 0)
		res = RTN_XRESOLVE;
	else if (matches(arg, "unicast") == 0)
		res = RTN_UNICAST;
	else if (strcmp(arg, "throw") == 0)
		res = RTN_THROW;
	else {
		res = strtoul(arg, &end, 0);
		if (!end || end == arg || *end || res > 255)
			return -1;
	}
	*id = res;
	return 0;
}

int get_rt_realms(__u32 *realms, char *arg)
{
	__u32 realm = 0;
	char *p = strchr(arg, '/');

	*realms = 0;
	if (p) {
		*p = 0;
		if (rtnl_rtrealm_a2n(realms, arg)) {
			*p = '/';
			return -1;
		}
		*realms <<= 16;
		*p = '/';
		arg = p+1;
	}
	if (*arg && rtnl_rtrealm_a2n(&realm, arg))
		return -1;
	*realms |= realm;
	return 0;
}



/*
  rt_names.c
*/

struct rtnl_hash_entry {
	struct rtnl_hash_entry *next;
	char *			name;
	unsigned int		id;
};

static void
rtnl_hash_initialize(char *file, struct rtnl_hash_entry **hash, int size)
{
	struct rtnl_hash_entry *entry;
	char buf[512];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return;
	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf;
		int id;
		char namebuf[512];

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == 0)
			continue;
		if (sscanf(p, "0x%x %s\n", &id, namebuf) != 2 &&
		    sscanf(p, "0x%x %s #", &id, namebuf) != 2 &&
		    sscanf(p, "%d %s\n", &id, namebuf) != 2 &&
		    sscanf(p, "%d %s #", &id, namebuf) != 2) {
			fprintf(stderr, "Database %s is corrupted at %s\n",
				file, p);
			return;
		}

		if (id<0)
			continue;
		entry = malloc(sizeof(*entry));
		entry->id   = id;
		entry->name = strdup(namebuf);
		entry->next = hash[id & (size - 1)];
		hash[id & (size - 1)] = entry;
	}
	fclose(fp);
}

static void rtnl_tab_initialize(char *file, char **tab, int size)
{
	char buf[512];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return;
	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf;
		int id;
		char namebuf[512];

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == 0)
			continue;
		if (sscanf(p, "0x%x %s\n", &id, namebuf) != 2 &&
		    sscanf(p, "0x%x %s #", &id, namebuf) != 2 &&
		    sscanf(p, "%d %s\n", &id, namebuf) != 2 &&
		    sscanf(p, "%d %s #", &id, namebuf) != 2) {
			fprintf(stderr, "Database %s is corrupted at %s\n",
				file, p);
			return;
		}

		if (id<0 || id>size)
			continue;

		tab[id] = strdup(namebuf);
	}
	fclose(fp);
}

static char * rtnl_rtprot_tab[256] = {
	[RTPROT_UNSPEC] = "none",
	[RTPROT_REDIRECT] ="redirect",
	[RTPROT_KERNEL] = "kernel",
	[RTPROT_BOOT] = "boot",
	[RTPROT_STATIC] = "static",

	[RTPROT_GATED] = "gated",
	[RTPROT_RA] = "ra",
	[RTPROT_MRT] =	"mrt",
	[RTPROT_ZEBRA] ="zebra",
	[RTPROT_BIRD] = "bird",
	[RTPROT_DNROUTED] = "dnrouted",
	[RTPROT_XORP] = "xorp",
	[RTPROT_NTK] = "ntk",
//	[RTPROT_DHCP] = "dhcp",
};



static int rtnl_rtprot_init;

static void rtnl_rtprot_initialize(void)
{
	rtnl_rtprot_init = 1;
	rtnl_tab_initialize("/etc/iproute2/rt_protos",
			    rtnl_rtprot_tab, 256);
}

char * rtnl_rtprot_n2a(int id, char *buf, int len)
{
	if (id<0 || id>=256) {
		snprintf(buf, len, "%d", id);
		return buf;
	}
	if (!rtnl_rtprot_tab[id]) {
		if (!rtnl_rtprot_init)
			rtnl_rtprot_initialize();
	}
	if (rtnl_rtprot_tab[id])
		return rtnl_rtprot_tab[id];
	snprintf(buf, len, "%d", id);
	return buf;
}

int rtnl_rtprot_a2n(__u32 *id, char *arg)
{
	static char *cache = NULL;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rtprot_init)
		rtnl_rtprot_initialize();

	for (i=0; i<256; i++) {
		if (rtnl_rtprot_tab[i] &&
		    strcmp(rtnl_rtprot_tab[i], arg) == 0) {
			cache = rtnl_rtprot_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}



static char * rtnl_rtscope_tab[256] = {
	"global",
};

static int rtnl_rtscope_init;

static void rtnl_rtscope_initialize(void)
{
	rtnl_rtscope_init = 1;
	rtnl_rtscope_tab[255] = "nowhere";
	rtnl_rtscope_tab[254] = "host";
	rtnl_rtscope_tab[253] = "link";
	rtnl_rtscope_tab[200] = "site";
	rtnl_tab_initialize("/etc/iproute2/rt_scopes",
			    rtnl_rtscope_tab, 256);
}

char * rtnl_rtscope_n2a(int id, char *buf, int len)
{
	if (id<0 || id>=256) {
		snprintf(buf, len, "%d", id);
		return buf;
	}
	if (!rtnl_rtscope_tab[id]) {
		if (!rtnl_rtscope_init)
			rtnl_rtscope_initialize();
	}
	if (rtnl_rtscope_tab[id])
		return rtnl_rtscope_tab[id];
	snprintf(buf, len, "%d", id);
	return buf;
}

int rtnl_rtscope_a2n(__u32 *id, char *arg)
{
	static char *cache = NULL;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rtscope_init)
		rtnl_rtscope_initialize();

	for (i=0; i<256; i++) {
		if (rtnl_rtscope_tab[i] &&
		    strcmp(rtnl_rtscope_tab[i], arg) == 0) {
			cache = rtnl_rtscope_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}



static char * rtnl_rtrealm_tab[256] = {
	"unknown",
};

static int rtnl_rtrealm_init;

static void rtnl_rtrealm_initialize(void)
{
	rtnl_rtrealm_init = 1;
	rtnl_tab_initialize("/etc/iproute2/rt_realms",
			    rtnl_rtrealm_tab, 256);
}

char * rtnl_rtrealm_n2a(int id, char *buf, int len)
{
	if (id<0 || id>=256) {
		snprintf(buf, len, "%d", id);
		return buf;
	}
	if (!rtnl_rtrealm_tab[id]) {
		if (!rtnl_rtrealm_init)
			rtnl_rtrealm_initialize();
	}
	if (rtnl_rtrealm_tab[id])
		return rtnl_rtrealm_tab[id];
	snprintf(buf, len, "%d", id);
	return buf;
}


int rtnl_rtrealm_a2n(__u32 *id, char *arg)
{
	static char *cache = NULL;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rtrealm_init)
		rtnl_rtrealm_initialize();

	for (i=0; i<256; i++) {
		if (rtnl_rtrealm_tab[i] &&
		    strcmp(rtnl_rtrealm_tab[i], arg) == 0) {
			cache = rtnl_rtrealm_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}


static struct rtnl_hash_entry dflt_table_entry  = { .id = 253, .name = "default" };
static struct rtnl_hash_entry main_table_entry  = { .id = 254, .name = "main" };
static struct rtnl_hash_entry local_table_entry = { .id = 255, .name = "local" };

static struct rtnl_hash_entry * rtnl_rttable_hash[256] = {
	[253] = &dflt_table_entry,
	[254] = &main_table_entry,
	[255] = &local_table_entry,
};

static int rtnl_rttable_init;

static void rtnl_rttable_initialize(void)
{
	rtnl_rttable_init = 1;
	rtnl_hash_initialize("/etc/iproute2/rt_tables",
			     rtnl_rttable_hash, 256);
}

char * rtnl_rttable_n2a(__u32 id, char *buf, int len)
{
	struct rtnl_hash_entry *entry;

	if (id > RT_TABLE_MAX) {
		snprintf(buf, len, "%u", id);
		return buf;
	}
	if (!rtnl_rttable_init)
		rtnl_rttable_initialize();
	entry = rtnl_rttable_hash[id & 255];
	while (entry && entry->id != id)
		entry = entry->next;
	if (entry)
		return entry->name;
	snprintf(buf, len, "%u", id);
	return buf;
}

int rtnl_rttable_a2n(__u32 *id, char *arg)
{
	static char *cache = NULL;
	static unsigned long res;
	struct rtnl_hash_entry *entry;
	char *end;
	__u32 i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rttable_init)
		rtnl_rttable_initialize();

	for (i=0; i<256; i++) {
		entry = rtnl_rttable_hash[i];
		while (entry && strcmp(entry->name, arg))
			entry = entry->next;
		if (entry) {
			cache = entry->name;
			res = entry->id;
			*id = res;
			return 0;
		}
	}

	i = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || i > RT_TABLE_MAX)
		return -1;
	*id = i;
	return 0;
}


static char * rtnl_rtdsfield_tab[256] = {
	"0",
};

static int rtnl_rtdsfield_init;

static void rtnl_rtdsfield_initialize(void)
{
	rtnl_rtdsfield_init = 1;
	rtnl_tab_initialize("/etc/iproute2/rt_dsfield",
			    rtnl_rtdsfield_tab, 256);
}

char * rtnl_dsfield_n2a(int id, char *buf, int len)
{
	if (id<0 || id>=256) {
		snprintf(buf, len, "%d", id);
		return buf;
	}
	if (!rtnl_rtdsfield_tab[id]) {
		if (!rtnl_rtdsfield_init)
			rtnl_rtdsfield_initialize();
	}
	if (rtnl_rtdsfield_tab[id])
		return rtnl_rtdsfield_tab[id];
	snprintf(buf, len, "0x%02x", id);
	return buf;
}


int rtnl_dsfield_a2n(__u32 *id, char *arg)
{
	static char *cache = NULL;
	static unsigned long res;
	char *end;
	int i;

	if (cache && strcmp(cache, arg) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rtdsfield_init)
		rtnl_rtdsfield_initialize();

	for (i=0; i<256; i++) {
		if (rtnl_rtdsfield_tab[i] &&
		    strcmp(rtnl_rtdsfield_tab[i], arg) == 0) {
			cache = rtnl_rtdsfield_tab[i];
			res = i;
			*id = res;
			return 0;
		}
	}

	res = strtoul(arg, &end, 16);
	if (!end || end == arg || *end || res > 255)
		return -1;
	*id = res;
	return 0;
}



/*
  libnetlink.c
*/



int rcvbuf = 1024 * 1024;

void rtnl_close(struct rtnl_handle *rth)
{
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
		      int protocol)
{
	socklen_t addr_len;
	int sndbuf = 32768;

	memset(rth, 0, sizeof(*rth));

	rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
		perror("SO_SNDBUF");
		return -1;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
		perror("SO_RCVBUF");
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;
}

int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

int rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
	req.g.rtgen_family = family;

	return send(rth->fd, (void*)&req, sizeof(req), 0);
}

int rtnl_send(struct rtnl_handle *rth, const char *buf, int len)
{
	return send(rth->fd, buf, len, 0);
}

int rtnl_send_check(struct rtnl_handle *rth, const char *buf, int len)
{
	struct nlmsghdr *h;
	int status;
	char resp[1024];

	status = send(rth->fd, buf, len, 0);
	if (status < 0)
		return status;

	/* Check for immediate errors */
	status = recv(rth->fd, resp, sizeof(resp), MSG_DONTWAIT|MSG_PEEK);
	if (status < 0) {
		if (errno == EAGAIN)
			return 0;
		return -1;
	}

	for (h = (struct nlmsghdr *)resp; NLMSG_OK(h, status);
	     h = NLMSG_NEXT(h, status)) {
		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
			if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				fprintf(stderr, "ERROR truncated\n");
			else 
				errno = -err->error;
			return -1;
		}
	}

	return 0;
}

int rtnl_dump_request(struct rtnl_handle *rth, int type, void *req, int len)
{
	struct nlmsghdr nlh;
	struct sockaddr_nl nladdr;
	struct iovec iov[2] = {
		{ .iov_base = &nlh, .iov_len = sizeof(nlh) },
		{ .iov_base = req, .iov_len = len }
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = 	sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = 2,
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	nlh.nlmsg_len = NLMSG_LENGTH(len);
	nlh.nlmsg_type = type;
	nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	nlh.nlmsg_pid = 0;
	nlh.nlmsg_seq = rth->dump = ++rth->seq;

	return sendmsg(rth->fd, &msg, 0);
}

int rtnl_dump_filter_l(struct rtnl_handle *rth,
		       const struct rtnl_dump_filter_arg *arg)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];

	iov.iov_base = buf;
	while (1) {
		int status;
		const struct rtnl_dump_filter_arg *a;

		iov.iov_len = sizeof(buf);
		status = recvmsg(rth->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			fprintf(stderr, "netlink receive error %s (%d)\n",
				strerror(errno), errno);
			return -1;
		}

		if (status == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return -1;
		}

		for (a = arg; a->filter; a++) {
			struct nlmsghdr *h = (struct nlmsghdr*)buf;

			while (NLMSG_OK(h, status)) {
				int err;

				if (nladdr.nl_pid != 0 ||
				    h->nlmsg_pid != rth->local.nl_pid ||
				    h->nlmsg_seq != rth->dump) {
					if (a->junk) {
						err = a->junk(&nladdr, h,
							      a->arg2);
						if (err < 0)
							return err;
					}
					goto skip_it;
				}

				if (h->nlmsg_type == NLMSG_DONE)
					return 0;
				if (h->nlmsg_type == NLMSG_ERROR) {
					struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
					if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
						fprintf(stderr,
							"ERROR truncated\n");
					} else {
						errno = -err->error;
						perror("RTNETLINK answers");
					}
					return -1;
				}
				err = a->filter(&nladdr, h, a->arg1);
				if (err < 0)
					return err;

skip_it:
				h = NLMSG_NEXT(h, status);
			}
		} while (0);
		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
}

int rtnl_dump_filter(struct rtnl_handle *rth,
		     rtnl_filter_t filter,
		     void *arg1,
		     rtnl_filter_t junk,
		     void *arg2)
{
	const struct rtnl_dump_filter_arg a[2] = {
		{ .filter = filter, .arg1 = arg1, .junk = junk, .arg2 = arg2 },
		{ .filter = NULL,   .arg1 = NULL, .junk = NULL, .arg2 = NULL }
	};

	return rtnl_dump_filter_l(rth, a);
}

int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
	      unsigned groups, struct nlmsghdr *answer,
	      rtnl_filter_t junk,
	      void *jarg)
{
	int status;
	unsigned seq;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = (void*) n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[16384];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;

	n->nlmsg_seq = seq = ++rtnl->seq;

	if (answer == NULL)
		n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(rtnl->fd, &msg, 0);

	if (status < 0) {
		perror("Cannot talk to rtnetlink");
		return -1;
	}

	memset(buf,0,sizeof(buf));

	iov.iov_base = buf;

	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(rtnl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			fprintf(stderr, "netlink receive error %s (%d)\n",
				strerror(errno), errno);
			return -1;
		}
		if (status == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			fprintf(stderr, "sender address length == %d\n", msg.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l<0 || len>status) {
				if (msg.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "Truncated message\n");
					return -1;
				}
				fprintf(stderr, "!!!malformed message: len=%d\n", len);
				exit(1);
			}

			if (nladdr.nl_pid != peer ||
			    h->nlmsg_pid != rtnl->local.nl_pid ||
			    h->nlmsg_seq != seq) {
				if (junk) {
					err = junk(&nladdr, h, jarg);
					if (err < 0)
						return err;
				}
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
				if (l < sizeof(struct nlmsgerr)) {
					fprintf(stderr, "ERROR truncated\n");
				} else {
					errno = -err->error;
					if (errno == 0) {
						if (answer)
							memcpy(answer, h, h->nlmsg_len);
						return 0;
					}
					perror("RTNETLINK answers");
				}
				return -1;
			}
			if (answer) {
				memcpy(answer, h, h->nlmsg_len);
				return 0;
			}

			fprintf(stderr, "Unexpected reply!!!\n");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
}

int rtnl_listen(struct rtnl_handle *rtnl,
		rtnl_filter_t handler,
		void *jarg)
{
	int status;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[8192];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(rtnl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			fprintf(stderr, "netlink receive error %s (%d)\n",
				strerror(errno), errno);
			if (errno == ENOBUFS)
				continue;
			return -1;
		}
		if (status == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			fprintf(stderr, "Sender address length == %d\n", msg.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l<0 || len>status) {
				if (msg.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "Truncated message\n");
					return -1;
				}
				fprintf(stderr, "!!!malformed message: len=%d\n", len);
				exit(1);
			}

			err = handler(&nladdr, h, jarg);
			if (err < 0)
				return err;

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
}

int rtnl_from_file(FILE *rtnl, rtnl_filter_t handler,
		   void *jarg)
{
	int status;
	struct sockaddr_nl nladdr;
	char   buf[8192];
	struct nlmsghdr *h = (void*)buf;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	while (1) {
		int err, len, type;
		int l;

		status = fread(&buf, 1, sizeof(*h), rtnl);

		if (status < 0) {
			if (errno == EINTR)
				continue;
			perror("rtnl_from_file: fread");
			return -1;
		}
		if (status == 0)
			return 0;

		len = h->nlmsg_len;
		type= h->nlmsg_type;
		l = len - sizeof(*h);

		if (l<0 || len>sizeof(buf)) {
			fprintf(stderr, "!!!malformed message: len=%d @%lu\n",
				len, ftell(rtnl));
			return -1;
		}

		status = fread(NLMSG_DATA(h), 1, NLMSG_ALIGN(l), rtnl);

		if (status < 0) {
			perror("rtnl_from_file: fread");
			return -1;
		}
		if (status < l) {
			fprintf(stderr, "rtnl-from_file: truncated message\n");
			return -1;
		}

		err = handler(&nladdr, h, jarg);
		if (err < 0)
			return err;
	}
}

int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
	int len = RTA_LENGTH(4);
	struct rtattr *rta;
	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
		fprintf(stderr,"addattr32: Error! max allowed bound %d exceeded\n",maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), &data, 4);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
	return 0;
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

int addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len)
{
	if (NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len) > maxlen) {
		fprintf(stderr, "addraw_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}

	memcpy(NLMSG_TAIL(n), data, len);
	memset((void *) NLMSG_TAIL(n) + len, 0, NLMSG_ALIGN(len) - len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len);
	return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

struct rtattr *addattr_nest_compat(struct nlmsghdr *n, int maxlen, int type,
				   const void *data, int len)
{
	struct rtattr *start = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, data, len);
	addattr_nest(n, maxlen, type);
	return start;
}

int addattr_nest_compat_end(struct nlmsghdr *n, struct rtattr *start)
{
	struct rtattr *nest = (void *)start + NLMSG_ALIGN(start->rta_len);

	start->rta_len = (void *)NLMSG_TAIL(n) - (void *)start;
	addattr_nest_end(n, nest);
	return n->nlmsg_len;
}

int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data)
{
	int len = RTA_LENGTH(4);
	struct rtattr *subrta;

	if (RTA_ALIGN(rta->rta_len) + len > maxlen) {
		fprintf(stderr,"rta_addattr32: Error! max allowed bound %d exceeded\n",maxlen);
		return -1;
	}
	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), &data, 4);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
	return 0;
}

int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
		  const void *data, int alen)
{
	struct rtattr *subrta;
	int len = RTA_LENGTH(alen);

	if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr,"rta_addattr_l: Error! max allowed bound %d exceeded\n",maxlen);
		return -1;
	}
	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), data, alen);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
	return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

int parse_rtattr_byindex(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	int i = 0;

	memset(tb, 0, sizeof(struct rtattr *) * max);
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max && i < max)
			tb[i++] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return i;
}

int __parse_rtattr_nested_compat(struct rtattr *tb[], int max, struct rtattr *rta,
			         int len)
{
	if (RTA_PAYLOAD(rta) < len)
		return -1;
	if (RTA_PAYLOAD(rta) >= RTA_ALIGN(len) + sizeof(struct rtattr)) {
		rta = RTA_DATA(rta) + RTA_ALIGN(len);
		return parse_rtattr_nested(tb, max, rta);
	}
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	return 0;
}


/*
  ipx_ntop
  ipx_pton
*/


static __inline__ int do_digit_ipx(char *str, u_int32_t addr, u_int32_t scale, size_t *pos, size_t len)
{
	u_int32_t tmp = addr >> (scale * 4);

	if (*pos == len)
		return 1;

	tmp &= 0x0f;
	if (tmp > 9)
		*str = tmp + 'A' - 10;
	else
		*str = tmp + '0';
	(*pos)++;

	return 0;
}

static const char *ipx_ntop1(const struct ipx_addr *addr, char *str, size_t len)
{
	int i;
	size_t pos = 0;

	if (len == 0)
		return str;

	for(i = 7; i >= 0; i--)
		if (do_digit_ipx(str + pos, ntohl(addr->ipx_net), i, &pos, len))
			return str;

	if (pos == len)
		return str;

	*(str + pos) = '.';
	pos++;

	for(i = 0; i < 6; i++) {
		if (do_digit_ipx(str + pos, addr->ipx_node[i], 1, &pos, len))
			return str;
		if (do_digit_ipx(str + pos, addr->ipx_node[i], 0, &pos, len))
			return str;
	}

	if (pos == len)
		return str;

	*(str + pos) = 0;

	return str;
}


const char *ipx_ntop(int af, const void *addr, char *str, size_t len)
{
	switch(af) {
		case AF_IPX:
			errno = 0;
			return ipx_ntop1((struct ipx_addr *)addr, str, len);
		default:
			errno = EAFNOSUPPORT;
	}

	return NULL;
}


static u_int32_t hexget(char c)
{
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= '0' && c <= '9')
		return c - '0';

	return 0xf0;
}

static int ipx_getnet(u_int32_t *net, const char *str)
{
	int i;
	u_int32_t tmp;

	for(i = 0; *str && (i < 8); i++) {

		if ((tmp = hexget(*str)) & 0xf0) {
			if (*str == '.')
				return 0;
			else
				return -1;
		}

		str++;
		(*net) <<= 4;
		(*net) |= tmp;
	}

	if (*str == 0)
		return 0;

	return -1;
}

static int ipx_getnode(u_int8_t *node, const char *str)
{
	int i;
	u_int32_t tmp;

	for(i = 0; i < 6; i++) {
		if ((tmp = hexget(*str++)) & 0xf0)
			return -1;
		node[i] = (u_int8_t)tmp;
		node[i] <<= 4;
		if ((tmp = hexget(*str++)) & 0xf0)
			return -1;
		node[i] |= (u_int8_t)tmp;
		if (*str == ':')
			str++;
	}

	return 0;
}

static int ipx_pton1(const char *src, struct ipx_addr *addr)
{
	char *sep = (char *)src;
	int no_node = 0;

	memset(addr, 0, sizeof(struct ipx_addr));

	while(*sep && (*sep != '.'))
		sep++;

	if (*sep != '.')
		no_node = 1;

	if (ipx_getnet(&addr->ipx_net, src))
		return 0;

	addr->ipx_net = htonl(addr->ipx_net);

	if (no_node)
		return 1;

	if (ipx_getnode(addr->ipx_node, sep + 1))
		return 0;

	return 1;
}

int ipx_pton(int af, const char *src, void *addr)
{
	int err;

	switch (af) {
	case AF_IPX:
		errno = 0;
		err = ipx_pton1(src, (struct ipx_addr *)addr);
		break;
	default:
		errno = EAFNOSUPPORT;
		err = -1;
	}

	return err;
}

/*
  dnet_ntop
  dnet_pton
*/

static __inline__ u_int16_t dn_ntohs(u_int16_t addr)
{
	union {
		u_int8_t byte[2];
		u_int16_t word;
	} u;

	u.word = addr;
	return ((u_int16_t)u.byte[0]) | (((u_int16_t)u.byte[1]) << 8);
}

static __inline__ int do_digit(char *str, u_int16_t *addr, u_int16_t scale, size_t *pos, size_t len, int *started)
{
	u_int16_t tmp = *addr / scale;

	if (*pos == len)
		return 1;

	if (((tmp) > 0) || *started || (scale == 1)) {
		*str = tmp + '0';
		*started = 1;
		(*pos)++;
		*addr -= (tmp * scale);
	}

	return 0;
}


static const char *dnet_ntop1(const struct dn_naddr *dna, char *str, size_t len)
{
	u_int16_t addr, area;
	size_t pos = 0;
	int started = 0;

	memcpy(&addr, dna->a_addr, sizeof(addr));
	addr = dn_ntohs(addr);
	area = addr >> 10;

	if (dna->a_len != 2)
		return NULL;

	addr &= 0x03ff;

	if (len == 0)
		return str;

	if (do_digit(str + pos, &area, 10, &pos, len, &started))
		return str;

	if (do_digit(str + pos, &area, 1, &pos, len, &started))
		return str;

	if (pos == len)
		return str;

	*(str + pos) = '.';
	pos++;
	started = 0;

	if (do_digit(str + pos, &addr, 1000, &pos, len, &started))
		return str;

	if (do_digit(str + pos, &addr, 100, &pos, len, &started))
		return str;

	if (do_digit(str + pos, &addr, 10, &pos, len, &started))
		return str;

	if (do_digit(str + pos, &addr, 1, &pos, len, &started))
		return str;

	if (pos == len)
		return str;

	*(str + pos) = 0;

	return str;
}


const char *dnet_ntop(int af, const void *addr, char *str, size_t len)
{
	switch(af) {
		case AF_DECnet:
			errno = 0;
			return dnet_ntop1((struct dn_naddr *)addr, str, len);
		default:
			errno = EAFNOSUPPORT;
	}

	return NULL;
}

static __inline__ u_int16_t dn_htons(u_int16_t addr)
{
        union {
                u_int8_t byte[2];
                u_int16_t word;
        } u;

        u.word = addr;
        return ((u_int16_t)u.byte[0]) | (((u_int16_t)u.byte[1]) << 8);
}


static int dnet_num(const char *src, u_int16_t * dst)
{
	int rv = 0;
	int tmp;
	*dst = 0;

	while ((tmp = *src++) != 0) {
		tmp -= '0';
		if ((tmp < 0) || (tmp > 9))
			return rv;

		rv++;
		(*dst) *= 10;
		(*dst) += tmp;
	}

	return rv;
}

static int dnet_pton1(const char *src, struct dn_naddr *dna)
{
	u_int16_t addr;
	u_int16_t area = 0;
	u_int16_t node = 0;
	int pos;

	pos = dnet_num(src, &area);
	if ((pos == 0) || (area > 63) || (*(src + pos) != '.'))
		return 0;
	pos = dnet_num(src + pos + 1, &node);
	if ((pos == 0) || (node > 1023))
		return 0;
	dna->a_len = 2;
	addr = dn_htons((area << 10) | node);
	memcpy(dna->a_addr, &addr, sizeof(addr));

	return 1;
}

int dnet_pton(int af, const char *src, void *addr)
{
	int err;

	switch (af) {
	case AF_DECnet:
		errno = 0;
		err = dnet_pton1(src, (struct dn_naddr *)addr);
		break;
	default:
		errno = EAFNOSUPPORT;
		err = -1;
	}

	return err;
}
