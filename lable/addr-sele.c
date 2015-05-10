/*
  Base on and follow the iproute2 style
  license: GNU General Public License

  Aaron Yi Ding, University of Helsinki
  yding@cs.helsinki.fi

  last update: 29.10.2010

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/types.h>
#include <linux/if_addrlabel.h>
#include <netinet/ip.h>

#include "ip-addr.h"

#define IFAL_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrlblmsg))))

#define IFAL_PAYLOAD(n)  NLMSG_PAYLOAD(n,sizeof(struct ifaddrlblmsg))

int preferred_family = AF_UNSPEC;
int show_stats = 0;
int show_details = 0;
int resolve_hosts = 0;
int oneline = 0;
int timestamp = 0;
char * _SL_ = NULL;
char *batch_file = NULL;
int force = 0;
struct rtnl_handle rth = { .fd = -1 };

static void Usage(void) __attribute__((noreturn));

static void Usage(void) {
    fprintf(stderr, "Usage: ./label [ show | add | del ] prefix PREFIX [ label LABEL ]\n");
    exit(-1);
}

int print_addrlabel(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg) {
    FILE *fp = (FILE*)arg;
    struct ifaddrlblmsg *ifal = NLMSG_DATA(n);
    int len = n->nlmsg_len;
    int host_len = -1;
    struct rtattr *tb[IFAL_MAX+1];
    char abuf[256];

    if (n->nlmsg_type != RTM_NEWADDRLABEL && n->nlmsg_type != RTM_DELADDRLABEL)
        return 0;

    len -= NLMSG_LENGTH(sizeof(*ifal));

    if (len < 0)
        return -1;

    parse_rtattr(tb, IFAL_MAX, IFAL_RTA(ifal), len);

    if (ifal->ifal_family == AF_INET)
        host_len = 32;
    else if (ifal->ifal_family == AF_INET6)
        host_len = 128;

    if (n->nlmsg_type == RTM_DELADDRLABEL)
        fprintf(fp, "Deleted ");

    if (tb[IFAL_ADDRESS]) {
        fprintf(fp, "prefix %s/%u ", 
                format_host(ifal->ifal_family, RTA_PAYLOAD(tb[IFAL_ADDRESS]),
                            RTA_DATA(tb[IFAL_ADDRESS]),
                            abuf, sizeof(abuf)),
                ifal->ifal_prefixlen);
    }

    if (ifal->ifal_index)
        fprintf(fp, "dev %s ", ll_index_to_name(ifal->ifal_index));

    if (tb[IFAL_LABEL] && RTA_PAYLOAD(tb[IFAL_LABEL]) == sizeof(int32_t)) {
        int32_t label;
        memcpy(&label, RTA_DATA(tb[IFAL_LABEL]), sizeof(label));
        fprintf(fp, "label %d ", label);
    }

    fprintf(fp, "\n");
    fflush(fp);

    return 0;
}

static int ipaddrlabel_modify(int cmd, int argc, char **argv) {
    struct {
        struct nlmsghdr n;
        struct ifaddrlblmsg ifal;
        char buf[1024];
    } req;

    inet_prefix prefix;
    uint32_t label = 0xffffffffUL;
    char *p = NULL;
    char *l = NULL;

    memset(&req, 0, sizeof(req));
    memset(&prefix, 0, sizeof(prefix));

    req.n.nlmsg_type = cmd;
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrlblmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.ifal.ifal_family = preferred_family;
    req.ifal.ifal_prefixlen = 0;
    req.ifal.ifal_index = 0;

    if (cmd == RTM_NEWADDRLABEL) {
        req.n.nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
    }

    while (argc > 0) {
        if (strcmp(*argv, "prefix") == 0) {
            NEXT_ARG();
            p = *argv;
            get_prefix(&prefix, *argv, preferred_family);
        }
        else if (strcmp(*argv, "dev") == 0) {
            NEXT_ARG();
            if ((req.ifal.ifal_index = ll_name_to_index(*argv)) == 0)
                invarg("dev is invalid\n", *argv);
        }
        else if (strcmp(*argv, "label") == 0) {
            NEXT_ARG();
            l = *argv;
            if (get_u32(&label, *argv, 0) || label == 0xffffffffUL)
                invarg("label is invalid\n", *argv);
        }
        argc--;
        argv++;
    }

    if (p == NULL) {
        fprintf(stderr, "Not enough information: \"prefix\" argument is required.\n");
        return -1;
    }

    if (l == NULL) {
        fprintf(stderr, "Not enough information: \"label\" argument is required.\n");
        return -1;
    }

    addattr32(&req.n, sizeof(req), IFAL_LABEL, label);
    addattr_l(&req.n, sizeof(req), IFAL_ADDRESS, &prefix.data, prefix.bytelen);
    req.ifal.ifal_prefixlen = prefix.bitlen;

    if (req.ifal.ifal_family == AF_UNSPEC)
        req.ifal.ifal_family = AF_INET6;

    if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
        return 2;

    return 0;
}

int Label_show(int argc, char **argv) {
    int af = preferred_family;

    if (af == AF_UNSPEC)
        af = AF_INET6;

    if (argc > 0) {
        fprintf(stderr, "\"label show\" does not take any arguments.\n");
        return -1;
    }

    if (rtnl_wilddump_request(&rth, af, RTM_GETADDRLABEL) < 0) {
        perror("Can not send dump request");
        return 1;
    }

    if (rtnl_dump_filter(&rth, print_addrlabel, stdout, NULL, NULL) < 0) {
        fprintf(stderr, "Dump terminated\n");
        return 1;
    }

    return 0;
}

int Label_add(int argc, char **argv) {
    return ipaddrlabel_modify(RTM_NEWADDRLABEL, argc, argv);
}

int Label_del(int argc, char **argv) {
    return ipaddrlabel_modify(RTM_DELADDRLABEL, argc, argv);
}

int main(int argc, char **argv)
{
    if (rtnl_open(&rth, 0)<0)
        exit(1);

    ll_init_map(&rth);

    if (argc > 1) {
        if (matches(argv[1], "show") == 0 || matches(argv[1], "list") == 0) {
            return Label_show(argc-2, argv+2);
        }
        else if (matches(argv[1], "add") == 0) {
            return Label_add(argc-2, argv+2);
        }
        else if (matches(argv[1], "delete") == 0) {
            return Label_del(argc-2, argv+2);
        }
    }

    rtnl_close(&rth);

    Usage();
}
