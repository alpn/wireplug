#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <pcap-int.h>
#include <pcap.h>

#define	BUFLEN 1024

void
get_bpf_program(struct bpf_program *prog, int snaplen, const char* rly_ip, const char* src_ip, const char* port)
{
	char filter[BUFLEN];
	pcap_t hpcap;

	if (snprintf(filter, sizeof(filter),
		"udp and src host %s and dst host %s and dst port %s "
		"and udp[8:4] = 0x01000000", // wg init packets
		src_ip, rly_ip, port) < 0)
		errx(1, "snprintf");

	hpcap.snapshot = snaplen;
	hpcap.linktype = 1;
	if (pcap_compile(&hpcap, prog, filter, 1, 0))
		err(1, "%s", hpcap.errbuf);
}

int
get_bpf_sock(const char *if_name, struct bpf_program *prog)
{
	struct ifreq ifr;
	int	fd, immediate, fildrop;
	u_int sz;

	if ((fd = open("/dev/bpf",  O_RDONLY)) == -1)
		err(1, "open(bpf)");

	sz = BUFLEN;
	if (ioctl(fd, BIOCSBLEN, &sz) == -1)
		err(1, "BIOCSBLEN");
	if (sz != BUFLEN)
		err(1, "BIOCSBLEN, expected %u, got %u", BUFLEN, sz);

	immediate = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &immediate) == -1)
		err(1, "BIOCIMMEDIATE");

	fildrop = BPF_FILDROP_CAPTURE;
	if (ioctl(fd, BIOCSFILDROP, &fildrop) == -1)
		err(1, "BIOCSFILDROP");

	if (ioctl(fd, BIOCSETF, prog) == -1)
		err(1, "BIOCSETF");

	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
		close(fd);
		return -1;
	}

	if (ioctl(fd, BIOCLOCK, NULL) == -1)
		err(1, "BIOCLOCK");

	return fd;
}

int
main(const int argc, const char *argv[]) {
    
	uint8_t buf[BUFLEN];
	struct bpf_program prog;
	struct bpf_hdr *hdr;
	struct udphdr *udp;
    ssize_t sz;
	int fd, snaplen, res = 1;

	if (argc != 5)
		err(1, "args");

	if (unveil("/dev/bpf" ,"r") == -1)
		err(1, "unveil");

	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");

	const char* if_name = argv[1];
	const char* rly_ip = argv[2];
	const char* src_ip = argv[3];
	const char* port = argv[4];

	const char* stnerr;
	if (strtonum(port, 1024, UINT16_MAX, &stnerr) == 0)
		errx(1, "port %s", stnerr);

	snaplen = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + 4;
	get_bpf_program(&prog, snaplen, rly_ip, src_ip, port);

    if ((fd = get_bpf_sock(if_name, &prog)) == -1)
		err(1, "bpf");

	if (pledge("stdio", "") == -1)
		goto out;

	int retries = 3;
    while (retries--) {

        if ((sz = read(fd, buf, BUFLEN)) == -1)
            continue;

        if (sz < sizeof(struct bpf_hdr))
            continue;

        hdr = (struct bpf_hdr *)buf;
		if (hdr->bh_caplen != snaplen)
            continue;

        size_t ip_data_offset = hdr->bh_hdrlen + sizeof(struct ether_header)
				+ sizeof(struct ip);

        if (sz < ip_data_offset + sizeof(struct udphdr) + 4)
            continue;

		udp = (struct udphdr*)((uint8_t*)(buf + ip_data_offset));

		if (ntohs(udp->uh_ulen) != 156)
			continue;

		if (write(1, &udp->uh_sport, 2) != 2)
			goto out;

		res = 0;
		break;
    }
out:
	close(fd);
    return res;
}
