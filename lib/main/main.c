#include "../../include/head.h"
#include "../../include/config.h"
#include "../../lib/banner/banner.h"

typedef enum { RES_UNKNOWN=0, RES_TCP_OPEN, RES_UDP_OPEN, RES_CLOSED } res_type_t;

typedef struct {
	int port;
	res_type_t res;
	char svc[128];
	char banner[1024];
	int tcp_open;
	int udp_open;
} port_result_t;

typedef struct { int port; } job_t;

typedef struct {
	const char *name;
	int port;
	const char *probe; size_t probe_len;
	const char *match;
} fp_entry_t;

char target_host[256];
char target_ip[64];
int start_port;
int end_port;
int num_threads;
int timeout_sec;
int total_ports;
int consent_flag = 0;
int max_rate_per_sec = 0;
int delay_ms = 0;

int scan_tcp = 1;
int scan_udp = 1;
int bport_flag = 0;

job_t *jobs = NULL;
int jobs_total = 0;
int jobs_index = 0;
pthread_mutex_t jobs_mutex = PTHREAD_MUTEX_INITIALIZER;

port_result_t *results = NULL;
int results_count = 0;
pthread_mutex_t results_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
int progress_sent = 0;

pthread_mutex_t rate_mutex = PTHREAD_MUTEX_INITIALIZER;
int rate_count = 0;
time_t rate_window = 0;

static const char PROBE_HTTP[] = "HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n";
static const char PROBE_HTTP_GET[] = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
static const char PROBE_SMTP[] = "EHLO scanner.example\r\n";
static const char PROBE_REDIS[] = "INFO\r\n";
static const char PROBE_MEMCACHED[] = "version\r\n";
static const char PROBE_SMTP_HELO[] = "HELO scanner.example\r\n";

static fp_entry_t FP_DB[] = {
	{"http", 80, PROBE_HTTP, sizeof(PROBE_HTTP)-1, "HTTP/"},
	{"http", 8080, PROBE_HTTP, sizeof(PROBE_HTTP)-1, "HTTP/"},
	{"http", 8000, PROBE_HTTP, sizeof(PROBE_HTTP)-1, "HTTP/"},
	{"smtp", 25, PROBE_SMTP, sizeof(PROBE_SMTP)-1, "SMTP"},
	{"redis", 6379, PROBE_REDIS, sizeof(PROBE_REDIS)-1, "redis_version"},
	{"memcached", 11211, PROBE_MEMCACHED, sizeof(PROBE_MEMCACHED)-1, "VERSION"},
};
static int FP_DB_COUNT = sizeof(FP_DB)/sizeof(FP_DB[0]);

void color_print(const char *color, const char *fmt, ...)
{
	va_list ap;
	pthread_mutex_lock(&print_mutex);
	printf("%s", color);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("%s", ANSI_RESET);
	pthread_mutex_unlock(&print_mutex);
}

void hexlor(const char *label, const uint8_t *buf, ssize_t len)
{
	if (len == 0)
	{
		return;
	}
	int idx = (int)(len % COLORS_COUNT);
	pthread_mutex_lock(&print_mutex);
	printf("%s (len=%zd): ", label, len);
	printf("%s", COLORS[idx]);
	for (ssize_t i = 0; i < len; i++)
	{
		printf("0x%02x ", buf[i]);
		if ((i + 1) % HEX_LINE == 0)
		{
			printf("\n               ");
		}
	}
	printf("%s\n", ANSI_RESET);
	pthread_mutex_unlock(&print_mutex);
}

void safe(const char *fmt, ...)
{
	va_list ap;
	pthread_mutex_lock(&print_mutex);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	pthread_mutex_unlock(&print_mutex);
}

char *my_strnstr(const char *hay, const char *needle, size_t len)
{
	size_t needle_len;
	if (!*needle)
	{
		return (char*)hay;
	}
	needle_len = strlen(needle);
	if (needle_len == 0)
	{
		return (char*)hay;
	}
	if (len < needle_len)
	{
		return NULL;
	}
	size_t limit = len - needle_len + 1;
	for (size_t i = 0; i < limit; i++)
	{
		if (memcmp(hay + i, needle, needle_len) == 0)
		{
			return (char*)(hay + i);
		}
	}
	return NULL;
}

int resolve_target(const char *host, char *ip, size_t outlen)
{
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	if (getaddrinfo(host, NULL, &hints, &res) != 0)
	{
		return -1;
	}
	struct sockaddr_in *sin = (struct sockaddr_in*)res->ai_addr;
	inet_ntop(AF_INET, &sin->sin_addr, ip, outlen);
	freeaddrinfo(res);
	return 0;
}

int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
	{
		return -1;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void add_result(const port_result_t *r)
{
	pthread_mutex_lock(&results_mutex);
	if (results_count < MAX_RESULTS)
	{
		results[results_count++] = *r;
	}
	pthread_mutex_unlock(&results_mutex);
}

int next_job()
{
	pthread_mutex_lock(&jobs_mutex);
	int idx = -1;
	if (jobs_index < jobs_total)
	{
		idx = jobs_index++;
	}
	pthread_mutex_unlock(&jobs_mutex);
	return idx;
}

const fp_entry_t *choose_probe_by_port(int port)
{
	for (int i = 0; i < FP_DB_COUNT; i++)
	{
		if (FP_DB[i].port == port)
		{
			return &FP_DB[i];
		}
	}
	return NULL;
}

void fingerprint_guess(port_result_t *r, const char *recvbuf, size_t rlen)
{
	if (!r)
	{
		return;
	}
	if (recvbuf && rlen > 0)
	{
		for (int i = 0; i < FP_DB_COUNT; i++)
		{
			if (FP_DB[i].match && my_strnstr(recvbuf, FP_DB[i].match, rlen))
			{
				strncpy(r->svc, FP_DB[i].name, sizeof(r->svc) - 1);
				r->svc[sizeof(r->svc) - 1] = '\0';
				return;
			}
		}
	}

	switch (r->port)
	{
		case 22:
			strncpy(r->svc, "ssh", sizeof(r->svc) - 1);
			r->svc[sizeof(r->svc) - 1] = '\0';
			break;
		case 80:
		case 8080:
			strncpy(r->svc, "http", sizeof(r->svc) - 1);
			r->svc[sizeof(r->svc) - 1] = '\0';
			break;
		case 445:
			strncpy(r->svc, "smb", sizeof(r->svc) - 1);
			r->svc[sizeof(r->svc) - 1] = '\0';
			break;
		case 3306:
			strncpy(r->svc, "mysql", sizeof(r->svc) - 1);
			r->svc[sizeof(r->svc) - 1] = '\0';
			break;
		case 6379:
			strncpy(r->svc, "redis", sizeof(r->svc) - 1);
			r->svc[sizeof(r->svc) - 1] = '\0';
			break;
		case 11211:
			strncpy(r->svc, "memcached", sizeof(r->svc) - 1);
			r->svc[sizeof(r->svc) - 1] = '\0';
			break;
		case 53:
			strncpy(r->svc, "dns", sizeof(r->svc) - 1);
			r->svc[sizeof(r->svc) - 1] = '\0';
			break;
		default:
			strncpy(r->svc, "N/A", sizeof(r->svc) - 1);
			r->svc[sizeof(r->svc) - 1] = '\0';
			break;
	}
}

int rate_allow()
{
	if (max_rate_per_sec <= 0)
	{
		return 1;
	}
	time_t now = time(NULL);
	pthread_mutex_lock(&rate_mutex);

	if (now != rate_window)
	{
		rate_window = now;
		rate_count = 0;
	}

	if (rate_count < max_rate_per_sec)
	{
		rate_count++;
		pthread_mutex_unlock(&rate_mutex);
		return 1;
	}

	pthread_mutex_unlock(&rate_mutex);
	return 0;
}

int tcp_connect_nonblocking(const char *ip, int port, int timeout_sec)
{
	int sock;
	struct sockaddr_in addr;
	fd_set wfds;
	struct timeval tv;
	int ret, err;
	socklen_t len;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
	{
		close(sock);
		return -1;
	}

	if (set_nonblocking(sock) < 0)
	{
		close(sock);
		return -1;
	}

	ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));

	if (ret == 0)
	{
		int flags = fcntl(sock, F_GETFL, 0);
		fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
		return sock;
	}
	else if (errno != EINPROGRESS)
	{
		close(sock);
		return -1;
	}

	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);

	tv.tv_sec = timeout_sec;
	tv.tv_usec = 0;
	ret = select(sock + 1, NULL, &wfds, NULL, &tv);

	if (ret > 0 && FD_ISSET(sock, &wfds))
	{
		len = sizeof(err);
		if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
		{
			close(sock);
			return -1;
		}

		if (err == 0)
		{
			int flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
			return sock;
		}
	}

	close(sock);
	return -1;
}

ssize_t recv_banner(int sock, char *buf, size_t bufsz, int timeout_sec)
{
	fd_set rfds;
	struct timeval tv;
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tv.tv_sec = timeout_sec;
	tv.tv_usec = 0;
	int r = select(sock + 1, &rfds, NULL, NULL, &tv);

	if (r > 0 && FD_ISSET(sock, &rfds))
	{
		ssize_t n = recv(sock, buf, bufsz - 1, 0);
		if (n > 0)
		{
			buf[n] = '\0';
			return n;
		}
	}

	return 0;
}

ssize_t send_probe_and_recv(int sock, const uint8_t *probe, size_t plen, char *outbuf, size_t outbufblen)
{
	if (probe && plen > 0)
	{
		hexlor("BPORT - TCP SENDED", probe, (ssize_t)plen);
		ssize_t s = send(sock, probe, plen, 0);
		(void)s;
	}

	ssize_t n = recv_banner(sock, outbuf, outbufblen, timeout_sec);
	if (n > 0)
	{
		hexlor("BPORT - TCP RECV", (uint8_t*)outbuf, n);
	}
	return n;
}

int udp_probe(const char *ip, int port, int timeout_sec, char *outbuf, size_t outlen)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		return 0;
	}
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
	{
		close(sock);
		return 0;
	}

	uint8_t sendbuf[512];
	size_t sendlen = 0;

	if (port == 53)
	{
		uint8_t dnsq[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0x00, 0x01, 0x00, 0x01};
		memcpy(sendbuf, dnsq, sizeof(dnsq));
		sendlen = sizeof(dnsq);
	}
	else if (port == 123)
	{
		uint8_t ntp[] = {0x1b, 0, 0, 0};
		memcpy(sendbuf, ntp, sizeof(ntp));
		sendlen = sizeof(ntp);
	}
	else if (port == 69)
	{
		uint8_t tftp[] = {0x00, 0x01, 'a', 0x00, '0', 'c', 't', 'e', 't', 0x00};
		memcpy(sendbuf, tftp, sizeof(tftp));
		sendlen = sizeof(tftp);
	}
	else
	{
		const char *g = "scanner_probe";
		sendlen = strlen(g);
		memcpy(sendbuf, g, sendlen);
	}

	hexlor("BPORT - UDP SENDED", sendbuf, (ssize_t)sendlen);
	ssize_t sret = sendto(sock, sendbuf, sendlen, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (sret < 0)
	{
		close(sock);
		return 0;
	}

	fd_set rf;
	struct timeval tv;
	FD_ZERO(&rf);
	FD_SET(sock, &rf);
	tv.tv_sec = timeout_sec;
	tv.tv_usec = 0;

	int r = select(sock + 1, &rf, NULL, NULL, &tv);
	if (r > 0 && FD_ISSET(sock, &rf))
	{
		ssize_t n = recv(sock, outbuf, outlen - 1, 0);
		if (n > 0)
		{
			outbuf[n] = '\0';
			hexlor("BPORT - UDP RECV", (uint8_t*)outbuf, n);
			close(sock);
			return 1;
		}
	}

	close(sock);
	return 0;
}

void *worker_thread(void *arg)
{
	(void)arg;
	while (1)
	{
		int idx = next_job();
		if (idx < 0)
		{
			break;
		}
		int port = jobs[idx].port;
		port_result_t r;
		memset(&r, 0, sizeof(r));
		r.port = port;
		r.res = RES_UNKNOWN;

		while (!rate_allow())
		{
			usleep(1000);
		}

		pthread_mutex_lock(&print_mutex);
		progress_sent++;
		printf("BPORT - PROGRESS port %d (%d/%d)\n", port, progress_sent, total_ports);
		pthread_mutex_unlock(&print_mutex);

		if (scan_tcp)
		{
			int sock = tcp_connect_nonblocking(target_ip, port, timeout_sec);
			if (sock >= 0)
			{
				r.tcp_open = 1;
				r.res = RES_TCP_OPEN;
				char banner[1024];
				memset(banner, 0, sizeof(banner));
				ssize_t n = recv_banner(sock, banner, sizeof(banner), timeout_sec);
				if (n > 0)
				{
					for (ssize_t i = 0; i < n; i++)
					{
						if (banner[i] == '\r' || banner[i] == '\n')
						{
							banner[i] = ' ';
						}
					}
					strncpy(r.banner, banner, sizeof(r.banner) - 1);
					r.banner[sizeof(r.banner) - 1] = '\0';
					fingerprint_guess(&r, banner, (size_t)n);
					hexlor("BPORT - TCP BANNER", (uint8_t*)banner, n);
				}
				else
				{
					const fp_entry_t *fp = choose_probe_by_port(port);
					if (bport_flag)
					{
						for (int pi = 0; pi < FP_DB_COUNT; pi++)
						{
							char probe_resp[1024];
							memset(probe_resp, 0, sizeof(probe_resp));
							ssize_t pn = send_probe_and_recv(sock, (const uint8_t*)FP_DB[pi].probe, FP_DB[pi].probe_len, probe_resp, sizeof(probe_resp));
							if (pn > 0)
							{
								for (ssize_t i = 0; i < pn; i++)
								{
									if (probe_resp[i] == '\r' || probe_resp[i] == '\n')
									{
										probe_resp[i] = ' ';
									}
								}
								strncpy(r.banner, probe_resp, sizeof(r.banner) - 1);
								r.banner[sizeof(r.banner) - 1] = '\0';
								fingerprint_guess(&r, probe_resp, (size_t)pn);
								break;
							}
						}
					}
					else if (fp)
					{
						char probe_resp[1024];
						memset(probe_resp, 0, sizeof(probe_resp));
						ssize_t pn = send_probe_and_recv(sock, (const uint8_t*)fp->probe, fp->probe_len, probe_resp, sizeof(probe_resp));
						if (pn > 0)
						{
							for (ssize_t i = 0; i < pn; i++)
							{
								if (probe_resp[i] == '\r' || probe_resp[i] == '\n')
								{
									probe_resp[i] = ' ';
								}
							}
							strncpy(r.banner, probe_resp, sizeof(r.banner) - 1);
							r.banner[sizeof(r.banner) - 1] = '\0';
							fingerprint_guess(&r, probe_resp, (size_t)pn);
						}
					}
				}
				close(sock);
			}
		}

		char uresp[1024];
		memset(uresp, 0, sizeof(uresp));
		int udp_ok = 0;
		if (scan_udp)
		{
			udp_ok = udp_probe(target_ip, port, timeout_sec, uresp, sizeof(uresp));
		}
		if (udp_ok)
		{
			r.udp_open = 1;
			if (!r.tcp_open)
			{
				r.res = RES_UDP_OPEN;
			}
			if (strlen(uresp) > 0 && strlen(r.banner) == 0)
			{
				strncpy(r.banner, uresp, sizeof(r.banner) - 1);
				r.banner[sizeof(r.banner) - 1] = '\0';
			}
			if (strlen(uresp) > 0)
			{
				fingerprint_guess(&r, uresp, strlen(uresp));
			}
		}

		if (!r.tcp_open && !r.udp_open)
		{
			r.res = RES_CLOSED;
		}
		add_result(&r);

		if (delay_ms > 0)
		{
			usleep(delay_ms * 1000);
		}
	}

	return NULL;
}

void write_json_output(const char *fname)
{
	FILE *f = fopen(fname, "w");
	if (!f)
	{
		safe("Failed to open %s: %s\n", fname, strerror(errno));
		return;
	}
	fprintf(f, "{\n");
	fprintf(f, "  \"target\": \"%s\",\n", target_ip);
	fprintf(f, "  \"scanned_ports\": %d,\n", results_count);
	fprintf(f, "  \"results\": [\n");
	for (int i = 0; i < results_count; i++)
	{
		port_result_t *r = &results[i];
		const char *rtype = "unknown";
		if (r->res == RES_TCP_OPEN)
		{
			rtype = "tcp_open";
		}
		else if (r->res == RES_UDP_OPEN)
		{
			rtype = "udp_open";
		}
		else if (r->res == RES_CLOSED)
		{
			rtype = "closed";
		}
		char sb[2048] = {0};
		size_t si = 0;
		for (size_t j = 0; j < strlen(r->banner) && si + 2 < sizeof(sb); j++)
		{
			char c = r->banner[j];
			if (c == '\\' || c == '\"')
			{
				sb[si++] = '\\';
				sb[si++] = c;
			}
			else if ((unsigned char)c < 32)
			{
			}
			else
			{
				sb[si++] = c;
			}
		}
		sb[si] = 0;
		fprintf(f, "    { \"port\": %d, \"type\": \"%s\", \"service_guess\": \"%s\", \"banner\": \"%s\", \"tcp\": %d, \"udp\": %d }%s\n",
		        r->port, rtype, r->svc, sb, r->tcp_open, r->udp_open, (i == results_count - 1) ? "" : ",");
	}
	fprintf(f, "  ]\n");
	fprintf(f, "}\n");
	fclose(f);
	safe("[+] JSON written to %s\n", fname);
}

int main(int argc, char **argv)
{
	bport();
	sleep(5);

	char *pos_args[16];
	int posc = 0;
	for (int i = 1; i < argc; i++)

	{
		if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0)
		{
			scan_tcp = 1;
			scan_udp = 1;
			continue;
		}
		if (strcmp(argv[i], "--tcp") == 0)
		{
			scan_tcp = 1;
			scan_udp = 0;
			continue;
		}
		if (strcmp(argv[i], "--udp") == 0)
		{
			scan_udp = 1;
			scan_tcp = 0;
			continue;
		}
		if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bport") == 0)
		{
			bport_flag = 1;
			continue;
		}
		pos_args[posc++] = argv[i];
	}

	if (posc < 6)
	{
		fprintf(stderr, "Usage: %s [flags] <target> <start-port> <end-port> <threads> <timeout-sec> <consent-yes-or-no> [max-rate-per-sec] [delay-ms]\n", argv[0]);
		fprintf(stderr, "\nFlags: -a|--all    enable tcp+udp probes\n");
		fprintf(stderr, "       --tcp      tcp only\n");
		fprintf(stderr, "       --udp      udp only\n");
		fprintf(stderr, "       -b|--bport bruteforce probes (try all probes on open tcp ports)\n");
		fprintf(stderr, "\nExample: %s --tcp 192.168.1.10 1 1024 50 2 yes 500 10\n", argv[0]);
		return 1;
	}

	strncpy(target_host, pos_args[0], sizeof(target_host) - 1);
	start_port = atoi(pos_args[1]);
	end_port = atoi(pos_args[2]);
	num_threads = atoi(pos_args[3]);
	timeout_sec = atoi(pos_args[4]);
	consent_flag = (strcmp(pos_args[5], "yes") == 0);
	if (posc >= 7)
	{
		max_rate_per_sec = atoi(pos_args[6]);
	}
	if (posc >= 8)
	{
		delay_ms = atoi(pos_args[7]);
	}
	if (!consent_flag)
	{
		fprintf(stderr, "Consent not set (last arg 'yes') - aborting.\n");
		return 2;
	}
	if (num_threads < 1)
	{
		num_threads = 1;
	}
	if (num_threads > MAX_THREADS)
	{
		num_threads = MAX_THREADS;
	}
	if (start_port < 1)
	{
		start_port = 1;
	}
	if (end_port > 65535)
	{
		end_port = 65535;
	}
	if (end_port < start_port)
	{
		fprintf(stderr, "Invalid port range\n");
		return 1;
	}

	if (resolve_target(target_host, target_ip, sizeof(target_ip)) != 0)
	{
		fprintf(stderr, "Failed to resolve %s\n", target_host);
		return 1;
	}

	total_ports = end_port - start_port + 1;
	safe("* Target %s -> %s\n", target_host, target_ip);
	safe("* Ports %d-%d threads=%d timeout=%ds max_rate=%d delay=%dms\n", start_port, end_port, num_threads, timeout_sec, max_rate_per_sec, delay_ms);

	jobs_total = total_ports;
	jobs = calloc(jobs_total, sizeof(job_t));
	int p = 0;
	for (int port = start_port; port <= end_port; port++)
	{
		jobs[p++].port = port;
	}
	jobs_index = 0;
	results = calloc(MAX_RESULTS, sizeof(port_result_t));
	results_count = 0;

	pthread_t *tids = calloc(num_threads, sizeof(pthread_t));
	for (int i = 0; i < num_threads; i++)
	{
		pthread_create(&tids[i], NULL, worker_thread, NULL);
	}

	for (int i = 0; i < num_threads; i++)
	{
		pthread_join(tids[i], NULL);
	}

	safe("* Scan complete. Collected %d results\n", results_count);
	write_json_output("scan_result.json");

	safe("Open ports summary:\n");
	for (int i = 0; i < results_count; i++)
	{
		port_result_t *r = &results[i];
		if (r->res == RES_TCP_OPEN || r->res == RES_UDP_OPEN)
		{
			safe(" - %5d: %s banner=\"%s\"\n", r->port, r->svc, r->banner);
		}
	}

	free(jobs);
	free(results);
	free(tids);
	return 0;
}
