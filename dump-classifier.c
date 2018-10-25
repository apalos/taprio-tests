/*
 * Copyright (c) 2018, Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <argp.h>
#include <inttypes.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NSEC_TO_SEC 1e9

#define NUM_FILTERS 8
#define NUM_ENTRIES 64
#define MAX_ARGS 100

/* TAPRIO */
enum {
	TC_TAPRIO_CMD_SET_GATES = 0x00,
	TC_TAPRIO_CMD_SET_AND_HOLD = 0x01,
	TC_TAPRIO_CMD_SET_AND_RELEASE = 0x02,
};

#define NEXT_ARG() \
	do {								\
		argv++;							\
		if (--argc <= 0) {					\
			fprintf(stderr, "Incomplete command\n");	\
			exit(-1);					\
		}							\
	} while (0)

enum traffic_flags {
	TRAFFIC_FLAGS_TXTIME,
};

struct tc_filter {
	char *name;
	struct bpf_program prog;
	unsigned int flags;
};

struct sched_entry {
	uint8_t command;
	uint32_t gatemask;
	uint32_t interval;
};

struct schedule {
	struct sched_entry entries[NUM_ENTRIES];
	int64_t base_time;
	size_t current_entry;
	size_t num_entries;
	int64_t cycle_time;
};

static struct argp_option options[] = {
	{"batch-file", 's', "BATCH_FILE", 0, "File containing the taprio configuration" },
	{"dump-file", 'd', "DUMP_FILE", 0, "File containing the tcpdump dump" },
	{"filters-file", 'f', "FILTERS_FILE", 0, "File containing the classfication filters" },
	{ 0 }
};

static struct tc_filter traffic_filters[NUM_FILTERS];
static FILE *batch_file, *dump_file, *filters_file;
static struct schedule schedule;

static error_t parser(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 's':
		batch_file = fopen(arg, "r");
		if (!batch_file) {
			perror("Could not open file, fopen");
			exit(EXIT_FAILURE);
		}
		break;
	case 'd':
		dump_file = fopen(arg, "r");
		if (!dump_file) {
			perror("Could not open file, fopen");
			exit(EXIT_FAILURE);
		}
		break;
	case 'f':
		filters_file = fopen(arg, "r");
		if (!filters_file) {
			perror("Could not open file, fopen");
			exit(EXIT_FAILURE);
		}
		break;
	}

	return 0;
}

static struct argp argp = { options, parser };

static void usage(void)
{
	fprintf(stderr, "dump-classifier -s <tc batch file> -d <dump-file> -f <filters-file>\n");
}

/* split command line into argument vector */
int makeargs(char *line, char *argv[], int max_args)
{
	static const char ws[] = " \t\r\n";
	char *cp = line;
	int argc = 0;

	while (*cp) {
		/* skip leading whitespace */
		cp += strspn(cp, ws);

		if (*cp == '\0')
			break;

		if (argc >= (max_args - 1))
			return -1;

		/* word begins with quote */
		if (*cp == '\'' || *cp == '"') {
			char quote = *cp++;

			argv[argc++] = cp;
			/* find ending quote */
			cp = strchr(cp, quote);
			if (cp == NULL) {
				fprintf(stderr, "Unterminated quoted string\n");
				exit(1);
			}
		} else {
			argv[argc++] = cp;

			/* find end of word */
			cp += strcspn(cp, ws);
			if (*cp == '\0')
				break;
		}

		/* seperate words */
		*cp++ = 0;
	}
	argv[argc] = NULL;

	return argc;
}

/* Like glibc getline but handle continuation lines and comments */
ssize_t getcmdline(char **linep, size_t *lenp, FILE *in)
{
	ssize_t cc;
	char *cp;

	cc = getline(linep, lenp, in);
	if (cc < 0)
		return cc;	/* eof or error */

	cp = strchr(*linep, '#');
	if (cp)
		*cp = '\0';

	while ((cp = strstr(*linep, "\\\n")) != NULL) {
		char *line1 = NULL;
		size_t len1 = 0;
		ssize_t cc1;

		cc1 = getline(&line1, &len1, in);
		if (cc1 < 0) {
			fprintf(stderr, "Missing continuation line\n");
			return cc1;
		}

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

static int parse_filters(pcap_t *handle, FILE *file,
			 struct tc_filter *filters, size_t num_filters)
{
	char *name, *expression;
	size_t i = 0;
	int err;

	while (i < num_filters && fscanf(file, "%ms :: %m[^\n]s\n",
					 &name, &expression) != EOF)  {
		struct tc_filter *filter = &filters[i];

		filter->name = name;

		err = pcap_compile(handle, &filter->prog, expression,
				   1, PCAP_NETMASK_UNKNOWN);
		if (err < 0) {
			pcap_perror(handle, "pcap_compile");
			return -EINVAL;
		}

		i++;
	}

	return i;
}

static int str_to_entry_cmd(const char *str)
{
	if (strcmp(str, "S") == 0)
		return TC_TAPRIO_CMD_SET_GATES;

	if (strcmp(str, "H") == 0)
		return TC_TAPRIO_CMD_SET_AND_HOLD;

	if (strcmp(str, "R") == 0)
		return TC_TAPRIO_CMD_SET_AND_RELEASE;

	return -1;
}

int get_u32(uint32_t *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);

	/* empty string or trailing non-digits */
	if (!ptr || ptr == arg || *ptr)
		return -1;

	/* overflow */
	if (res == ULONG_MAX && errno == ERANGE)
		return -1;

	/* in case UL > 32 bits */
	if (res > 0xFFFFFFFFUL)
		return -1;

	*val = res;
	return 0;
}

int get_s64(int64_t *val, const char *arg, int base)
{
	long res;
	char *ptr;

	errno = 0;

	if (!arg || !*arg)
		return -1;
	res = strtoll(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr)
		return -1;
	if ((res == LLONG_MIN || res == LLONG_MAX) && errno == ERANGE)
		return -1;
	if (res > INT64_MAX || res < INT64_MIN)
		return -1;

	*val = res;
	return 0;
}

static int parse_batch_file(FILE *file, struct schedule *schedule, size_t max_entries)
{
	int argc;
	char *arguments[MAX_ARGS];
	char **argv;
	size_t len;
	char *line = NULL;
	int err;

	if (getcmdline(&line, &len, file) < 0) {
		fprintf(stderr, "Could not read batch file\n");
		exit(EXIT_FAILURE);
	}

	argc = makeargs(line, arguments, MAX_ARGS);
	if (argc < 0) {
		fprintf(stderr, "Could not parse arguments\n");
		return -1;
	}

	argv = arguments;

	while (argc > 0) {
	        if (strcmp(*argv, "sched-entry") == 0) {
			struct sched_entry *e;

			if (schedule->num_entries >= max_entries) {
				fprintf(stderr, "The maximum number of schedule entries is %zu\n", max_entries);
				return -1;
			}

			e = &schedule->entries[schedule->num_entries];

			NEXT_ARG();
			err = str_to_entry_cmd(*argv);
			if (err < 0) {
				fprintf(stderr, "Could not parse command (found %s)\n", *argv);
				return  -1;
			}
			e->command = err;

			NEXT_ARG();
			if (get_u32(&e->gatemask, *argv, 16)) {
				fprintf(stderr, "Could not parse gatemask (found %s)\n", *argv);
				return -1;
			}

			NEXT_ARG();
			if (get_u32(&e->interval, *argv, 0)) {
				fprintf(stderr, "Could not parse interval (found %s)\n", *argv);
				return -1;
			}

			schedule->num_entries++;

		} else if (strcmp(*argv, "base-time") == 0) {
			NEXT_ARG();
			if (get_s64(&schedule->base_time, *argv, 10)) {
				fprintf(stderr, "Could not parse base-time (found %s)\n", *argv);
				return -1;
			}
		}
		argc--; argv++;
	}

	return 0;
}

/* libpcap re-uses the timeval struct for nanosecond resolution when
 * PCAP_TSTAMP_PRECISION_NANO is specified.
 */
static uint64_t tv_to_nanos(const struct timeval *tv)
{
	return tv->tv_sec * NSEC_TO_SEC + tv->tv_usec;
}

static struct sched_entry *next_entry(struct schedule *schedule)
{
	schedule->current_entry++;

	if (schedule->current_entry >= schedule->num_entries)
		schedule->current_entry = 0;

	return &schedule->entries[schedule->current_entry];
}

static struct sched_entry *first_entry(struct schedule *schedule)
{
	schedule->current_entry = 0;

	return &schedule->entries[0];
}

static struct sched_entry *advance_until(struct schedule *schedule,
					 uint64_t ts, uint64_t *now)
{
	struct sched_entry *first, *entry;
	uint64_t cycle = 0;
	uint64_t n;

	entry = first = first_entry(schedule);

	if (!schedule->cycle_time) {
		do {
			cycle += entry->interval;
			entry = next_entry(schedule);
		} while (entry != first);

		schedule->cycle_time = cycle;
	}

	cycle = schedule->cycle_time;

	n = (ts - schedule->base_time) / cycle;
	*now = schedule->base_time + (n * cycle);

	do {
		if (*now + entry->interval > ts)
			break;

		*now += entry->interval;
		entry = next_entry(schedule);
	} while (true);

	return entry;
}

static int match_packet(const struct tc_filter *filters, int num_filters,
			const struct pcap_pkthdr *hdr,
			const uint8_t *frame)
{
	int err;
	int i;

	for (i = 0; i < num_filters; i++) {
		const struct tc_filter *f = &filters[i];

		err = pcap_offline_filter(&f->prog, hdr, frame);
		if (!err) {
			/* The filter for traffic class 'i' doesn't
			 * match the packet
			 */
			continue;
		}

		return i;
	}

	/* returning 'num_filters' means that the packet matches none
	 * of the filters, so it's a Best Effort packet.
	 */
	return num_filters;
}

static int classify_frames(pcap_t *handle, const struct tc_filter *tc_filters,
			   int num_filters, struct schedule *schedule)
{
	struct sched_entry *entry;
	struct pcap_pkthdr *hdr;
	const uint8_t *frame;
	uint64_t now, ts;
	int err;

	now = schedule->base_time;

	/* Ignore frames until we get to the base_time of the
	 * schedule. */
	do {
		err = pcap_next_ex(handle, &hdr, &frame);
		if (err < 0) {
			pcap_perror(handle, "pcap_next_ex");
			return -EINVAL;
		}

		ts = tv_to_nanos(&hdr->ts);
	} while (ts <= now);

	do {
		const char *name, *ontime;
		int64_t offset;
		int tc;

		ts = tv_to_nanos(&hdr->ts);

		entry = advance_until(schedule, ts, &now);

		tc = match_packet(tc_filters, num_filters, hdr, frame);

		if (tc < num_filters)
			name = tc_filters[tc].name;
		else
			name = "BE";

		if (entry->gatemask & (1 << tc))
			ontime = "ontime";
		else
			ontime = "late";

		offset = ts - now;

		/* XXX: what more information might we need? */
		printf("%" PRIu64 " %" PRIu64 " \"%s\" \"%s\" %" PRId64 " %#x\n",
		       ts, now, name, ontime, offset, entry->gatemask);
	} while (pcap_next_ex(handle, &hdr, &frame) >= 0);

	return 0;
}

static void free_filters(struct tc_filter *filters, int num_filters)
{
	int i;

	for (i = 0; i < num_filters; i++) {
		struct tc_filter *f = &filters[i];

		free(f->name);
	}
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int err, num;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	if (!dump_file || !batch_file || !filters_file) {
		usage();
		exit(EXIT_FAILURE);
	}

	err = parse_batch_file(batch_file, &schedule, NUM_ENTRIES);
	if (err < 0) {
		fprintf(stderr, "Could not parse schedule file (or file empty)\n");
		exit(EXIT_FAILURE);
	}

	handle = pcap_fopen_offline_with_tstamp_precision(
		dump_file, PCAP_TSTAMP_PRECISION_NANO, errbuf);
	if (!handle) {
		fprintf(stderr, "Could not parse dump file\n");
		exit(EXIT_FAILURE);
	}

	num = parse_filters(handle, filters_file,
			    traffic_filters, NUM_FILTERS);
	if (err < 0) {
		fprintf(stderr, "Could not filters file\n");
		exit(EXIT_FAILURE);
	}

	err = classify_frames(handle, traffic_filters, num, &schedule);
	if (err < 0) {
		fprintf(stderr, "Could not classify frames\n");
		exit(EXIT_FAILURE);
	}

	free_filters(traffic_filters, num);

	pcap_close(handle);

	return 0;
}
