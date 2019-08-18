#include <unistd.h>
#include "erofs/config.h"
#include "erofs/fuzzer.h"
#include "erofs/print.h"

void erofs_fuzz(void *buf, unsigned int length)
{
	int fd, ret;
	unsigned int a1, a2;

	/* whether the fuzzer is disabled */
	if (!cfg.c_fuzz_trapcount)
		return;

	/* whether this field should be fuzzed */
	if (cfg.c_fuzz_trapcount-- != 1)
		return;

	fd = open("/dev/urandom", O_RDONLY);

	do {
		ret = read(fd, &a1, sizeof(a1));
		a1 %= length;

		ret = read(fd, &a2, sizeof(a2));
		a2 %= length;
	} while (a1 == a2);

	if (a1 > a2) {
		const unsigned int t = a1;

		a1 = a2;
		a2 = t;
	}
	ret = read(fd, buf + a1, a2 - a1);
	erofs_err("fuzzed!");
	close(fd);
}

