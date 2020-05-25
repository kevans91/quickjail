/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Kyle Evans <kevans@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <capsicum_helpers.h>
#include <err.h>
#include <jail.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* These can go away when stable/11 goes EoL in 2021. */
#if __FreeBSD_version < 1200000
static __inline int
caph_enter(void)
{

	if (cap_enter() < 0 && errno != ENOSYS)
		return (-1);

	return (0);
}

static __inline int
caph_rights_limit(int fd, const cap_rights_t *rights)
{

	if (cap_rights_limit(fd, rights) < 0 && errno != ENOSYS)
		return (-1);

	return (0);
}
#endif

static void
usage(void)
{

	fprintf(stderr, "usage: quickjail [-c] [param=value ...] command=command ...\n");
	exit(1);
}

static int
quickjail(char *argv[], struct jailparam *params, int nparams, const char *path)
{
	struct kevent kev;
	pid_t pid;
	int fdp, kq, rv, status;
	cap_rights_t rights;

	pid = pdfork(&fdp, 0);
	if (pid == -1)
		err(1, "pdfork");

	if (pid == 0) {
		/* Child */
		if (path != NULL && strcmp(path, ".") != 0 && chdir(path) == -1)
			err(1, "chdir");

		rv = jailparam_set(params, nparams, JAIL_CREATE | JAIL_ATTACH);
		if (rv < 0)
			err(1, "jailparam_set");

		execvp(argv[0], __DECONST(char *const*, argv));
		err(1, "execvp");
	} else {
		if (caph_rights_limit(fdp,
		    cap_rights_init(&rights, CAP_PDKILL, CAP_EVENT)) == -1) {
			pdkill(fdp, SIGKILL);
			err(1, "caph_rights_limit(fdp)");
		}

		/*
		 * The following cases, up until we enter capability mode, will opt to
		 * try killing the child immediately upon error.  I'd tend to prefer the
		 * jail didn't continue to exist if we hit some error case here before
		 * we managed to enter capability mode.
		 */
		kq = kqueue();
		if (kq == -1) {
			pdkill(fdp, SIGKILL);
			err(1, "kqueue");
		}

		/*
		 * We don't actually need stdin at all, so just go ahead and close it.
		 * caph_limit_stdio will still attempt to limit it, but it intentionally
		 * ignores EBADF.
		 */
		close(STDIN_FILENO);
		if (caph_limit_stdio() == -1) {
			pdkill(fdp, SIGKILL);
			err(1, "caph_limit_stdio");
		}

		if (caph_enter() == -1) {
			pdkill(fdp, SIGKILL);
			err(1, "caph_enter");
		}

		EV_SET(&kev, fdp, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
		rv = kevent(kq, &kev, 1, NULL, 0, NULL);
		if (rv == -1) {
			pdkill(fdp, SIGKILL);
			err(1, "kevent");
		}

		if (caph_rights_limit(kq,
		    cap_rights_init(&rights, CAP_KQUEUE_EVENT)) == -1) {
			pdkill(fdp, SIGKILL);
			err(1, "caph_rights_limit(kq)");
		}

		while ((rv = kevent(kq, NULL, 0, &kev, 1, NULL)) == -1 &&
		    errno == EINTR) {
			/* Meh. */
		}

		if (rv == -1)
			err(1, "kevent");

		status = WEXITSTATUS(kev.data);
		return (status);
	}
}

int
main(int argc, char *argv[])
{
	int nparams, paramsz;
	char *curarg, *name, *path, *val;
	struct jailparam jparams[2], *params;

	if (argc < 2) {
		usage();
	}

	/*
	 * quickjail allows an optional -c as a first argument, to maintain an
	 * interface compatible with jail(8) for creatinf a jail.
	 */
	if (strcmp(argv[1], "-c") == 0) {
		argc -= 2;
		argv += 2;
	} else {
		argc--;
		argv++;
	}
	paramsz = nitems(jparams);
	params = jparams;
	nparams = 0;
	path = NULL;
	while (argc > 0) {
		name = curarg = argv[0];
		if ((val = strchr(curarg, '=')) == NULL) {
			fprintf(stderr, "malformed setting, missing '=': %s\n", curarg);
			usage();
		}

		*val++ = '\0';
		/* Once we've hit command, halt; the rest goes to execvp().*/
		if (strcmp(name, "command") == 0) {
			if (*val == '\0') {
				fprintf(stderr, "command must not be empty\n");
				usage();
			}
			argv[0] = val;
			break;
		}

		if (strcmp(name, "path") == 0)
			path = val;

		if (nparams == paramsz) {
			struct jailparam *newparams;

			paramsz *= 2;
			newparams = calloc(paramsz, sizeof(*newparams));
			if (newparams == NULL) {
				fprintf(stderr, "out of memory\n");
				return (1);
			}

			memcpy(newparams, params, nparams * sizeof(*params));
			if (params != jparams)
				free(params);
			params = newparams;
		}

		if (jailparam_init(&params[nparams], name) != 0) {
			if (*jail_errmsg != '\0') {
				fprintf(stderr, "jail error: %s\n", jail_errmsg);
				return (1);
			}

			fprintf(stderr, "invalid jail parameter: %s\n", name);
			return (1);
		}

		if (jailparam_import(&params[nparams++], val) != 0) {
			fprintf(stderr, "jail error: %s\n", jail_errmsg);
			return (1);
		}
		argc--;
		argv++;
	}

	if (argc == 0) {
		fprintf(stderr, "missing command\n");
		usage();
	}

	return (quickjail(argv, params, nparams, path));
}
