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

#define	DEFAULT_PATH "/"

static void
usage(void)
{

	fprintf(stderr, "usage: quickjail [-n name] [-p path] command ...\n");
	exit(1);
}

static int
quickjail(int argc, char *argv[], const char *name, const char *path)
{
	struct jailparam params[2];
	struct kevent kev;
	pid_t pid, wpid;
	int fdp, kq, nparams, rv, status;

	pid = pdfork(&fdp, 0);
	if (pid == -1)
		err(1, "pdfork");

	if (pid == 0) {
		/* Child */
		nparams = 1;
		if (strcmp(path, ".") != 0 && chdir(path) == -1)
			err(1, "chdir");
		jailparam_init(&params[0], "path");
		jailparam_import(&params[0], ".");
		if (name != NULL) {
			++nparams;
			jailparam_init(&params[1], "name");
			jailparam_import(&params[1], name);
		}

		rv = jailparam_set(params, nparams, JAIL_CREATE | JAIL_ATTACH);
		if (rv < 0)
			err(1, "jailparam_set");

		execvp(argv[0], __DECONST(char *const*, argv));
		err(1, "execvp");
	} else {
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

		if (caph_limit_stdio() == -1) {
			pdkill(fdp, SIGKILL);
			err(1, "caph_limit_stdio");
		}

		/* Parent, immediately enter capability mode. */
		if (caph_enter() == -1) {
			pdkill(fdp, SIGKILL);
			err(1, "caph_enter");
		}

		EV_SET(&kev, fdp, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
		while ((rv = kevent(kq, &kev, 1, &kev, 1, NULL)) == -1 &&
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
	int ch;
	const char *name = NULL;
	const char *path = DEFAULT_PATH;

	if (argc < 2) {
		usage();
	}

	while ((ch = getopt(argc, argv, "n:p:")) != -1) {
		switch (ch) {
		case 'n':
			name = optarg;
			break;
		case 'p':
			path = optarg;
			if (*path == '\0') {
				fprintf(stderr, "path must not be empty.\n");
				usage();
			}
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		fprintf(stderr, "missing command\n");
		usage();
	}

	return (quickjail(argc, argv, name, path));
}
