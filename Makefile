
PROG=	quickjail
CFLAGS+=	-Wall -Wextra -Werror -pedantic
LDADD+=	-ljail
CSTD=	c11

LINKS=	${BINDIR}/quickjail ${BINDIR}/quickshell
MLINKS=	quickjail.1 quickshell.1

.include <bsd.prog.mk>
