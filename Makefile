
PROG=	quickjail
CFLAGS+=	-Wall -Wextra -Werror -pedantic
LDADD+=	-ljail

.include <bsd.prog.mk>
