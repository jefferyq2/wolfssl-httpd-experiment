all:
	clang -std=c2x -D_POSIX_C_SOURCE=200809L -Wextra -Werror -pedantic-errors -lwolfssl tls.c socket.c main.c -o httpd

clean:
	rm -f httpd
