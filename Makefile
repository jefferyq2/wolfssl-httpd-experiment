all:
	clang -std=c2x -D_POSIX_C_SOURCE=200809L -Wextra -Werror -pedantic-errors -lwolfssl http.c -o httpd

clean:
	rm -f httpd
