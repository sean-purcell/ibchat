#include <stdio.h>
#include <unistd.h>
#include <termios.h>

#include <sys/ioctl.h>

#include "termctl.h"

void set_ctl(int on) {
	struct termios term;
	tcgetattr(STDIN_FILENO, &term);
	if(on)
		term.c_lflag &= ~(ICANON | ECHO);
	else
		term.c_lflag |= (ICANON | ECHO);

	tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void clr_scrn() {
	printf("\033[2J");
}

void mov_curs(int x, int y) {
	printf("\033[%d;%dH", y, x);
}

void home_curs() {
	printf("\033[1G");
}

int term_height() {
	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	return w.ws_row;
}

int term_width() {
	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	return w.ws_col;
}

