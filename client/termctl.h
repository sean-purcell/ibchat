#ifndef CLIENT_TERMCTL_H
#define CLIENT_TERMCTL_H

/* sets the terminal to be in non-ICANON|ECHO mode */
void set_ctl(int on);

void clr_scrn();
void mov_curs(int x, int y);
void home_curs();

int term_height();
int term_width();

#endif

