#ifndef CONFIG_H
#define CONFIG_H

// *
// * CONFIG SETTINGS 
// *
#define MAX_THREADS 200
#define MAX_RESULTS 200000
#define HEX_LINE 32
#define READBUF 1024

// *
// * CONFIG COLOR
// *
static const char *COLORS[] = {"\x1b[38;5;82m","\x1b[38;5;214m","\x1b[38;5;75m","\x1b[38;5;220m","\x1b[38;5;201m","\x1b[38;5;159m","\x1b[38;5;208m"};

#define ANSI_RESET "\x1b[0m"
#define COLORS_COUNT (sizeof(COLORS)/sizeof(COLORS[0]))
#define COLORS_R "\1xb[31m"
#define COLORS_G "\1xb[32m"
#define COLORS_B "\1xb[34m"

#endif
