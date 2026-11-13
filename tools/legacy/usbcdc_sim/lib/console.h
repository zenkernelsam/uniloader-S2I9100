#ifndef SIM_CONSOLE_H_
#define SIM_CONSOLE_H_
struct console {
	void (*write)(int level, const char *prefix, const char *msg);
};
void console_register(const struct console *con);
#endif
