#ifndef DNSSERVER__TICK_TIMER_H
#define DNSSERVER__TICK_TIMER_H

typedef void (*timer_handler_func)(void);

void tick_timer_init(uint32_t sec, timer_handler_func application_fun);

#endif //DNSSERVER__TICK_TIMER_H
