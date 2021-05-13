#include <bits/stdint-uintn.h>
#include <signal.h>
#include <stdio.h>
#include <sys/time.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include "tick_timer.h"

timer_handler_func timer_handler_function_for_application;

void signal_handler(int signo)
{
  assert(signo == SIGALRM);

  time_t timer;
  char buffer[26];
  struct tm* tm_info;

  timer = time(NULL);
  tm_info = localtime(&timer);

  strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
  printf("Alarm Triggered at %s\n",buffer);

  if (timer_handler_function_for_application)
  {
    timer_handler_function_for_application();
  }
}

void tick_timer_init(uint32_t sec, timer_handler_func application_fun)
{

  struct itimerval timer;
  struct sigaction sa;
  sigset_t sigset;

  /* mask SIGALRM in all threads by default */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGALRM);

  /* we need a signal handler. The default is to call abort() and
  * setting SIG_IGN might cause the signal to not be delivered at all.
  **/
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  sigaction(SIGALRM, &sa, NULL);

  timer.it_interval.tv_sec = sec;
  timer.it_interval.tv_usec = 0;  // when timer expires, reset to 100ms
  timer.it_value = timer.it_interval;

  setitimer(ITIMER_REAL, &timer, 0);
  timer_handler_function_for_application = application_fun;
}
