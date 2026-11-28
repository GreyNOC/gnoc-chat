#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s WINDOW_ID\n", argv[0]);
    return 2;
  }

  Display *display = XOpenDisplay(NULL);
  if (display == NULL) {
    fprintf(stderr, "cannot open display\n");
    return 1;
  }

  Window target = (Window)strtoul(argv[1], NULL, 0);
  Atom active_window = XInternAtom(display, "_NET_ACTIVE_WINDOW", False);
  XEvent event = {0};
  event.xclient.type = ClientMessage;
  event.xclient.window = target;
  event.xclient.message_type = active_window;
  event.xclient.format = 32;
  event.xclient.data.l[0] = 2;
  event.xclient.data.l[1] = CurrentTime;

  XMapRaised(display, target);
  XSendEvent(display, DefaultRootWindow(display), False,
             SubstructureRedirectMask | SubstructureNotifyMask, &event);
  XFlush(display);
  XCloseDisplay(display);
  return 0;
}
