#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: FocusX11 WINDOW_ID\n");
        return 2;
    }
    Display *display = XOpenDisplay(NULL);
    if (!display) return 3;
    Window target = (Window)strtoul(argv[1], NULL, 0);
    Window root = DefaultRootWindow(display);
    Atom active = XInternAtom(display, "_NET_ACTIVE_WINDOW", False);
    XEvent event = {0};
    event.xclient.type = ClientMessage;
    event.xclient.window = target;
    event.xclient.message_type = active;
    event.xclient.format = 32;
    event.xclient.data.l[0] = 1;
    event.xclient.data.l[1] = CurrentTime;
    XSendEvent(display, root, False,
        SubstructureRedirectMask | SubstructureNotifyMask, &event);
    XMapRaised(display, target);
    XSetInputFocus(display, target, RevertToParent, CurrentTime);
    XFlush(display);
    XCloseDisplay(display);
    return 0;
}
