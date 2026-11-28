for (const window of workspace.windowList()) {
    if (String(window.caption).includes("Open File")) {
        workspace.activeWindow = window;
        window.keepAbove = true;
    }
}
