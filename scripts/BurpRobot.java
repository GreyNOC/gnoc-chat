import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

/** Minimal X11 desktop helper for capturing genuine Burp UI panels. */
public final class BurpRobot {
    private static final int PAUSE_MS = 250;

    private static void click(Robot robot, int x, int y) throws Exception {
        robot.mouseMove(x, y);
        robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
        robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
        Thread.sleep(PAUSE_MS);
    }

    private static void paste(Robot robot, int x, int y, String value) throws Exception {
        Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new StringSelection(value), null);
        click(robot, x, y);
        robot.keyPress(KeyEvent.VK_CONTROL);
        robot.keyPress(KeyEvent.VK_A);
        robot.keyRelease(KeyEvent.VK_A);
        robot.keyRelease(KeyEvent.VK_CONTROL);
        robot.keyPress(KeyEvent.VK_CONTROL);
        robot.keyPress(KeyEvent.VK_V);
        robot.keyRelease(KeyEvent.VK_V);
        robot.keyRelease(KeyEvent.VK_CONTROL);
        Thread.sleep(PAUSE_MS);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || (!("setclip".equals(args[0]) || "pasteactive".equals(args[0])) && args.length < 3)) {
            throw new IllegalArgumentException("usage: click x y | paste x y text | pasteactive text | setclip text | copy x y | drag x1 y1 x2 y2 | key keycode | hotkey modifier keycode");
        }
        Robot robot = new Robot();
        switch (args[0]) {
            case "click" -> click(robot, Integer.parseInt(args[1]), Integer.parseInt(args[2]));
            case "paste" -> {
                if (args.length != 4) throw new IllegalArgumentException("paste x y text");
                paste(robot, Integer.parseInt(args[1]), Integer.parseInt(args[2]), args[3]);
            }
            case "copy" -> {
                click(robot, Integer.parseInt(args[1]), Integer.parseInt(args[2]));
                robot.keyPress(KeyEvent.VK_CONTROL);
                robot.keyPress(KeyEvent.VK_A);
                robot.keyRelease(KeyEvent.VK_A);
                robot.keyRelease(KeyEvent.VK_CONTROL);
                robot.keyPress(KeyEvent.VK_CONTROL);
                robot.keyPress(KeyEvent.VK_C);
                robot.keyRelease(KeyEvent.VK_C);
                robot.keyRelease(KeyEvent.VK_CONTROL);
                Thread.sleep(PAUSE_MS);
                Object value = Toolkit.getDefaultToolkit().getSystemClipboard()
                    .getData(DataFlavor.stringFlavor);
                System.out.print(String.valueOf(value));
            }
            case "drag" -> {
                if (args.length != 5) throw new IllegalArgumentException("drag x1 y1 x2 y2");
                int x1 = Integer.parseInt(args[1]);
                int y1 = Integer.parseInt(args[2]);
                int x2 = Integer.parseInt(args[3]);
                int y2 = Integer.parseInt(args[4]);
                robot.mouseMove(x1, y1);
                robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
                Thread.sleep(100);
                robot.mouseMove(x2, y2);
                robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
                Thread.sleep(PAUSE_MS);
            }
            case "setclip" -> {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(args[1]), null);
                Thread.sleep(PAUSE_MS);
            }
            case "pasteactive" -> {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(args[1]), null);
                robot.keyPress(KeyEvent.VK_CONTROL);
                robot.keyPress(KeyEvent.VK_V);
                robot.keyRelease(KeyEvent.VK_V);
                robot.keyRelease(KeyEvent.VK_CONTROL);
                Thread.sleep(PAUSE_MS);
            }
            case "key" -> {
                int code = Integer.parseInt(args[1]);
                robot.keyPress(code);
                robot.keyRelease(code);
                Thread.sleep(PAUSE_MS);
            }
            case "hotkey" -> {
                int modifier = Integer.parseInt(args[1]);
                int code = Integer.parseInt(args[2]);
                robot.keyPress(modifier);
                robot.keyPress(code);
                robot.keyRelease(code);
                robot.keyRelease(modifier);
                Thread.sleep(PAUSE_MS);
            }
            default -> throw new IllegalArgumentException("unknown action: " + args[0]);
        }
    }
}
