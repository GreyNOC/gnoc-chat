import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

public final class X11Robot {
  private static int keyCode(String name) throws Exception {
    return KeyEvent.class.getField("VK_" + name.toUpperCase()).getInt(null);
  }

  private static void key(Robot robot, int code) {
    robot.keyPress(code);
    robot.keyRelease(code);
  }

  private static void type(Robot robot, String value) {
    for (char character : value.toCharArray()) {
      boolean shift = Character.isUpperCase(character);
      int code = KeyEvent.getExtendedKeyCodeForChar(character);
      if (code == KeyEvent.VK_UNDEFINED) {
        throw new IllegalArgumentException("Cannot type character U+" + Integer.toHexString(character));
      }
      if (shift) robot.keyPress(KeyEvent.VK_SHIFT);
      key(robot, code);
      if (shift) robot.keyRelease(KeyEvent.VK_SHIFT);
    }
  }

  public static void main(String[] args) throws Exception {
    Robot robot = new Robot();
    robot.setAutoDelay(80);
    for (String action : args) {
      if (action.startsWith("click:")) {
        String[] point = action.substring(6).split(":", 2);
        robot.mouseMove(Integer.parseInt(point[0]), Integer.parseInt(point[1]));
        robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
        robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
      } else if (action.startsWith("doubleclick:")) {
        String[] point = action.substring(12).split(":", 2);
        robot.mouseMove(Integer.parseInt(point[0]), Integer.parseInt(point[1]));
        robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
        robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
        robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
        robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
      } else if (action.startsWith("sleep:")) {
        Thread.sleep(Long.parseLong(action.substring(6)));
      } else if (action.startsWith("type:")) {
        type(robot, action.substring(5));
      } else if (action.startsWith("paste:")) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
          new StringSelection(action.substring(6)),
          null
        );
        robot.keyPress(KeyEvent.VK_CONTROL);
        key(robot, KeyEvent.VK_V);
        robot.keyRelease(KeyEvent.VK_CONTROL);
      } else if (action.startsWith("key:")) {
        key(robot, keyCode(action.substring(4)));
      } else if (action.startsWith("hotkey:")) {
        String[] names = action.substring(7).split("\\+");
        int[] codes = new int[names.length];
        for (int i = 0; i < names.length; i++) {
          codes[i] = keyCode(names[i]);
          robot.keyPress(codes[i]);
        }
        for (int i = codes.length - 1; i >= 0; i--) robot.keyRelease(codes[i]);
      } else if (action.startsWith("wheel:")) {
        robot.mouseWheel(Integer.parseInt(action.substring(6)));
      } else {
        throw new IllegalArgumentException("Unknown action: " + action);
      }
    }
  }
}
