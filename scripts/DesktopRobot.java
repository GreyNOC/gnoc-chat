import java.awt.Dimension;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.Rectangle;
import java.awt.image.BufferedImage;
import java.io.File;
import javax.imageio.ImageIO;

/** Minimal local desktop capture helper for evidence QA. */
public final class DesktopRobot {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: DesktopRobot screenshot|click|key ...");
        }
        Robot robot = new Robot();
        robot.setAutoDelay(80);
        switch (args[0]) {
            case "screenshot" -> {
                if (args.length != 2) throw new IllegalArgumentException("screenshot OUTPUT.png");
                Dimension size = Toolkit.getDefaultToolkit().getScreenSize();
                BufferedImage image = robot.createScreenCapture(
                    new Rectangle(0, 0, size.width, size.height)
                );
                ImageIO.write(image, "png", new File(args[1]));
                System.out.println(size.width + "x" + size.height);
            }
            case "click" -> {
                if (args.length != 3) throw new IllegalArgumentException("click X Y");
                robot.mouseMove(Integer.parseInt(args[1]), Integer.parseInt(args[2]));
                robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
                robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
            }
            case "key" -> {
                if (args.length != 2) throw new IllegalArgumentException("key KEYCODE");
                int key = Integer.parseInt(args[1]);
                robot.keyPress(key);
                robot.keyRelease(key);
            }
            case "wheel" -> {
                if (args.length != 2) throw new IllegalArgumentException("wheel AMOUNT");
                robot.mouseWheel(Integer.parseInt(args[1]));
            }
            case "chord" -> {
                if (args.length < 3) throw new IllegalArgumentException("chord KEYCODE...");
                for (int i = 1; i < args.length; i++) robot.keyPress(Integer.parseInt(args[i]));
                for (int i = args.length - 1; i >= 1; i--) robot.keyRelease(Integer.parseInt(args[i]));
            }
            case "text" -> {
                if (args.length != 2) throw new IllegalArgumentException("text VALUE");
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                    new StringSelection(args[1]), null
                );
                robot.keyPress(KeyEvent.VK_CONTROL);
                robot.keyPress(KeyEvent.VK_V);
                robot.keyRelease(KeyEvent.VK_V);
                robot.keyRelease(KeyEvent.VK_CONTROL);
            }
            default -> throw new IllegalArgumentException("unknown action " + args[0]);
        }
    }
}
