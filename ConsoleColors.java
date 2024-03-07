
/**
 * This class provides methods to print text in color in the console.
 */
public class ConsoleColors {
    public enum Color {
        RESET("\u001B[0m"),
        BLACK("\u001B[30m"),
        RED("\u001B[31m"),
        GREEN("\u001B[32m"),
        YELLOW("\u001B[33m"),
        BLUE("\u001B[34m"),
        PURPLE("\u001B[35m"),
        CYAN("\u001B[36m"),
        WHITE("\u001B[37m");

        private final String code;

        Color(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }
    }

    public enum BackgroundColor {
        BLACK("\u001B[40m"),
        RED("\u001B[41m"),
        GREEN("\u001B[42m"),
        YELLOW("\u001B[43m"),
        BLUE("\u001B[44m"),
        PURPLE("\u001B[45m"),
        CYAN("\u001B[46m"),
        WHITE("\u001B[47m");

        private final String code;

        BackgroundColor(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }
    }

    public static void printInColor(String text, Color color, BackgroundColor backgroundColor) {
        String colorCode = (color != null) ? color.getCode() : "";
        String backgroundColorCode = (backgroundColor != null) ? backgroundColor.getCode() : "";
        System.out.print(colorCode + backgroundColorCode + text + Color.RESET.getCode());

    }

    public static void printlnInColor(String text, Color color, BackgroundColor backgroundColor) {
        printInColor(text, color, backgroundColor);
        System.out.println();

    }

    public static void printlnBlinkInColor(String text, Color color, BackgroundColor backgroundColor) {
        text = "\u001B[5m" + text + Color.RESET.getCode();
        printlnInColor(text, color, null);
    }


}