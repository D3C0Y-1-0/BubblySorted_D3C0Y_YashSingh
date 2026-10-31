package bank;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger LOG = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        // Constants only: user input never reaches the logger.
        LOG.info("transaction service started");
    }
}
