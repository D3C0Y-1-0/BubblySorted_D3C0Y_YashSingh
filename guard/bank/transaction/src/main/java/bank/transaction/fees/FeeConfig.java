package bank.transaction.fees;

import java.util.ArrayList;
import java.util.List;

/** Fee settings, read from YAML. */
public class FeeConfig {
    public double base = 0.0;
    public double percent = 0.0;
    public List<String> waived = new ArrayList<>();
}
