package bank.transaction.fees;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

/** Transfer fees per customer tier, loaded from YAML. */
public final class FeeSchedule {
    private final FeeConfig config;

    public FeeSchedule(String yamlText) {
        this.config = new Yaml(new Constructor(FeeConfig.class)).load(yamlText);
    }

    /** A schedule where the second document overrides the first one. */
    public static FeeSchedule merged(String base, String overrides) {
        FeeConfig defaults = new Yaml(new Constructor(FeeConfig.class)).load(base);
        FeeConfig changes = new Yaml(new Constructor(FeeConfig.class)).load(overrides);
        FeeConfig result = new FeeConfig();
        result.base = changes.base != 0.0 ? changes.base : defaults.base;
        result.percent = changes.percent != 0.0 ? changes.percent : defaults.percent;
        result.waived = changes.waived.isEmpty() ? defaults.waived : changes.waived;
        return new FeeSchedule(result);
    }

    /** Every document of a multi-document file, one schedule each (for scheduled changes). */
    public static java.util.List<FeeSchedule> all(String yamlText) {
        java.util.List<FeeSchedule> schedules = new java.util.ArrayList<>();
        for (Object document : new Yaml(new Constructor(FeeConfig.class)).loadAll(yamlText)) {
            schedules.add(new FeeSchedule((FeeConfig) document));
        }
        return schedules;
    }

    private FeeSchedule(FeeConfig config) {
        this.config = config;
    }

    public double feeFor(String tier, double amount) {
        if (config.waived.contains(tier)) {
            return 0.0;
        }
        return Math.round((config.base + amount * config.percent / 100.0) * 100.0) / 100.0;
    }

    FeeConfig config() {
        return config;
    }
}
