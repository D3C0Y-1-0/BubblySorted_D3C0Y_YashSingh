package bank.transaction.fees;

import java.util.HashMap;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

/** Customer tiers and their monthly transfer limits, loaded from YAML. */
public final class TierTable {
    /** The YAML document: tier name to limit. */
    public static class Tiers {
        public Map<String, Integer> limits = new HashMap<>();
    }

    private final Tiers tiers;

    public TierTable(String yamlText) {
        Yaml yaml = new Yaml(new Constructor(Tiers.class));
        this.tiers = yaml.load(yamlText);
    }

    public static TierTable standard() {
        return new TierTable("limits: {standard: 2000, premium: 10000}\n");
    }

    public int limitFor(String tier) {
        return tiers.limits.getOrDefault(tier, 0);
    }
}
