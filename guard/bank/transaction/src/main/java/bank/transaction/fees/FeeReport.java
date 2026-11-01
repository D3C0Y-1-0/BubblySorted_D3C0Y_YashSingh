package bank.transaction.fees;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.nodes.Tag;

/** Writes a fee schedule back out as YAML. */
public final class FeeReport {
    private FeeReport() {}

    public static String dump(FeeConfig config) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Yaml yaml = new Yaml(new Representer(options), options);
        return yaml.dumpAs(config, Tag.MAP, DumperOptions.FlowStyle.BLOCK);
    }
}
