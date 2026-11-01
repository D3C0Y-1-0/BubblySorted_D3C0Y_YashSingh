package bank.transaction.fees;

import java.util.ArrayList;
import java.util.List;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

/** Days when transfers are settled late, loaded from YAML. */
public final class HolidayCalendar {
    /** The YAML document: a list of ISO dates. */
    public static class Holidays {
        public List<String> dates = new ArrayList<>();
    }

    private final Holidays holidays;

    public HolidayCalendar(String yamlText) {
        Yaml yaml = new Yaml(new Constructor(Holidays.class, new org.yaml.snakeyaml.LoaderOptions()));
        this.holidays = yaml.load(yamlText);
    }

    public boolean isHoliday(String isoDate) {
        return holidays.dates.contains(isoDate);
    }

    public int count() {
        return holidays.dates.size();
    }
}
