package bank.transaction.fees;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FeeScheduleTest {
    private static final String FEES = "base: 0.5\npercent: 1.0\nwaived: [staff]\n";

    @Test
    void feesFollowTheSchedule() {
        FeeSchedule schedule = new FeeSchedule(FEES);
        assertEquals(10.5, schedule.feeFor("standard", 1000.0), 0.001);
        assertEquals(0.0, schedule.feeFor("staff", 1000.0), 0.001);
    }

    @Test
    void theSecondDocumentOverridesTheFirst() {
        FeeSchedule schedule = FeeSchedule.merged(FEES, "percent: 2.0\n");
        assertEquals(20.5, schedule.feeFor("standard", 1000.0), 0.001);
    }

    @Test
    void holidaysAreRead() {
        HolidayCalendar calendar = new HolidayCalendar("dates: ['2026-12-25', '2026-01-01']\n");
        assertTrue(calendar.isHoliday("2026-12-25"));
        assertEquals(2, calendar.count());
    }

    @Test
    void everyDocumentOfAFileIsASchedule() {
        assertEquals(2, FeeSchedule.all("base: 1.0\n---\nbase: 2.0\n").size());
    }

    @Test
    void tierLimitsAreRead() {
        TierTable tiers = TierTable.standard();
        assertEquals(10000, tiers.limitFor("premium"));
        assertEquals(0, tiers.limitFor("unknown"));
    }

    @Test
    void aScheduleCanBeWrittenBack() {
        FeeConfig config = new FeeSchedule(FEES).config();
        String text = FeeReport.dump(config);
        assertTrue(text.contains("percent"));
    }

    /** A YAML file must never be able to create arbitrary classes (CVE-2022-1471). */
    @Test
    void yamlCannotCreateArbitraryObjects() {
        Gadget.created = false;
        try {
            new FeeSchedule("waived: [!!bank.transaction.fees.FeeScheduleTest$Gadget {}]\n");
        } catch (RuntimeException expected) {
            // refused, or the wrong type: what matters is that nothing was created
        }
        assertFalse(Gadget.created, "the YAML created an object of a class it named");
    }

    public static class Gadget {
        static boolean created;

        public Gadget() {
            created = true;
        }
    }
}
