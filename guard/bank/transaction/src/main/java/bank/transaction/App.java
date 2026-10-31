package bank.transaction;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** The demo bank's transaction service. Fake users and money only. */
public final class App {
    private static final Logger LOG = LogManager.getLogger(App.class);
    private static final Pattern FIELD =
            Pattern.compile("\"(\\w+)\"\\s*:\\s*(\"((?:[^\"\\\\]|\\\\.)*)\"|-?[0-9.]+)");

    static final String DEMO_USER = "demo";
    static final String DEMO_PASSWORD = "demo-pass";
    static final String ACCOUNT = "DE00 0000 0000 0042";

    private final Path accessLog;
    private double balance = 1234.56;
    private int nextTransfer = 1001;

    App(Path accessLog) {
        this.accessLog = accessLog;
    }

    public static void main(String[] args) throws IOException {
        System.setProperty("log4j2.formatMsgNoLookups", "true");
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        Path log = Path.of(System.getenv().getOrDefault("ACCESS_LOG", "logs/access.log"));
        HttpServer server = new App(log).start(port);
        LOG.info("transaction service started"); // a constant: no user input reaches log4j
        System.out.println("transaction listening on " + server.getAddress().getPort());
    }

    HttpServer start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", this::handle);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        return server;
    }

    private void handle(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        byte[] body = ex.getRequestBody().readAllBytes();
        int status;
        String json;
        synchronized (this) {
            String route = method + " " + path;
            switch (route) {
                case "GET /health" -> { status = 200; json = "{\"status\":\"ok\"}"; }
                case "GET /" -> {
                    status = 200;
                    json = "{\"service\":\"transaction\",\"bank\":\"Hedwig Demo Bank\"}";
                }
                case "POST /login" -> {
                    Map<String, String> f = fields(body, ex.getRequestHeaders().getFirst("Content-Type"));
                    if (DEMO_USER.equals(f.get("username")) && DEMO_PASSWORD.equals(f.get("password"))) {
                        status = 200;
                        String session = UUID.randomUUID().toString();
                        ex.getResponseHeaders().add("Set-Cookie", "bank_session=" + session + "; Path=/; HttpOnly");
                        json = "{\"ok\":true,\"user\":\"demo\",\"session\":\"" + session + "\"}";
                    } else {
                        status = 401;
                        json = "{\"ok\":false,\"error\":\"invalid credentials\"}";
                    }
                }
                case "GET /balance" -> {
                    status = 200;
                    json = String.format(java.util.Locale.ROOT,
                            "{\"account\":\"%s\",\"balance\":%.2f,\"currency\":\"EUR\"}", ACCOUNT, balance);
                }
                case "GET /transactions" -> {
                    status = 200;
                    json = "{\"account\":\"" + ACCOUNT + "\",\"transactions\":["
                            + "{\"id\":998,\"date\":\"2026-10-28\",\"to\":\"Grocer GmbH\",\"amount\":-42.10},"
                            + "{\"id\":999,\"date\":\"2026-10-30\",\"from\":\"Payroll\",\"amount\":2100.00},"
                            + "{\"id\":1000,\"date\":\"2026-10-31\",\"to\":\"City Power\",\"amount\":-63.25}]}";
                }
                case "POST /transfer" -> {
                    Map<String, String> f = fields(body, ex.getRequestHeaders().getFirst("Content-Type"));
                    double amount = parse(f.get("amount"));
                    String to = f.getOrDefault("to", "");
                    if (amount <= 0 || amount > balance || to.isBlank()) {
                        status = 400;
                        json = "{\"ok\":false,\"error\":\"invalid transfer\"}";
                    } else {
                        balance -= amount;
                        status = 200;
                        json = "{\"ok\":true,\"id\":" + nextTransfer++ + "}";
                    }
                }
                default -> { status = 404; json = "{\"error\":\"not found\"}"; }
            }
        }
        writeAccessLog(ex, method, status);
        byte[] out = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, out.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(out);
        }
    }

    /** One line per request in the format Hedwig's evidence reader reads. */
    private void writeAccessLog(HttpExchange ex, String method, int status) {
        String ip = ex.getRequestHeaders().getFirst("X-Forwarded-For");
        if (ip == null) ip = ex.getRemoteAddress().getAddress().getHostAddress();
        String line = Instant.now().truncatedTo(ChronoUnit.SECONDS) + " " + ip.split(",")[0].trim()
                + " - \"" + method + " " + ex.getRequestURI() + " HTTP/1.1\" " + status + "\n";
        try {
            if (accessLog.getParent() != null) Files.createDirectories(accessLog.getParent());
            Files.writeString(accessLog, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // a full disk must not break the bank
        }
    }

    static Map<String, String> fields(byte[] body, String contentType) {
        Map<String, String> out = new HashMap<>();
        String text = new String(body, StandardCharsets.UTF_8);
        if (contentType != null && contentType.contains("x-www-form-urlencoded")) {
            for (String pair : text.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2) {
                    out.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                            URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                }
            }
            return out;
        }
        Matcher m = FIELD.matcher(text);
        while (m.find()) out.put(m.group(1), m.group(3) != null ? m.group(3) : m.group(2));
        return out;
    }

    private static double parse(String value) {
        try {
            return value == null ? 0 : Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
