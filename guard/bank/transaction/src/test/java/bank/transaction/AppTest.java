package bank.transaction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AppTest {
    private HttpServer server;
    private Path log;
    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void start() throws Exception {
        log = Files.createTempDirectory("tx").resolve("access.log");
        server = new App(log).start(0);
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private HttpResponse<String> send(String method, String path, String body) throws Exception {
        URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
        HttpRequest.BodyPublisher pub = body == null
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body);
        HttpRequest request = HttpRequest.newBuilder(uri).method(method, pub)
                .header("Content-Type", "application/json").header("X-Forwarded-For", "127.0.0.9").build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void healthIsOk() throws Exception {
        HttpResponse<String> r = send("GET", "/health", null);
        assertEquals(200, r.statusCode());
        assertEquals("{\"status\":\"ok\"}", r.body());
    }

    @Test
    void loginAcceptsOnlyTheDemoUser() throws Exception {
        assertEquals(401, send("POST", "/login", "{\"username\":\"demo\",\"password\":\"nope\"}").statusCode());
        HttpResponse<String> ok = send("POST", "/login", "{\"username\":\"demo\",\"password\":\"demo-pass\"}");
        assertEquals(200, ok.statusCode());
        assertTrue(ok.body().contains("\"ok\":true"));
    }

    @Test
    void transferMovesFakeMoneyAndIsLogged() throws Exception {
        assertEquals(200, send("POST", "/transfer", "{\"to\":\"Alice\",\"amount\":10}").statusCode());
        assertEquals(400, send("POST", "/transfer", "{\"to\":\"Alice\",\"amount\":999999}").statusCode());
        assertTrue(send("GET", "/balance", null).body().contains("1224.56"));
        assertTrue(Files.readString(log).contains("127.0.0.9 - \"POST /transfer HTTP/1.1\" 200"));
    }
}
