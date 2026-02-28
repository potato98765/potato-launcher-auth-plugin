package com.mrpotato.potatoauth;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.YamlConfiguration;

public final class PotatoAuthVerifier {
    private final HttpClient httpClient;
    private final String baseUrl;
    private final URI verifyProofUri;
    private final Duration timeout;

    public PotatoAuthVerifier(String baseUrl, long timeoutSeconds) {
        this.baseUrl = normalizeBaseUrl(baseUrl);
        this.verifyProofUri = URI.create(this.baseUrl + "/api/game-auth/server/verify");
        this.timeout = Duration.ofSeconds(Math.max(3L, timeoutSeconds));
        this.httpClient = HttpClient.newBuilder().connectTimeout(this.timeout).build();
    }

    public VerifyResult verifyJoinedSession(String username, String serverId) {
        if (username == null || username.isBlank()) {
            return VerifyResult.failure("Missing username");
        }
        if (serverId == null || serverId.isBlank()) {
            return VerifyResult.failure("Missing challenge");
        }

        final String encodedUsername = URLEncoder.encode(username.trim(), StandardCharsets.UTF_8);
        final String encodedServerId = URLEncoder.encode(serverId.trim(), StandardCharsets.UTF_8);
        final URI uri = URI.create(
            baseUrl + "/api/yggdrasil/sessionserver/session/minecraft/hasJoined?username=" + encodedUsername + "&serverId=" + encodedServerId
        );

        final HttpRequest request = HttpRequest.newBuilder(uri)
            .timeout(timeout)
            .header("Accept", "application/json")
            .GET()
            .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException error) {
            return VerifyResult.failure("Network error: " + error.getMessage());
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return VerifyResult.failure("Verification interrupted");
        }

        if (response.statusCode() == 204) {
            return VerifyResult.failure("Session not joined on PotatoAuth");
        }
        if (response.statusCode() != 200) {
            final String parsed = parseErrorMessage(response.body());
            if (parsed != null && !parsed.isBlank()) {
                return VerifyResult.failure(parsed);
            }
            return VerifyResult.failure("Auth server returned HTTP " + response.statusCode());
        }

        try {
            final YamlConfiguration yaml = new YamlConfiguration();
            yaml.loadFromString(response.body());
            final String profileId = yaml.getString("id", "").trim();
            final String profileName = yaml.getString("name", "").trim();
            if (profileId.isEmpty() || profileName.isEmpty()) {
                return VerifyResult.failure("Profile data missing in session response");
            }
            TextureProperty textures = extractTexturesProperty(yaml);
            if (textures == null) {
                textures = fetchProfileTextures(profileId);
            }
            return VerifyResult.success(new Profile(profileId, profileName, textures));
        } catch (InvalidConfigurationException error) {
            return VerifyResult.failure("Invalid response from auth server");
        }
    }

    public VerifyResult verifyAccessToken(String token) {
        if (token == null || token.isBlank()) {
            return VerifyResult.failure("Empty token");
        }
        final URI uri = URI.create(baseUrl + "/api/launcher/profile");
        final HttpRequest request = HttpRequest.newBuilder(uri)
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer " + token.trim())
            .GET()
            .build();
        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException error) {
            return VerifyResult.failure("Network error: " + error.getMessage());
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return VerifyResult.failure("Verification interrupted");
        }
        if (response.statusCode() != 200) {
            final String parsed = parseErrorMessage(response.body());
            if (parsed != null && !parsed.isBlank()) {
                return VerifyResult.failure(parsed);
            }
            return VerifyResult.failure("Auth server returned HTTP " + response.statusCode());
        }
        try {
            final YamlConfiguration yaml = new YamlConfiguration();
            yaml.loadFromString(response.body());
            if (!yaml.getBoolean("ok", false)) {
                return VerifyResult.failure(yaml.getString("error", "Verification rejected"));
            }
            final String profileId = yaml.getString("profile.id", "").trim();
            final String profileName = yaml.getString("profile.name", "").trim();
            if (profileId.isEmpty() || profileName.isEmpty()) {
                return VerifyResult.failure("Profile data missing in auth response");
            }
            return VerifyResult.success(new Profile(profileId, profileName, null));
        } catch (InvalidConfigurationException error) {
            return VerifyResult.failure("Invalid response from auth server");
        }
    }

    public VerifyResult verifyJoinedSessionWithRetry(String username, String serverId, int attempts, long sleepMillis) {
        final int maxAttempts = Math.max(1, attempts);
        final long delayMs = Math.max(0L, sleepMillis);
        VerifyResult last = VerifyResult.failure("Session not joined on PotatoAuth");
        for (int i = 0; i < maxAttempts; i++) {
            last = verifyJoinedSession(username, serverId);
            if (last.success()) {
                return last;
            }
            if (i + 1 < maxAttempts && delayMs > 0L) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    return VerifyResult.failure("Verification interrupted");
                }
            }
        }
        return last;
    }

    public VerifyResult verifyClientProof(String proof, String nonce, String username, String playerIp) {
        if (proof == null || proof.isBlank()) {
            return VerifyResult.failure("Missing proof");
        }
        if (nonce == null || nonce.isBlank()) {
            return VerifyResult.failure("Missing nonce");
        }
        if (username == null || username.isBlank()) {
            return VerifyResult.failure("Missing username");
        }

        final String body =
            "{"
                + "\"proof\":\"" + jsonEscape(proof.trim()) + "\","
                + "\"nonce\":\"" + jsonEscape(nonce.trim()) + "\","
                + "\"username\":\"" + jsonEscape(username.trim()) + "\","
                + "\"playerIp\":\"" + jsonEscape(String.valueOf(playerIp)) + "\""
                + "}";

        final HttpRequest request = HttpRequest.newBuilder(verifyProofUri)
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException error) {
            return VerifyResult.failure("Network error: " + error.getMessage());
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return VerifyResult.failure("Verification interrupted");
        }

        if (response.statusCode() != 200) {
            final String parsed = parseErrorMessage(response.body());
            if (parsed != null && !parsed.isBlank()) {
                return VerifyResult.failure(parsed);
            }
            return VerifyResult.failure("Auth server returned HTTP " + response.statusCode());
        }

        try {
            final YamlConfiguration yaml = new YamlConfiguration();
            yaml.loadFromString(response.body());
            if (!yaml.getBoolean("ok", false)) {
                return VerifyResult.failure(yaml.getString("error", "Verification rejected"));
            }
            final String profileId = yaml.getString("profile.id", "").trim();
            final String profileName = yaml.getString("profile.name", "").trim();
            if (profileId.isEmpty() || profileName.isEmpty()) {
                return VerifyResult.failure("Profile data missing in auth response");
            }
            return VerifyResult.success(new Profile(profileId, profileName, null));
        } catch (InvalidConfigurationException error) {
            return VerifyResult.failure("Invalid response from auth server");
        }
    }

    public String baseUrl() {
        return baseUrl;
    }

    private TextureProperty fetchProfileTextures(String profileId) {
        if (profileId == null || profileId.isBlank()) {
            return null;
        }
        final URI uri = URI.create(
            baseUrl + "/api/yggdrasil/sessionserver/session/minecraft/profile/" + URLEncoder.encode(profileId.trim(), StandardCharsets.UTF_8)
        );
        final HttpRequest request = HttpRequest.newBuilder(uri)
            .timeout(timeout)
            .header("Accept", "application/json")
            .GET()
            .build();
        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException error) {
            if (error instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
        if (response.statusCode() != 200) {
            return null;
        }
        try {
            final YamlConfiguration yaml = new YamlConfiguration();
            yaml.loadFromString(response.body());
            return extractTexturesProperty(yaml);
        } catch (InvalidConfigurationException ignored) {
            return null;
        }
    }

    private static String parseErrorMessage(String bodyText) {
        try {
            final YamlConfiguration yaml = new YamlConfiguration();
            yaml.loadFromString(String.valueOf(bodyText));
            final String error = yaml.getString("error", "").trim();
            if (!error.isEmpty()) {
                return error;
            }
            return yaml.getString("errorMessage", "").trim();
        } catch (InvalidConfigurationException ignored) {
            return null;
        }
    }

    private static String normalizeBaseUrl(String baseUrl) {
        String value = String.valueOf(baseUrl).trim();
        if (value.isEmpty()) {
            value = "https://potato-launcher.duckdns.org:25585";
        }
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }

    private static String jsonEscape(String value) {
        final StringBuilder escaped = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            switch (c) {
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    escaped.append(c);
                    break;
            }
        }
        return escaped.toString();
    }

    private static TextureProperty extractTexturesProperty(YamlConfiguration yaml) {
        final List<Map<?, ?>> properties = yaml.getMapList("properties");
        for (Map<?, ?> property : properties) {
            final String name = mapString(property, "name");
            if (!"textures".equalsIgnoreCase(name)) {
                continue;
            }
            final String value = mapString(property, "value");
            if (value.isEmpty()) {
                continue;
            }
            final String signature = mapString(property, "signature");
            return new TextureProperty(value, signature.isEmpty() ? null : signature);
        }
        return null;
    }

    private static String mapString(Map<?, ?> map, String key) {
        final Object value = map.get(key);
        return value != null ? String.valueOf(value).trim() : "";
    }

    public record TextureProperty(String value, String signature) {}

    public record Profile(String id, String name, TextureProperty textures) {}

    public record VerifyResult(boolean success, String reason, Profile profile) {
        public static VerifyResult success(Profile profile) {
            return new VerifyResult(true, "", profile);
        }

        public static VerifyResult failure(String reason) {
            return new VerifyResult(false, reason, null);
        }
    }
}
