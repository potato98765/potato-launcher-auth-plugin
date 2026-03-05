package com.mrpotato.potatoauth;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import com.destroystokyo.paper.profile.PlayerProfile;
import com.destroystokyo.paper.profile.ProfileProperty;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.PluginCommand;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.plugin.messaging.PluginMessageListener;
import org.bukkit.scheduler.BukkitTask;

public final class PotatoAuthPlugin extends JavaPlugin implements PluginMessageListener {
    private static final int PROTOCOL_VERSION = 1;
    private static final String PACKET_CHALLENGE = "POTATOAUTH_CHALLENGE";
    private static final String PACKET_RESPONSE = "POTATOAUTH_RESPONSE";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Set<UUID> pendingPlayers = ConcurrentHashMap.newKeySet();
    private final Map<UUID, BukkitTask> pendingKickTasks = new ConcurrentHashMap<>();
    private final Map<UUID, BukkitTask> pendingChallengeRepeatTasks = new ConcurrentHashMap<>();
    private final Map<UUID, ChallengeState> pendingChallenges = new ConcurrentHashMap<>();
    private final Map<String, SessionGrant> sessionGrants = new ConcurrentHashMap<>();
    private final Map<String, String> linkedProfiles = new ConcurrentHashMap<>();

    private File linkedAccountsFile;
    private PotatoAuthVerifier verifier;

    private String pluginChannel;
    private String registeredChannel;
    private long challengeSendDelayTicks;
    private long challengeRepeatIntervalTicks;
    private int challengeRepeatCount;
    private long sessionMillis;
    private long verifyTimeoutTicks;
    private int hasJoinedAttempts;
    private long hasJoinedRetryDelayMillis;
    private boolean sendLegacyBinaryChallenge;
    private boolean allowLegacyProofFallback;
    private boolean debugLogging;
    private boolean requireSameIpForSessionReuse;
    private boolean enforceLinkedProfile;

    @Override
    public void onEnable() {
        saveDefaultConfig();

        linkedAccountsFile = new File(getDataFolder(), "linked-accounts.yml");
        loadLinkedProfiles();

        reloadRuntimeConfig();
        getServer().getPluginManager().registerEvents(new PendingAuthListener(this), this);

        final PluginCommand potatoCommand = getCommand("potato");
        if (potatoCommand == null) {
            getLogger().severe("Command /potato was not registered from plugin.yml.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        final PotatoAuthCommand executor = new PotatoAuthCommand(this);
        potatoCommand.setExecutor(executor);
        potatoCommand.setTabCompleter(executor);

        getLogger().info("PotatoAuth enabled. Channel=" + pluginChannel + ", debugLogging=" + debugLogging);
    }

    @Override
    public void onDisable() {
        for (BukkitTask task : pendingKickTasks.values()) {
            task.cancel();
        }
        pendingKickTasks.clear();
        for (BukkitTask task : pendingChallengeRepeatTasks.values()) {
            task.cancel();
        }
        pendingChallengeRepeatTasks.clear();
        pendingPlayers.clear();
        pendingChallenges.clear();
        if (registeredChannel != null && !registeredChannel.isBlank()) {
            getServer().getMessenger().unregisterIncomingPluginChannel(this, registeredChannel, this);
            getServer().getMessenger().unregisterOutgoingPluginChannel(this, registeredChannel);
            registeredChannel = null;
        }
        saveLinkedProfiles();
    }

    public void reloadRuntimeConfig() {
        reloadConfig();

        final String baseUrl = getConfig().getString("potatoAuthBaseUrl", "https://potato-launcher.heliohost.us");
        final long requestTimeoutSeconds = Math.max(3L, getConfig().getLong("requestTimeoutSeconds", 8L));
        this.verifier = new PotatoAuthVerifier(baseUrl, requestTimeoutSeconds);
        this.pluginChannel = String.valueOf(getConfig().getString("pluginChannel", "potatoauth:auth")).trim();
        if (pluginChannel.isEmpty()) {
            pluginChannel = "potatoauth:auth";
        }

        final long sessionMinutes = Math.max(1L, getConfig().getLong("sessionMinutes", 120L));
        this.sessionMillis = sessionMinutes * 60_000L;
        final long timeoutSeconds = Math.max(10L, getConfig().getLong("verifyTimeoutSeconds", 90L));
        this.verifyTimeoutTicks = timeoutSeconds * 20L;
        this.challengeSendDelayTicks = Math.max(1L, getConfig().getLong("challengeSendDelayTicks", 20L));
        this.challengeRepeatIntervalTicks = Math.max(10L, getConfig().getLong("challengeRepeatIntervalTicks", 30L));
        this.challengeRepeatCount = Math.max(1, getConfig().getInt("challengeRepeatCount", 6));
        this.hasJoinedAttempts = Math.max(1, getConfig().getInt("hasJoinedAttempts", 6));
        this.hasJoinedRetryDelayMillis = Math.max(0L, getConfig().getLong("hasJoinedRetryDelayMillis", 250L));
        this.sendLegacyBinaryChallenge = getConfig().getBoolean("sendLegacyBinaryChallenge", true);
        this.allowLegacyProofFallback = getConfig().getBoolean("allowLegacyProofFallback", true);
        this.debugLogging = getConfig().getBoolean("debugLogging", false);
        this.requireSameIpForSessionReuse = getConfig().getBoolean("requireSameIpForSessionReuse", true);
        this.enforceLinkedProfile = getConfig().getBoolean("enforceLinkedProfile", true);

        registerMessagingChannelIfNeeded();
    }

    private void registerMessagingChannelIfNeeded() {
        if (registeredChannel != null && !registeredChannel.equals(pluginChannel)) {
            getServer().getMessenger().unregisterIncomingPluginChannel(this, registeredChannel, this);
            getServer().getMessenger().unregisterOutgoingPluginChannel(this, registeredChannel);
            registeredChannel = null;
        }
        if (registeredChannel == null) {
            getServer().getMessenger().registerIncomingPluginChannel(this, pluginChannel, this);
            getServer().getMessenger().registerOutgoingPluginChannel(this, pluginChannel);
            registeredChannel = pluginChannel;
        }
    }

    private void loadLinkedProfiles() {
        linkedProfiles.clear();
        if (!linkedAccountsFile.exists()) {
            saveLinkedProfiles();
            return;
        }
        final YamlConfiguration yaml = YamlConfiguration.loadConfiguration(linkedAccountsFile);
        final ConfigurationSection section = yaml.getConfigurationSection("linked");
        if (section == null) {
            return;
        }
        for (String key : section.getKeys(false)) {
            final String normalized = normalizeName(key);
            final String profileId = section.getString(key, "").trim();
            if (!normalized.isEmpty() && !profileId.isEmpty()) {
                linkedProfiles.put(normalized, profileId);
            }
        }
    }

    private void saveLinkedProfiles() {
        if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
            getLogger().warning("Failed to create plugin data folder.");
            return;
        }
        final YamlConfiguration yaml = new YamlConfiguration();
        final ConfigurationSection section = yaml.createSection("linked");
        for (Map.Entry<String, String> entry : linkedProfiles.entrySet()) {
            section.set(entry.getKey(), entry.getValue());
        }
        try {
            yaml.save(linkedAccountsFile);
        } catch (IOException error) {
            getLogger().warning("Failed to save linked account file: " + error.getMessage());
        }
    }

    public void onPlayerJoin(Player player) {
        final InetAddress address = player.getAddress() != null ? player.getAddress().getAddress() : null;
        final SessionGrant grant = getActiveSessionGrant(player.getName(), address);
        if (grant != null) {
            applySessionProfile(player, grant);
            return;
        }
        setPending(player);
        scheduleChallengeSend(player);
    }

    public void onPlayerQuit(UUID uuid) {
        clearPending(uuid);
    }

    public boolean isPending(Player player) {
        return pendingPlayers.contains(player.getUniqueId());
    }

    public boolean isAllowedPendingCommand(String commandLine) {
        final String normalized = commandLine.trim().toLowerCase(Locale.ROOT);
        return normalized.equals("/potato")
            || normalized.startsWith("/potato ")
            || normalized.equals("/potatoauth")
            || normalized.startsWith("/potatoauth ");
    }

    private void setPending(Player player) {
        final UUID uuid = player.getUniqueId();
        if (!pendingPlayers.add(uuid)) {
            return;
        }
        pendingChallenges.put(uuid, new ChallengeState(newNonce(), System.currentTimeMillis() + (verifyTimeoutTicks * 50L)));
        player.sendMessage(colorize(getConfig().getString("messages.pending", "&eAuthenticating with PotatoAuth. Please wait...")));

        final BukkitTask timeout = getServer().getScheduler().runTaskLater(this, () -> {
            pendingKickTasks.remove(uuid);
            final BukkitTask repeatTask = pendingChallengeRepeatTasks.remove(uuid);
            if (repeatTask != null) {
                repeatTask.cancel();
            }
            if (!pendingPlayers.remove(uuid)) {
                return;
            }
            pendingChallenges.remove(uuid);
            if (debugLogging) {
                getLogger().info("PotatoAuth timeout for " + player.getName() + " (no successful auth response in time).");
            }
            if (player.isOnline()) {
                player.kickPlayer(colorize(getConfig().getString("messages.timeoutKick", "&cPotato authentication timed out.")));
            }
        }, verifyTimeoutTicks);
        pendingKickTasks.put(uuid, timeout);
    }

    private void scheduleChallengeSend(Player player) {
        final UUID uuid = player.getUniqueId();
        final int[] remaining = {challengeRepeatCount};
        final BukkitTask repeatTask = getServer().getScheduler().runTaskTimer(this, () -> {
            if (!player.isOnline() || !pendingPlayers.contains(uuid)) {
                final BukkitTask task = pendingChallengeRepeatTasks.remove(uuid);
                if (task != null) {
                    task.cancel();
                }
                return;
            }
            final ChallengeState state = pendingChallenges.get(uuid);
            if (state == null) {
                final BukkitTask task = pendingChallengeRepeatTasks.remove(uuid);
                if (task != null) {
                    task.cancel();
                }
                return;
            }
            sendChallenge(player, state);
            remaining[0]--;
            if (remaining[0] <= 0) {
                final BukkitTask task = pendingChallengeRepeatTasks.remove(uuid);
                if (task != null) {
                    task.cancel();
                }
            }
        }, challengeSendDelayTicks, challengeRepeatIntervalTicks);
        pendingChallengeRepeatTasks.put(uuid, repeatTask);
    }

    private void sendChallenge(Player player, ChallengeState state) {
        try {
            final byte[] jsonPayload = buildChallengeJsonPayload(state.nonce(), state.expiresAtEpochMillis());
            player.sendPluginMessage(this, pluginChannel, jsonPayload);
            if (sendLegacyBinaryChallenge) {
                final byte[] legacyPayload = buildChallengeBinaryPayload(state.nonce(), state.expiresAtEpochMillis());
                player.sendPluginMessage(this, pluginChannel, legacyPayload);
            }
        } catch (IOException error) {
            getLogger().warning("Failed to send PotatoAuth challenge to " + player.getName() + ": " + error.getMessage());
            kickVerificationFailed(player, "Internal challenge error");
        }
    }

    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        if (!channel.equals(registeredChannel)) {
            return;
        }
        if (!isPending(player)) {
            return;
        }

        final ChallengeState challenge = pendingChallenges.get(player.getUniqueId());
        if (challenge == null) {
            return;
        }

        final ParsedResponse response = parseResponse(message);
        if (response == null) {
            kickVerificationFailed(player, "Malformed client auth packet");
            return;
        }
        if (!response.nonce().equals(challenge.nonce())) {
            kickVerificationFailed(player, "Invalid challenge nonce");
            return;
        }

        player.sendMessage(colorize(getConfig().getString("messages.checking", "&7Checking PotatoAuth session...")));
        final String playerIp =
            player.getAddress() != null && player.getAddress().getAddress() != null
                ? player.getAddress().getAddress().getHostAddress()
                : "";
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            final PotatoAuthVerifier.VerifyResult result =
                verifyResponse(player, response, playerIp);
            getServer().getScheduler().runTask(this, () -> applyVerifyResult(player, result));
        });
    }

    private PotatoAuthVerifier.VerifyResult verifyResponse(Player player, ParsedResponse response, String playerIp) {
        PotatoAuthVerifier.VerifyResult result = verifier.verifyJoinedSessionWithRetry(
            player.getName(),
            response.nonce(),
            hasJoinedAttempts,
            hasJoinedRetryDelayMillis
        );
        if (!result.success() && allowLegacyProofFallback && response.proof() != null && !response.proof().isBlank()) {
            if (debugLogging) {
                getLogger().info("PotatoAuth hasJoined failed for " + player.getName() + ", trying legacy proof fallback.");
            }
            result = verifier.verifyClientProof(response.proof(), response.nonce(), player.getName(), playerIp);
        }
        return result;
    }

    private static ParsedResponse parseBinaryResponse(byte[] payload) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {
            final String packetType = in.readUTF();
            final int version = in.readInt();
            if (!PACKET_RESPONSE.equals(packetType)) {
                throw new IOException("Unexpected packet type");
            }
            if (version != PROTOCOL_VERSION) {
                throw new IOException("Unsupported protocol version");
            }
            final String nonce = in.readUTF().trim();
            String proof = "";
            if (in.available() > 0) {
                proof = in.readUTF().trim();
            }
            return new ParsedResponse(nonce, proof);
        }
    }

    private static ParsedResponse parseJsonResponse(byte[] payload) {
        final String text = new String(payload, StandardCharsets.UTF_8).trim();
        if (text.isEmpty() || text.charAt(0) != '{') {
            return null;
        }
        final YamlConfiguration yaml = new YamlConfiguration();
        try {
            yaml.loadFromString(text);
        } catch (InvalidConfigurationException ignored) {
            return null;
        }
        final String packetType = String.valueOf(yaml.getString("packetType", PACKET_RESPONSE)).trim();
        final int version = yaml.getInt("version", PROTOCOL_VERSION);
        if (!PACKET_RESPONSE.equals(packetType) || version != PROTOCOL_VERSION) {
            return null;
        }
        final String nonce = String.valueOf(yaml.getString("nonce", "")).trim();
        final String proof = String.valueOf(yaml.getString("proof", yaml.getString("key", ""))).trim();
        if (nonce.isEmpty()) {
            return null;
        }
        return new ParsedResponse(nonce, proof);
    }

    private static ParsedResponse parsePipeResponse(byte[] payload) {
        final String text = new String(payload, StandardCharsets.UTF_8).trim();
        final int separator = text.indexOf('|');
        if (separator > 0) {
            final String nonce = text.substring(0, separator).trim();
            final String proof = text.substring(separator + 1).trim();
            if (nonce.isEmpty()) {
                return null;
            }
            return new ParsedResponse(nonce, proof);
        }
        if (text.isEmpty()) {
            return null;
        }
        return new ParsedResponse(text, "");
    }

    private static ParsedResponse parseResponse(byte[] payload) {
        final ParsedResponse json = parseJsonResponse(payload);
        if (json != null) {
            return json;
        }
        try {
            return parseBinaryResponse(payload);
        } catch (IOException ignored) {
            return parsePipeResponse(payload);
        }
    }

    private byte[] buildChallengeBinaryPayload(String nonce, long expiresAtEpochMillis) throws IOException {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeUTF(PACKET_CHALLENGE);
            out.writeInt(PROTOCOL_VERSION);
            out.writeUTF(nonce);
            out.writeUTF(nonce);
            out.writeLong(expiresAtEpochMillis);
            out.writeUTF(verifier.baseUrl());
            out.flush();
            return bytes.toByteArray();
        }
    }

    private byte[] buildChallengeJsonPayload(String nonce, long expiresAtEpochMillis) {
        final String json =
            "{"
                + "\"packetType\":\"" + PACKET_CHALLENGE + "\","
                + "\"version\":" + PROTOCOL_VERSION + ","
                + "\"nonce\":\"" + jsonEscape(nonce) + "\","
                + "\"serverId\":\"" + jsonEscape(nonce) + "\","
                + "\"expiresAt\":" + expiresAtEpochMillis + ","
                + "\"potatoBaseUrl\":\"" + jsonEscape(verifier.baseUrl()) + "\""
                + "}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    public void clearPending(UUID uuid) {
        pendingPlayers.remove(uuid);
        pendingChallenges.remove(uuid);
        final BukkitTask timeoutTask = pendingKickTasks.remove(uuid);
        if (timeoutTask != null) {
            timeoutTask.cancel();
        }
        final BukkitTask repeatTask = pendingChallengeRepeatTasks.remove(uuid);
        if (repeatTask != null) {
            repeatTask.cancel();
        }
    }

    public void verifyByAccessToken(Player player, String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            player.sendMessage(colorize("&cUsage: /potato verify <accessToken>"));
            return;
        }
        player.sendMessage(colorize("&7Checking PotatoAccount token..."));
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            final PotatoAuthVerifier.VerifyResult result = verifier.verifyAccessToken(accessToken);
            getServer().getScheduler().runTask(this, () -> applyVerifyResult(player, result));
        });
    }

    public void applyVerifyResult(Player player, PotatoAuthVerifier.VerifyResult result) {
        if (!player.isOnline()) {
            return;
        }
        if (!result.success()) {
            if (debugLogging) {
                getLogger().info("PotatoAuth failed for " + player.getName() + ": " + result.reason());
            }
            kickVerificationFailed(player, result.reason());
            return;
        }

        final String playerName = player.getName();
        final String normalizedName = normalizeName(playerName);
        final String profileName = result.profile().name();
        final String profileId = result.profile().id();
        if (!profileName.equalsIgnoreCase(playerName)) {
            kickVerificationFailed(player, "Session belongs to " + profileName + ", not " + playerName);
            return;
        }

        if (enforceLinkedProfile) {
            final String linkedProfile = linkedProfiles.get(normalizedName);
            if (linkedProfile == null) {
                linkedProfiles.put(normalizedName, profileId);
                saveLinkedProfiles();
            } else if (!linkedProfile.equalsIgnoreCase(profileId)) {
                kickVerificationFailed(player, "This username is linked to another Potato profile");
                return;
            }
        }

        final String ipAddress =
            player.getAddress() != null && player.getAddress().getAddress() != null
                ? player.getAddress().getAddress().getHostAddress()
                : null;
        final PotatoAuthVerifier.TextureProperty textures = result.profile().textures();
        final String texturesValue = textures != null ? textures.value() : null;
        final String texturesSignature = textures != null ? textures.signature() : null;
        if (debugLogging) {
            final String skinUrl = extractSkinUrl(texturesValue);
            getLogger().info(
                "PotatoAuth profile verified for " + playerName + " profileId=" + profileId + " textures=" + (texturesValue != null && !texturesValue.isBlank())
                    + " signedTextures=" + (texturesSignature != null && !texturesSignature.isBlank())
                    + (skinUrl != null ? " skinUrl=" + skinUrl : "")
            );
        }
        sessionGrants.put(
            normalizedName,
            new SessionGrant(profileId, profileName, System.currentTimeMillis() + sessionMillis, ipAddress, texturesValue, texturesSignature)
        );
        applyProfile(player, texturesValue, texturesSignature);
        clearPending(player.getUniqueId());
        player.sendMessage(colorize(getConfig().getString("messages.success", "&aPotato authentication succeeded.")));
    }

    private void kickVerificationFailed(Player player, String reason) {
        if (debugLogging) {
            getLogger().info("PotatoAuth kicking " + player.getName() + ": " + reason);
        }
        clearPending(player.getUniqueId());
        final String template = getConfig().getString("messages.failedKick", "&cNot authenticated with PotatoAuth: {reason}");
        player.kickPlayer(colorize(template.replace("{reason}", String.valueOf(reason))));
    }

    public boolean resendChallenge(Player player) {
        if (!isPending(player)) {
            return false;
        }
        final ChallengeState state = pendingChallenges.get(player.getUniqueId());
        if (state == null) {
            return false;
        }
        sendChallenge(player, state);
        return true;
    }

    public boolean hasActiveSession(String username, InetAddress address) {
        return getActiveSessionGrant(username, address) != null;
    }

    private SessionGrant getActiveSessionGrant(String username, InetAddress address) {
        final String normalized = normalizeName(username);
        final SessionGrant grant = sessionGrants.get(normalized);
        if (grant == null) {
            return null;
        }
        if (grant.expiresAtEpochMillis() < System.currentTimeMillis()) {
            sessionGrants.remove(normalized);
            return null;
        }
        if (requireSameIpForSessionReuse) {
            final String expectedIp = grant.ipAddress();
            final String currentIp = address != null ? address.getHostAddress() : null;
            if (expectedIp != null && currentIp != null && !expectedIp.equals(currentIp)) {
                return null;
            }
        }
        return grant;
    }

    private void applySessionProfile(Player player, SessionGrant grant) {
        applyProfile(player, grant.texturesValue(), grant.texturesSignature());
    }

    private void applyProfile(Player player, String texturesValue, String texturesSignature) {
        applyProfileNow(player, texturesValue, texturesSignature);
        scheduleProfileReapply(player.getUniqueId(), texturesValue, texturesSignature, 1L);
        scheduleProfileReapply(player.getUniqueId(), texturesValue, texturesSignature, 20L);
    }

    private void scheduleProfileReapply(
        UUID playerUuid,
        String texturesValue,
        String texturesSignature,
        long delayTicks
    ) {
        getServer().getScheduler().runTaskLater(this, () -> {
            final Player online = getServer().getPlayer(playerUuid);
            if (online == null || !online.isOnline()) {
                return;
            }
            applyProfileNow(online, texturesValue, texturesSignature);
        }, Math.max(1L, delayTicks));
    }

    private void applyProfileNow(Player player, String texturesValue, String texturesSignature) {
        try {
            final PlayerProfile currentProfile = player.getPlayerProfile();
            final PlayerProfile paperProfile = Bukkit.createProfileExact(player.getUniqueId(), player.getName());

            if (currentProfile != null && !currentProfile.getProperties().isEmpty()) {
                paperProfile.setProperties(currentProfile.getProperties());
            }

            if (texturesValue != null && !texturesValue.isBlank()) {
                paperProfile.removeProperty("textures");
                if (texturesSignature != null && !texturesSignature.isBlank()) {
                    paperProfile.setProperty(new ProfileProperty("textures", texturesValue, texturesSignature));
                } else {
                    paperProfile.setProperty(new ProfileProperty("textures", texturesValue));
                }
            }
            player.setPlayerProfile(paperProfile);
            refreshAppearance(player);
        } catch (Throwable error) {
            if (debugLogging) {
                getLogger().warning("Failed to apply PotatoAuth skin profile for " + player.getName() + ": " + error.getMessage());
            }
        }
    }

    private void refreshAppearance(Player player) {
        for (Player viewer : getServer().getOnlinePlayers()) {
            if (viewer.getUniqueId().equals(player.getUniqueId())) {
                continue;
            }
            if (!viewer.canSee(player)) {
                continue;
            }
            viewer.hidePlayer(this, player);
            viewer.showPlayer(this, player);
        }
    }

    private static String extractSkinUrl(String texturesValue) {
        if (texturesValue == null || texturesValue.isBlank()) {
            return null;
        }
        final String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(texturesValue), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
        final YamlConfiguration yaml = new YamlConfiguration();
        try {
            yaml.loadFromString(decoded);
        } catch (InvalidConfigurationException ignored) {
            return null;
        }
        final String url = String.valueOf(yaml.getString("textures.SKIN.url", "")).trim();
        return url.isEmpty() ? null : url;
    }

    public void clearSession(String username) {
        sessionGrants.remove(normalizeName(username));
    }

    public boolean unlink(String username) {
        final String normalized = normalizeName(username);
        final boolean removed = linkedProfiles.remove(normalized) != null;
        if (removed) {
            saveLinkedProfiles();
        }
        return removed;
    }

    public String statusFor(Player player) {
        if (isPending(player)) {
            return colorize(getConfig().getString("messages.statusPending", "&eStatus: pending auth"));
        }
        if (hasActiveSession(player.getName(), player.getAddress() != null ? player.getAddress().getAddress() : null)) {
            return colorize(getConfig().getString("messages.statusVerified", "&aStatus: authenticated"));
        }
        return colorize(getConfig().getString("messages.statusUnverified", "&cStatus: not authenticated"));
    }

    public String colorize(String message) {
        return ChatColor.translateAlternateColorCodes('&', message);
    }

    private static String newNonce() {
        final byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String normalizeName(String username) {
        return String.valueOf(username).trim().toLowerCase(Locale.ROOT);
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

    private record ChallengeState(String nonce, long expiresAtEpochMillis) {}

    private record ParsedResponse(String nonce, String proof) {}

    private record SessionGrant(
        String profileId,
        String profileName,
        long expiresAtEpochMillis,
        String ipAddress,
        String texturesValue,
        String texturesSignature
    ) {}
}
