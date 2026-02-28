package com.mrpotato.potatoauth;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

public final class PotatoAuthCommand implements CommandExecutor, TabCompleter {
    private final PotatoAuthPlugin plugin;

    public PotatoAuthCommand(PotatoAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) {
            sender.sendMessage(plugin.colorize("&eUsage: /potato verify <accessToken>"));
            sender.sendMessage(plugin.colorize("&eUsage: /potato status"));
            sender.sendMessage(plugin.colorize("&eUsage: /potato resend"));
            if (sender.hasPermission("potatoauth.admin")) {
                sender.sendMessage(plugin.colorize("&eUsage: /potato unlink <username>"));
                sender.sendMessage(plugin.colorize("&eUsage: /potato reload"));
            }
            return true;
        }

        final String subcommand = args[0].toLowerCase(Locale.ROOT);
        switch (subcommand) {
            case "verify":
                return handleVerify(sender, args);
            case "status":
                return handleStatus(sender);
            case "resend":
                return handleResend(sender);
            case "unlink":
                return handleUnlink(sender, args);
            case "reload":
                return handleReload(sender);
            default:
                sender.sendMessage(plugin.colorize("&cUnknown subcommand. Use /potato status"));
                return true;
        }
    }

    private boolean handleVerify(CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(plugin.colorize("&cOnly players can verify."));
            return true;
        }
        if (args.length < 2) {
            sender.sendMessage(plugin.colorize("&cUsage: /potato verify <accessToken>"));
            return true;
        }
        plugin.verifyByAccessToken(player, args[1].trim());
        return true;
    }

    private boolean handleStatus(CommandSender sender) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(plugin.colorize("&eStatus is player-specific. Run this as a player."));
            return true;
        }
        sender.sendMessage(plugin.statusFor(player));
        return true;
    }

    private boolean handleResend(CommandSender sender) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(plugin.colorize("&cOnly players can request a challenge resend."));
            return true;
        }
        if (plugin.resendChallenge(player)) {
            player.sendMessage(plugin.colorize("&aAuth challenge resent."));
        } else {
            player.sendMessage(plugin.colorize("&eNo pending authentication challenge."));
        }
        return true;
    }

    private boolean handleUnlink(CommandSender sender, String[] args) {
        if (!sender.hasPermission("potatoauth.admin")) {
            sender.sendMessage(plugin.colorize("&cYou do not have permission to do that."));
            return true;
        }
        if (args.length < 2) {
            sender.sendMessage(plugin.colorize("&cUsage: /potato unlink <username>"));
            return true;
        }
        final String username = args[1];
        final boolean removed = plugin.unlink(username);
        plugin.clearSession(username);
        if (removed) {
            sender.sendMessage(plugin.colorize("&aUnlinked Potato profile for " + username + "."));
        } else {
            sender.sendMessage(plugin.colorize("&eNo linked profile found for " + username + "."));
        }
        return true;
    }

    private boolean handleReload(CommandSender sender) {
        if (!sender.hasPermission("potatoauth.admin")) {
            sender.sendMessage(plugin.colorize("&cYou do not have permission to do that."));
            return true;
        }
        plugin.reloadRuntimeConfig();
        sender.sendMessage(plugin.colorize("&aPotatoAuth config reloaded."));
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        final List<String> out = new ArrayList<>();
        if (args.length == 1) {
            final String typed = args[0].toLowerCase(Locale.ROOT);
            addIfMatches(out, typed, "verify");
            addIfMatches(out, typed, "status");
            addIfMatches(out, typed, "resend");
            if (sender.hasPermission("potatoauth.admin")) {
                addIfMatches(out, typed, "unlink");
                addIfMatches(out, typed, "reload");
            }
        }
        return out;
    }

    private static void addIfMatches(List<String> out, String typed, String candidate) {
        if (candidate.startsWith(typed)) {
            out.add(candidate);
        }
    }
}
