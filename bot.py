#!/usr/bin/env python3
"""
Advanced Multi-App VPN Config Formatter Bot with SSL Scanner
Commands: /start, /help, /example, /stats, /build, /scan
Supports: HA Tunnel, TLS Tunnel, HTTP Custom, HTTP Injector, NapsternetV,
          OpenVPN, WireGuard, Shadowsocks, V2Ray, NetMod, HTTP Net Header
Auto-retry on network errors (up to 5 times)
"""

import os
import re
import json
import atexit
import logging
import requests
import time
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ConversationHandler, filters, ContextTypes
)

# ============================================================
# LOCK FILE SETUP (PythonAnywhere free tier persistence)
# ============================================================
LOCKFILE_PATH = "/tmp/my_telegram_vpn_bot.lock"

def remove_lock_file():
    if os.path.exists(LOCKFILE_PATH):
        os.remove(LOCKFILE_PATH)

with open(LOCKFILE_PATH, 'w') as f:
    f.write("bot is running")
atexit.register(remove_lock_file)

# ============================================================
# BOT CONFIGURATION
# ============================================================
BOT_TOKEN = "8331593245:AAHoieYR8jxW_PSWFdz9dGBsmaU4g1wUGNU"
WHOISJSON_API_KEY = "77c8798ee484732cb2012ccfa85ea76d9c97cafef99db9d3f54b69fc11966a1e"

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# In-memory storage
user_configs = {}           # Temporary config storage
stats = {                   # Simple usage counter
    "configs_processed": 0,
    "start_timestamp": datetime.now().isoformat()
}

# Conversation states for /build
BUILD_SNI, BUILD_HOST, BUILD_PORT, BUILD_PAYLOAD = range(4)

# ============================================================
# PARSING & VALIDATION
# ============================================================
def parse_config_text(raw_text: str) -> dict:
    """Extracts values from [ᯤ] [Key] : Value format."""
    config = {}
    pattern = r"\[ᯤ\] \[(.*?)\] : (.*)"
    matches = re.findall(pattern, raw_text)
    for key, value in matches:
        config[key.strip()] = value.strip()
    return config

def validate_config(config: dict) -> list:
    """Returns list of missing important fields."""
    required = ["SSL/SNI", "Primary Host", "Payload"]
    missing = [field for field in required if field not in config or not config[field]]
    return missing

# ============================================================
# FORMATTING FUNCTIONS
# ============================================================
def clean_payload(payload: str) -> str:
    return payload.replace("[crlf]", "\r\n").replace("[crlf]", "\r\n")

def format_ha_tunnel(config: dict) -> str:
    p = clean_payload(config.get("Payload", ""))
    return f"""connection_mode={config.get("Connection Mode", "3")}
server_port={config.get("Server Port", "443")}
payload={p}
custom_host={config.get("Custom Host", "")}
ssl_sni={config.get("SSL/SNI", "")}
custom_resolver={config.get("Custom Resolver", "1.1.1.1")}
use_realm_host={config.get("Use Realm Host?", "True")}
preserve_sni={config.get("Preserve SNI?", "False")}
use_tcp_payload={config.get("Use TCP Payload?", "False")}
realm_host={config.get("Realm Host", "")}
primary_host={config.get("Primary Host", "")}
dns_primary_host={config.get("DNS Primary Host", "")}
server_country={config.get("Server Node/Country", "us")}
lock_mobile_data={config.get("Lock Mobile Data Only?", "True")}
block_root={config.get("Block Root", "False")}"""

def format_tls_tunnel(config: dict) -> str:
    p = clean_payload(config.get("Payload", ""))
    return f"""port={config.get("Server Port", "443")}
sni={config.get("SSL/SNI", "")}
payload={p}
proxy_host={config.get("Proxy Host", "")}
proxy_port={config.get("Proxy Port", "")}"""

def format_http_custom(config: dict) -> str:
    p = clean_payload(config.get("Payload", ""))
    return f"""# HTTP Custom Config
server={config.get("Primary Host", "")}
port={config.get("Server Port", "443")}
sni={config.get("SSL/SNI", "")}
payload={p}
proxy={config.get("Proxy Host", "")}
proxy_port={config.get("Proxy Port", "")}"""

def format_http_injector(config: dict) -> str:
    p = clean_payload(config.get("Payload", ""))
    return f"""# HTTP Injector Config
remote_proxy={config.get("Primary Host", "")}
remote_port={config.get("Server Port", "443")}
sni={config.get("SSL/SNI", "")}
payload={p}
proxy={config.get("Proxy Host", "")}
proxy_port={config.get("Proxy Port", "")}"""

def format_napsternetv(config: dict) -> str:
    p = clean_payload(config.get("Payload", ""))
    data = {
        "server": config.get("Primary Host", ""),
        "server_port": int(config.get("Server Port", "443")),
        "password": "",
        "method": "chacha20-ietf-poly1305",
        "plugin": "v2ray-plugin",
        "plugin_opts": f"tls;host={config.get('SSL/SNI', '')};path=/",
        "remarks": config.get("Note", "VPN Config"),
        "payload": p
    }
    return json.dumps(data, indent=2)

def format_openvpn(config: dict) -> str:
    host = config.get("Primary Host", "server.example.com")
    port = config.get("Server Port", "443")
    sni = config.get("SSL/SNI", "")
    return f"""client
dev tun
proto tcp
remote {host} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
# Paste your CA certificate here
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
# Paste your client certificate here
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
# Paste your client key here
-----END PRIVATE KEY-----
</key>
# tls-server-name {sni}
verb 3
"""

def format_wireguard(config: dict) -> str:
    host = config.get("Primary Host", "server.example.com")
    port = config.get("Server Port", "443")
    return f"""[Interface]
PrivateKey = <client private key>
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = <server public key>
Endpoint = {host}:{port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

def format_shadowsocks(config: dict) -> str:
    host = config.get("Primary Host", "")
    port = config.get("Server Port", "443")
    method = "aes-256-gcm"
    password = "your_password"
    import base64
    userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
    return f"ss://{userinfo}@{host}:{port}#VPN_Config"

def format_v2ray(config: dict) -> str:
    host = config.get("Primary Host", "")
    port = int(config.get("Server Port", "443"))
    sni = config.get("SSL/SNI", "")
    return json.dumps({
        "inbounds": [{"port": 10808, "listen": "127.0.0.1", "protocol": "socks"}],
        "outbounds": [{
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": "your-uuid", "security": "auto"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": sni}}
        }]
    }, indent=2)

def format_netmod(config: dict) -> str:
    p = clean_payload(config.get("Payload", ""))
    return f"""# NetMod Config
server={config.get("Primary Host", "")}
port={config.get("Server Port", "443")}
sni={config.get("SSL/SNI", "")}
payload={p}"""

def format_http_net_header(config: dict) -> str:
    p = clean_payload(config.get("Payload", ""))
    return f"""Host: {config.get("SSL/SNI", "")}
Port: {config.get("Server Port", "443")}
Payload: {p}"""

# App registry
APP_REGISTRY = {
    "ha": ("📱 HA Tunnel Plus", format_ha_tunnel),
    "tls": ("🔒 TLS Tunnel", format_tls_tunnel),
    "httpcustom": ("🌐 HTTP Custom", format_http_custom),
    "injector": ("💉 HTTP Injector", format_http_injector),
    "napster": ("🚀 NapsternetV", format_napsternetv),
    "openvpn": ("🔐 OpenVPN", format_openvpn),
    "wireguard": ("🛡️ WireGuard", format_wireguard),
    "shadowsocks": ("🌑 Shadowsocks", format_shadowsocks),
    "v2ray": ("☁️ V2Ray", format_v2ray),
    "netmod": ("📶 NetMod", format_netmod),
    "httpnet": ("📡 HTTP Net Header", format_http_net_header),
}

# ============================================================
# SSL SCANNER FUNCTION
# ============================================================
async def scan_sni_via_api(domain: str) -> str:
    """Call WhoisJSON to check SSL certificate for a domain."""
    url = "https://whoisjson.com/api/v1/ssl-cert-check"
    headers = {"Authorization": f"TOKEN={WHOISJSON_API_KEY}"}
    params = {"domain": domain}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        if not data.get("valid"):
            return f"❌ SSL certificate for `{domain}` is not valid or could not be verified."

        issuer = data.get("issuer", {}).get("CN", "N/A")
        valid_from = data.get("valid_from", "N/A")
        valid_to = data.get("valid_to", "N/A")
        subject_cn = data.get("details", {}).get("subject", {}).get("CN", "N/A")

        return (
            f"🔒 *SSL Info for `{domain}`*\n"
            f"• Common Name: `{subject_cn}`\n"
            f"• Issuer: `{issuer}`\n"
            f"• Valid: {valid_from} → {valid_to}"
        )
    except Exception as e:
        logger.error(f"Scan error for {domain}: {e}")
        return f"❌ Failed to scan `{domain}`. Please try again later."

# ============================================================
# BOT COMMAND HANDLERS
# ============================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "🤖 *VPN Config Formatter Bot*\n\n"
        "This bot converts raw VPN configuration text (from apps like HA Tunnel, TLS Tunnel, "
        "or bots like @Decode7Bot) into clean, ready‑to‑use formats for *11+ VPN applications*.\n\n"
        "📋 *What I Do:*\n"
        "• Parse config dumps containing `[ᯤ] [Key] : Value`\n"
        "• Validate missing important fields (SNI, Host, Payload)\n"
        "• Generate clipboard‑ready text for HA Tunnel, TLS Tunnel, HTTP Custom, HTTP Injector, "
        "NapsternetV, OpenVPN, WireGuard, Shadowsocks, V2Ray, NetMod, and HTTP Net Header\n"
        "• Offer an interactive payload builder with `/build`\n"
        "• Scan SSL certificates with `/scan domain.com`\n\n"
        "🚀 *How to Use:*\n"
        "1. Send me a config text block.\n"
        "2. I'll show buttons for each supported app.\n"
        "3. Tap an app to get formatted output.\n"
        "4. Copy the text and paste it into your VPN app.\n\n"
        "🔧 *Commands:*\n"
        "/start – This welcome message\n"
        "/help – List all supported apps and commands\n"
        "/example – Show a sample config text\n"
        "/stats – View bot usage statistics\n"
        "/build – Step‑by‑step payload builder\n"
        "/scan <domain> – Check SSL certificate info\n\n"
        "✨ *No files, no encryption — just fast formatting.*"
    )
    await update.message.reply_text(welcome_text, parse_mode="Markdown")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📚 *Available Commands*\n\n"
        "/start - Welcome message\n"
        "/help - This help\n"
        "/example - Show sample config text\n"
        "/stats - Bot usage statistics\n"
        "/build - Interactive payload builder\n"
        "/scan <domain> - SSL certificate scanner (e.g., /scan google.com)\n\n"
        "*Supported Apps:*\n"
    )
    for key, (name, _) in APP_REGISTRY.items():
        msg += f"• {name}\n"
    msg += "\nJust send me a config text and I'll let you choose the format."
    await update.message.reply_text(msg, parse_mode="Markdown")

async def example_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sample = """[ᯤ] [Connection Mode] : 3
[ᯤ] [Server Port] : 443
[ᯤ] [Payload] : CONNECT [host_port] HTTP/1.1[crlf]Host: www.freesite.com[crlf][crlf]
[ᯤ] [Custom Host] : www.freesite.com
[ᯤ] [SSL/SNI] : arenaplus.co.za
[ᯤ] [Primary Host] : 204.48.30.222"""
    await update.message.reply_text(
        "📋 *Example Config Text*\n\n"
        "Copy and send me something like this:\n\n"
        f"```\n{sample}\n```",
        parse_mode="Markdown"
    )

async def stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime = datetime.now() - datetime.fromisoformat(stats["start_timestamp"])
    await update.message.reply_text(
        f"📊 *Bot Statistics*\n\n"
        f"Configs processed: {stats['configs_processed']}\n"
        f"Uptime: {str(uptime).split('.')[0]}\n"
        f"Supported apps: {len(APP_REGISTRY)}",
        parse_mode="Markdown"
    )

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan domain.com command."""
    try:
        domain = context.args[0].strip().lower()
        if "." not in domain or " " in domain:
            await update.message.reply_text("❌ Please provide a valid domain, e.g., `/scan google.com`")
            return
    except IndexError:
        await update.message.reply_text("❌ Please provide a domain, e.g., `/scan arenaplus.co.za`")
        return

    message = await update.message.reply_text(f"🔍 Scanning SSL for `{domain}`...")
    result = await scan_sni_via_api(domain)
    await message.edit_text(result, parse_mode="Markdown")

# ============================================================
# CONFIG MESSAGE HANDLER
# ============================================================
async def handle_config_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text
    user_id = update.message.from_user.id

    if "[Connection Mode]" in user_text or "[Server Port]" in user_text:
        config_data = parse_config_text(user_text)
        if not config_data:
            await update.message.reply_text("❌ Could not parse configuration.")
            return

        missing = validate_config(config_data)
        warning = ""
        if missing:
            warning = f"⚠️ Missing fields: {', '.join(missing)}\n\n"

        user_configs[user_id] = config_data
        stats["configs_processed"] += 1

        keyboard = []
        row = []
        for i, (key, (name, _)) in enumerate(APP_REGISTRY.items()):
            row.append(InlineKeyboardButton(name, callback_data=key))
            if len(row) == 2:
                keyboard.append(row)
                row = []
        if row:
            keyboard.append(row)
        keyboard.append([InlineKeyboardButton("📋 ALL FORMATS", callback_data="all")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            f"{warning}✅ *Configuration parsed!*\n\nSelect an app format:",
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
    else:
        await update.message.reply_text(
            "Please send a valid config text containing `[Connection Mode]` or `[Server Port]`.\n"
            "Use /example to see a sample."
        )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    config_data = user_configs.get(user_id)

    if not config_data:
        await query.edit_message_text("❌ Session expired. Please send the config again.")
        return

    choice = query.data
    if choice == "all":
        response = "📋 *All Formats Generated*\n\n"
        for key, (name, formatter) in APP_REGISTRY.items():
            formatted = formatter(config_data)
            response += f"*{name}:*\n```\n{formatted}\n```\n\n"
        await query.edit_message_text(response, parse_mode="Markdown")
        return

    if choice in APP_REGISTRY:
        name, formatter = APP_REGISTRY[choice]
        formatted = formatter(config_data)
        response = f"✅ *{name} Configuration*\n\n```\n{formatted}\n```"
        await query.edit_message_text(response, parse_mode="Markdown")
    else:
        await query.edit_message_text("❌ Unknown format.")

# ============================================================
# INTERACTIVE BUILDER (Conversation Handler)
# ============================================================
async def build_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛠️ *Payload Builder*\n\n"
        "Let's create a basic config. First, enter the *SNI/Host* (e.g., arenaplus.co.za):\n"
        "Send /cancel to abort.",
        parse_mode="Markdown"
    )
    return BUILD_SNI

async def build_sni(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['sni'] = update.message.text.strip()
    await update.message.reply_text("Now enter the *Custom Host* (e.g., www.freesite.com):", parse_mode="Markdown")
    return BUILD_HOST

async def build_host(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['host'] = update.message.text.strip()
    await update.message.reply_text("Enter the *Server Port* (default 443):", parse_mode="Markdown")
    return BUILD_PORT

async def build_port(update: Update, context: ContextTypes.DEFAULT_TYPE):
    port = update.message.text.strip()
    if not port.isdigit():
        await update.message.reply_text("Invalid port. Please enter a number (e.g., 443):")
        return BUILD_PORT
    context.user_data['port'] = port
    await update.message.reply_text(
        "Finally, enter the *Payload* (use [crlf] for newlines):\n"
        "Example: CONNECT [host_port] HTTP/1.1[crlf]Host: www.freesite.com[crlf][crlf]",
        parse_mode="Markdown"
    )
    return BUILD_PAYLOAD

async def build_payload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    payload = update.message.text.strip()
    config = {
        "SSL/SNI": context.user_data['sni'],
        "Custom Host": context.user_data['host'],
        "Server Port": context.user_data['port'],
        "Payload": payload,
        "Primary Host": context.user_data.get('sni', ''),
        "Connection Mode": "3"
    }
    user_id = update.message.from_user.id
    user_configs[user_id] = config
    stats["configs_processed"] += 1

    keyboard = []
    row = []
    for i, (key, (name, _)) in enumerate(APP_REGISTRY.items()):
        row.append(InlineKeyboardButton(name, callback_data=key))
        if len(row) == 2:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    keyboard.append([InlineKeyboardButton("📋 ALL FORMATS", callback_data="all")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "✅ *Config built!* Select an app format:",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )
    return ConversationHandler.END

async def build_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Builder cancelled.")
    return ConversationHandler.END

# ============================================================
# ERROR HANDLER
# ============================================================
async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(msg="Exception while handling an update:", exc_info=context.error)

# ============================================================
# MAIN WITH AUTO-RETRY
# ============================================================
def main():
    """Start the bot with auto-retry on network errors."""
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("example", example_cmd))
    app.add_handler(CommandHandler("stats", stats_cmd))
    app.add_handler(CommandHandler("scan", scan_command))

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("build", build_start)],
        states={
            BUILD_SNI: [MessageHandler(filters.TEXT & ~filters.COMMAND, build_sni)],
            BUILD_HOST: [MessageHandler(filters.TEXT & ~filters.COMMAND, build_host)],
            BUILD_PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, build_port)],
            BUILD_PAYLOAD: [MessageHandler(filters.TEXT & ~filters.COMMAND, build_payload)],
        },
        fallbacks=[CommandHandler("cancel", build_cancel)],
    )
    app.add_handler(conv_handler)

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_config_message))
    app.add_handler(CallbackQueryHandler(button_callback))
    app.add_error_handler(error_handler)

    logger.info("Bot is starting...")
    
    # Auto-retry on network errors up to 5 times
    retries = 0
    while retries < 5:
        try:
            app.run_polling()
        except Exception as e:
            retries += 1
            logger.error(f"Bot crashed: {e}. Retry {retries}/5 in 10 seconds...")
            time.sleep(10)
    
    logger.critical("Bot failed after 5 retries. Exiting.")

if __name__ == "__main__":
    main()