// Jaronite News — Advertising Notifier Bot
// Watches for new members who joined via the advertising invite link
// and pings @advertising organizer in the designated channel.
//
// NOTE: This bot runs on the SAME Discord application as the Worker's DM bot
// and OAuth (one app for everything). Keep DISCORD_BOT_TOKEN pointed at that
// app's bot.
//
// Environment variables (set in Railway dashboard):
//   DISCORD_BOT_TOKEN      — your bot token (the one Jaronite News app)
//   DISCORD_GUILD_ID       — your server ID
//   NOTIFY_CHANNEL_ID      — channel to post notifications in
//   NOTIFY_ROLE_ID         — role to ping (@advertising organizer)
//   WATCH_INVITE_CODE      — the invite code to watch (just the code, not the full URL)

const { Client, GatewayIntentBits, Events } = require('discord.js');

const TOKEN           = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID        = process.env.DISCORD_GUILD_ID        || '';
const NOTIFY_CHANNEL  = process.env.NOTIFY_CHANNEL_ID       || '1519191536007512114';
const NOTIFY_ROLE     = process.env.NOTIFY_ROLE_ID          || '1513126299512864869';
const WATCH_INVITE    = process.env.WATCH_INVITE_CODE        || '4Gu4ybqDdg';

if (!TOKEN) {
  console.error('DISCORD_BOT_TOKEN is not set — exiting');
  process.exit(1);
}

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,   // privileged — enable in Discord Dev Portal → Bot → Privileged Gateway Intents
    GatewayIntentBits.GuildMessages,  // needed to receive message events for the !checkpayments command
    GatewayIntentBits.MessageContent, // privileged — enable in Discord Dev Portal → Bot → Privileged Gateway Intents
    // Note: GuildInvites is NOT a valid GatewayIntentBits value in discord.js v14.
    // InviteCreate/InviteDelete events and guild.invites.fetch() work with just
    // the Guilds intent. The bot needs Manage Guild *permission* (not a special
    // intent) to read invite use counts.
  ],
});

// Cache of invite use counts: Map<inviteCode, useCount>
// Populated on ready, updated on each guildMemberAdd by diffing.
const inviteCache = new Map();

async function cacheInvites(guild) {
  try {
    const invites = await guild.invites.fetch();
    invites.forEach(inv => inviteCache.set(inv.code, inv.uses));
    console.log(`Cached ${invites.size} invite(s) for guild "${guild.name}"`);
  } catch (e) {
    console.error('Failed to cache invites:', e);
  }
}

client.once(Events.ClientReady, async (c) => {
  console.log(`✅ Logged in as ${c.user.tag}`);
  const guild = c.guilds.cache.get(GUILD_ID) || c.guilds.cache.first();
  if (!guild) { console.error('Guild not found — check DISCORD_GUILD_ID'); return; }
  await cacheInvites(guild);
});

client.on(Events.GuildMemberAdd, async (member) => {
  if (member.guild.id !== GUILD_ID && GUILD_ID) return;

  // Fetch current invite counts and diff against cache to find which one was used
  let usedInvite = null;
  try {
    const currentInvites = await member.guild.invites.fetch();
    currentInvites.forEach(inv => {
      const cachedUses = inviteCache.get(inv.code) ?? 0;
      if (inv.uses > cachedUses) {
        usedInvite = inv;
      }
      // Update cache
      inviteCache.set(inv.code, inv.uses);
    });
    // Also remove any invites that no longer exist (expired/deleted)
    for (const code of inviteCache.keys()) {
      if (!currentInvites.has(code)) inviteCache.delete(code);
    }
  } catch (e) {
    console.error('Failed to fetch invites on member join:', e);
  }

  // Only notify if the used invite matches the advertising invite
  if (!usedInvite || usedInvite.code !== WATCH_INVITE) return;

  const channel = member.guild.channels.cache.get(NOTIFY_CHANNEL);
  if (!channel) {
    console.error(`Notify channel ${NOTIFY_CHANNEL} not found`);
    return;
  }

  const joinedAt = new Date().toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
  });

  await channel.send(
    `📢 <@&${NOTIFY_ROLE}> — a new potential advertiser just joined!\n\n` +
    `**User:** ${member.user.tag} (<@${member.user.id}>)\n` +
    `**Joined via:** discord.gg/${WATCH_INVITE}\n` +
    `**Joined at:** ${joinedAt}\n\n` +
    `They came from the Jaronite News advertise page — reach out to help them get started!`
  );

  console.log(`Notified: ${member.user.tag} joined via advertising invite`);
});

// Refresh invite cache whenever an invite is created or deleted
client.on(Events.InviteCreate, async (invite) => {
  inviteCache.set(invite.code, invite.uses ?? 0);
});
client.on(Events.InviteDelete, async (invite) => {
  inviteCache.delete(invite.code);
});

client.login(TOKEN);

// ================================================================
// Payment status checker
// Runs daily at 9 AM UTC via node-cron.
//
// Fetches all won bids from the Worker API and posts a summary to the staff
// channel, pinging @NOTIFY_ROLE.
//
// Updated for the per-view billing model: the Worker now bills rate × views
// after each ad runs, so we report the invoiced total (`amount_owed`) and the
// API's derived lifecycle `stage` (late / unpaid / underpaid / etc.) rather
// than recomputing urgency from the ad date.
//
// Additional environment variables needed:
//   WORKER_BASE_URL        — e.g. https://jaronitenewsinc.ejblox476.workers.dev
//   BOT_API_KEY            — the permanent key you set as a Worker secret (BOT_API_KEY)
//   PAYMENT_CHANNEL_ID     — channel to post payment alerts in (can be same as NOTIFY_CHANNEL)
//   PAYMENT_ROLE_ID        — role to ping for payment alerts (can be same as NOTIFY_ROLE)
// ================================================================

const cron = require('node-cron');

const WORKER_URL       = process.env.WORKER_BASE_URL        || '';
const BOT_API_KEY      = process.env.BOT_API_KEY            || '';
const PAYMENT_CHANNEL  = process.env.PAYMENT_CHANNEL_ID     || NOTIFY_CHANNEL;
const PAYMENT_ROLE     = process.env.PAYMENT_ROLE_ID        || NOTIFY_ROLE;

// Match the Worker's slot labels so reports read consistently.
const SLOT_LABELS = {
  1: 'Bottom Leaderboard (728×90)',
  2: 'Left Skyscraper (160×600)',
  3: 'Right Skyscraper (160×600)',
};

const money = (v) => (v == null ? null : `${Number(v).toFixed(2)} ℐ`);

// Format one bid line. Shows the invoiced total when available (amount_owed),
// otherwise notes the invoice hasn't been generated yet.
function fmtBid(b, extra = '') {
  const label = SLOT_LABELS[b.slot_number] || `Slot ${b.slot_number}`;
  const owed = b.amount_owed != null ? `**${money(b.amount_owed)}**` : '_pending invoice_';
  const paid = b.payment_amount_received ? ` · paid: ${money(b.payment_amount_received)}` : '';
  return `> **Bid #${b.id}** · ${b.advertiser_name} (\`${b.contact}\`) · ${label} · **${b.target_date}**` +
         ` · owed: ${owed}${paid}${extra}`;
}

// opts.targetChannel — a channel to post into instead of the default PAYMENT_CHANNEL
//                      (used by the !checkpayments command to reply in-place).
// opts.announceClear — if true, post a confirmation even when nothing is due
//                      (manual command), instead of staying silent (cron).
async function checkOverduePayments(opts = {}) {
  const { targetChannel = null, announceClear = false } = opts;

  if (!WORKER_URL || !BOT_API_KEY) {
    console.warn('WORKER_BASE_URL or BOT_API_KEY not set — payment check skipped');
    if (targetChannel) await targetChannel.send('⚠️ Payment check is misconfigured: `WORKER_BASE_URL` or `BOT_API_KEY` is not set.');
    return;
  }

  let channel = targetChannel;
  if (!channel) {
    const guild = client.guilds.cache.get(GUILD_ID) || client.guilds.cache.first();
    if (!guild) { console.error('Guild not found for payment check'); return; }
    channel = guild.channels.cache.get(PAYMENT_CHANNEL);
    if (!channel) { console.error(`Payment channel ${PAYMENT_CHANNEL} not found`); return; }
  }

  // Fetch won bids from the last 30 days (the API default window)
  let bids;
  try {
    const res = await fetch(
      `${WORKER_URL}/api/ads/payment-status`,
      { headers: { 'X-Bot-Key': BOT_API_KEY } }
    );
    if (!res.ok) {
      console.error(`Payment status API returned ${res.status}`);
      if (targetChannel) await targetChannel.send(`⚠️ Couldn't fetch payment status — the API returned ${res.status}.`);
      return;
    }
    bids = await res.json();
  } catch (e) {
    console.error('Failed to fetch payment status:', e);
    if (targetChannel) await targetChannel.send('⚠️ Couldn\'t reach the payment-status API. Check the worker URL and that it\'s deployed.');
    return;
  }

  const today = new Date().toISOString().slice(0, 10);

  // Bucket by the API's derived lifecycle stage.
  const late        = []; // invoice sent, unpaid past the grace window — chase these
  const underpaid   = []; // partial payment received, balance outstanding
  const unpaid      = []; // invoice sent, still within grace
  const notInvoiced = []; // won but the ad hasn't run / been invoiced yet

  for (const bid of (Array.isArray(bids) ? bids : [])) {
    switch (bid.stage) {
      case 'late':             late.push(bid); break;
      case 'underpaid':        underpaid.push(bid); break;
      case 'unpaid':           unpaid.push(bid); break;
      case 'won':
      case 'awaiting_invoice': notInvoiced.push(bid); break;
      default: break; // paid / overpaid / lost / pending → nothing to chase
    }
  }

  const total = late.length + underpaid.length + unpaid.length + notInvoiced.length;
  if (total === 0) {
    console.log('Payment check: nothing outstanding');
    if (announceClear && channel) {
      await channel.send('✅ All invoiced ad bids are paid up — nothing outstanding.');
    }
    return;
  }

  const lines = [
    `💸 <@&${PAYMENT_ROLE}> — **Daily ad payment report** (${today})`,
    '',
  ];

  if (late.length > 0) {
    lines.push(`🚨 **LATE — invoiced, unpaid past the grace window (${late.length})**`);
    for (const b of late) lines.push(fmtBid(b));
    lines.push('');
  }
  if (underpaid.length > 0) {
    lines.push(`➗ **UNDERPAID — partial payment, balance due (${underpaid.length})**`);
    for (const b of underpaid) {
      const remaining = (b.amount_owed != null)
        ? ` · remaining: **${money(Math.max(0, b.amount_owed - (b.payment_amount_received || 0)))}**`
        : '';
      lines.push(fmtBid(b, remaining));
    }
    lines.push('');
  }
  if (unpaid.length > 0) {
    lines.push(`📋 **AWAITING PAYMENT — invoice sent recently (${unpaid.length})**`);
    for (const b of unpaid) lines.push(fmtBid(b));
    lines.push('');
  }
  if (notInvoiced.length > 0) {
    lines.push(`🗓️ **WON — ad not yet run / invoiced (${notInvoiced.length})**`);
    for (const b of notInvoiced) lines.push(fmtBid(b));
    lines.push('');
  }

  lines.push(`_Advertisers are notified automatically (Discord DM, plus email if provided). This report is for staff follow-up._`);

  // Discord messages cap at 2000 chars — chunk if needed.
  const full = lines.join('\n');
  for (let i = 0; i < full.length; i += 1900) {
    await channel.send(full.slice(i, i + 1900));
  }
  console.log(`Payment check: ${late.length} late, ${underpaid.length} underpaid, ${unpaid.length} awaiting, ${notInvoiced.length} not-yet-invoiced`);
}

// ================================================================
// !checkpayments — manual trigger for the payment report.
// Posts the report into the channel where the command was used.
// Restricted to members with the Manage Guild permission (staff),
// so advertiser contact details aren't exposed to everyone.
// ================================================================
const { PermissionFlagsBits } = require('discord.js');

client.on(Events.MessageCreate, async (message) => {
  if (message.author.bot) return;
  if (!message.guild) return; // ignore DMs
  const content = message.content.trim().toLowerCase();
  if (content !== '!checkpayments') return;

  // Permission gate: must be able to Manage Guild (admins/managers).
  const member = message.member;
  if (!member || !member.permissions.has(PermissionFlagsBits.ManageGuild)) {
    await message.reply('You need the **Manage Server** permission to run this.');
    return;
  }

  await message.channel.sendTyping();
  try {
    await checkOverduePayments({ targetChannel: message.channel, announceClear: true });
  } catch (e) {
    console.error('!checkpayments error:', e);
    await message.reply('Something went wrong running the payment check — see the bot logs.');
  }
});

// Schedule daily at 9 AM UTC
client.once(Events.ClientReady, () => {
  // Small delay so guild cache is warm before the first run
  cron.schedule('0 9 * * *', () => {
    console.log('Running scheduled payment check…');
    checkOverduePayments().catch(e => console.error('Payment check error:', e));
  }, { timezone: 'UTC' });

  console.log('Payment overdue checker scheduled for 09:00 UTC daily');
});