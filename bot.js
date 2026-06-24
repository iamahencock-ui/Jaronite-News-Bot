// Jaronite News — Advertising Notifier Bot
// Watches for new members who joined via the advertising invite link
// and pings @advertising organizer in the designated channel.
//
// Environment variables (set in Railway dashboard):
//   DISCORD_BOT_TOKEN      — your bot token
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
