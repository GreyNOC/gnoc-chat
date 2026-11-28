module.exports = { apps: [{
  name: "oss-bot", script: "~/.gnoc/scripts/oss-bot.sh", interpreter: "bash",
  cwd: "~/.gnoc", autorestart: true, watch: false,
  min_uptime: "60s", max_restarts: 20, exp_backoff_restart_delay: 30000,
  kill_timeout: 20000, treekill: true, max_memory_restart: "1500M",
  env: { OSS_BOT_DRY: "0" } }] };
