'use strict';
require('dotenv').config();
const base = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}`;
const url = process.argv[2];
if (!url || !/^https:\/\//.test(url)) throw Error('Usage: npm run webhook -- https://domain');
(async () => { const r = await fetch(`${base}/setWebhook`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({url:`${url.replace(/\/$/,'')}/telegram/webhook`,secret_token:process.env.TELEGRAM_WEBHOOK_SECRET,allowed_updates:['message']}) }); if(!r.ok) process.exit(1); console.log(await r.text()); })();
