'use strict';
const url = process.argv[2];
if (!url || !/^https:\/\//.test(url)) throw Error('Usage: npm run keepalive -- https://domain/health');
fetch(url,{signal:AbortSignal.timeout(10000)}).then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1));
