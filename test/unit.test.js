'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { pinOk, idOk, validBody, configFromEnv } = require('../server');
test('validation rejects unsafe values',()=>{assert(pinOk('1234'));assert(!pinOk('12345'));assert(idOk('123'));assert(!idOk('0'));assert(validBody('x'));assert(!validBody(' '));});
test('configuration requires strong secrets',()=>assert.throws(()=>configFromEnv({DATABASE_URL:'postgres://x',PHONE_PIN:'1234',TELEGRAM_BOT_TOKEN:'1:x',TELEGRAM_WEBHOOK_SECRET:'short'})));
