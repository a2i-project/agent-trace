'use strict';
// Feed PostToolUse events to Signet's Claude Code signer, one call per event,
// in one node process. chains.py starts it; SIGNET_HOME comes from the
// environment, as for the hook.
//
//   node signet_drive.cjs SIGN_CJS EVENTS.jsonl
//
// It calls processInput, the function sign.cjs runs on its standard input,
// with each event, which is what a hook process per event does, without the
// start-up per event. The signer never fails the agent and reports a lost
// receipt on standard error instead, so anything it writes there fails this
// driver.
const fs = require('node:fs');

const { processInput } = require(process.argv[2]);
const lines = fs.readFileSync(process.argv[3], 'utf8').split('\n').filter((l) => l.trim());
lines.forEach((line, i) => {
  let err = '';
  processInput(line, process.env, { write: (s) => { err += s; } });
  if (err.trim()) {
    process.stderr.write(`event ${i + 1}: ${err.trim()}\n`);
    process.exit(1);
  }
});
