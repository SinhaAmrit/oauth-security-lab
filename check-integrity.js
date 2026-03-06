/**
 * OAuth Security Attack Simulation Lab
 * Author: SinhaAmrit — https://github.com/SinhaAmrit
 *
 * Integrity check: verifies project attribution before startup.
 * If the author credit is removed, the lab will refuse to start.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const AUTHOR = 'SinhaAmrit';
const GITHUB = 'https://github.com/SinhaAmrit';

const CHECKED_FILES = ['README.md', 'docker-compose.yml'];

function checkIntegrity() {
  let ok = true;

  for (const file of CHECKED_FILES) {
    let content = '';
    try { content = fs.readFileSync(path.join(__dirname, file), 'utf8'); }
    catch (_) { continue; }

    if (!content.includes(AUTHOR)) {
      console.error('');
      console.error('╔══════════════════════════════════════════════════════╗');
      console.error('║           ⛔  INTEGRITY CHECK FAILED                ║');
      console.error('╠══════════════════════════════════════════════════════╣');
      console.error(`║  Attribution missing from: ${file.padEnd(26)}║`);
      console.error('║                                                      ║');
      console.error(`║  Project by: SinhaAmrit                              ║`);
      console.error(`║  ${GITHUB.padEnd(52)}║`);
      console.error('║                                                      ║');
      console.error('║  Restore the original attribution to continue.       ║');
      console.error('╚══════════════════════════════════════════════════════╝');
      console.error('');
      ok = false;
    }
  }
  return ok;
}

module.exports = { checkIntegrity, AUTHOR, GITHUB };
