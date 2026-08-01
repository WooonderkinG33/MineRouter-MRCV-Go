#!/bin/sh
# Cross-compatibility check: Go creates a vault, Node.js reads it back.
# Run from the repo root. Requires Node.js and @minerouter/mrcv installed.
set -e
cd "$(dirname "$0")/.."

echo "1) Go creates a vault..."
go run ./scripts/gomake

echo "2) Node.js reads it back..."
node --input-type=module -e "
import { Vault } from '@minerouter/mrcv'
const v = new Vault({
  path: 'testdata/go-vault.mrcv',
  bindingSources: [{ name: 'test', getter: () => 'devA' }],
  mode: 'bound',
})
const res = await v.tryOpen()
if (res.state !== 'unlocked') throw new Error('Go->JS mismatch: ' + JSON.stringify(res))
await v.unlock()
if (v.get('greeting') !== 'hello-from-go') throw new Error('greeting mismatch: ' + v.get('greeting'))
if (v.get('answer') !== 7) throw new Error('answer mismatch: ' + v.get('answer'))
console.log('Go -> JS OK: greeting=' + v.get('greeting') + ' answer=' + v.get('answer'))
"
echo "CROSS CHECK PASSED"
