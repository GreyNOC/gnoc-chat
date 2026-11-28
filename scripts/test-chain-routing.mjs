// Routing regression for the non-EVM language specialists (starknet-cairo / algorand-avm).
// Extracts the REAL CLASS_AGENT table from hunt-cycle.js and replays the matcher, so it tests
// the live data, not a copy. Asserts: chain leads win over bare vuln-class words, and the new
// keys steal no existing web/EVM lead. Run: node scripts/test-chain-routing.mjs
import { readFileSync } from 'node:fs'
const src = readFileSync(new URL('../.claude/workflows/hunt-cycle.js', import.meta.url), 'utf8')
const m = src.match(/const CLASS_AGENT = (\[[\s\S]*?\n\])\n/)
if (!m) { console.error('FAIL: could not extract CLASS_AGENT'); process.exit(1) }
const CLASS_AGENT = eval(m[1]) // ponytail: eval a literal array we just read from our own repo file
const route = (cls) => {
  const c = String(cls || '').toLowerCase()
  for (const [keys, name] of CLASS_AGENT) if (keys.some((k) => c.includes(k))) return name
  return 'bb-researcher'
}
const eq = [
  // chain-language beats bare vuln-class (the reposition's whole point)
  ['cairo reentrancy', 'starknet-cairo-hunter'],
  ['starknet l1_handler missing from_address', 'starknet-cairo-hunter'],
  ['felt252 overflow mint', 'starknet-cairo-hunter'],
  ['zklend accumulator rounding', 'starknet-cairo-hunter'],
  ['algorand rekey-to takeover', 'algorand-avm-hunter'],
  ['logicsig close-remainder drain', 'algorand-avm-hunter'],
  ['oncompletion updateapplication unguarded', 'algorand-avm-hunter'],
  ['tinyman swap rounding', 'algorand-avm-hunter'],
  // existing leads unchanged (no theft by the new rows)
  ['reentrancy', 'evm-execution-hunter'],
  ['oracle manipulation twap', 'oracle-hunter'],
  ['bridge layerzero dvn', 'bridge-xchain-hunter'],
  ['approve-race', 'token-standard-hunter'],
  ['xss dom-xss sink', 'xss-hunter'],
  ['onchain substrate pallet', 'onchain-hunter'],
]
const notEq = [
  // substring-collision guards: these must NOT hit the new agents
  ['credential steal flow', 'algorand-avm-hunter'],   // 'steal' contains 'teal' - we dropped bare 'teal'
  ['session rekey token', 'algorand-avm-hunter'],     // bare 'rekey' - we use 'rekey-to'
  ['storage class confusion', 'starknet-cairo-hunter'], // 'class' - we use full 'replace_class'
  ['avm bytecode', 'algorand-avm-hunter'],            // bare 'avm' dropped; needs 'algorand-avm' or 'algorand'
]
let fail = 0
for (const [inp, want] of eq) {
  const got = route(inp)
  if (got !== want) { console.error(`FAIL route(${JSON.stringify(inp)}) = ${got}, want ${want}`); fail++ }
}
for (const [inp, banned] of notEq) {
  const got = route(inp)
  if (got === banned) { console.error(`FAIL route(${JSON.stringify(inp)}) = ${got}, must NOT be ${banned}`); fail++ }
}
if (fail) { console.error(`\n${fail} routing assertion(s) failed`); process.exit(1) }
console.log(`routing OK: ${eq.length + notEq.length} assertions pass`)
