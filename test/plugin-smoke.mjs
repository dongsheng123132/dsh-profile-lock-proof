import assert from 'node:assert/strict'
import * as plugin from '../index.js'
assert.equal('default' in plugin, false); assert.equal(plugin.name, 'dsh-profile-lock-proof'); assert.deepEqual(plugin.inject, ['tools'])
const definitions = plugin.createDefinitions(null, { workspaceRoot: process.cwd() }); assert.deepEqual(definitions.map(({ name }) => name), ['dsh_profile_lock_inspect', 'dsh_profile_lock_verify']); process.stdout.write(`${JSON.stringify({ ok: true, namespaceLoaderSafe: true, tools: definitions.map(({ name }) => name) })}\n`)
