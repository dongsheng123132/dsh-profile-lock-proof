import assert from 'node:assert/strict'
import { createDefinitions } from '../index.js'
const definitions = createDefinitions(null, { workspaceRoot: process.cwd() }); assert.deepEqual(definitions.map(({ name }) => name), ['dsh_profile_lock_inspect', 'dsh_profile_lock_verify']); process.stdout.write(`${JSON.stringify({ ok: true, tools: definitions.map(({ name }) => name) })}\n`)
