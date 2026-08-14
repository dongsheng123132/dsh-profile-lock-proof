import { defineTool } from '@deepseek-ai/dsh-tools'
import { inspectProfileLockProof, verifyProfileLockProof } from './lib/profile-lock-proof.mjs'
export const name = 'dsh-profile-lock-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const base = (config, args) => ({ workspaceRoot: config.workspaceRoot ?? process.cwd(), manifestPath: args.manifestPath, artifactDir: args.artifactDir })
export function createDefinitions(_ctx, config = {}) { return [
  defineTool({ name: 'dsh_profile_lock_inspect', description: 'Inspect immutable DSH profile-lock proof identities without returning manifests, lockfiles or source.', parameters: { manifestPath: { type: 'string', required: true } }, output: { schema: { type: 'json' }, render: renderJson }, execute(args) { return inspectProfileLockProof(base(config, args)) } }),
  defineTool({ name: 'dsh_profile_lock_verify', description: 'Verify declared, locked and installed DSH bundle closure and emit a content-addressed proof.', parameters: { manifestPath: { type: 'string', required: true }, artifactDir: { type: 'string', required: true } }, output: { schema: { type: 'json' }, render: renderJson }, execute(args) { return verifyProfileLockProof(base(config, args)) } })
] }
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
export default apply
