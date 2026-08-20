import { inspectProfileLockProof, verifyProfileLockProof } from './lib/profile-lock-proof.mjs'
export const name = 'dsh-profile-lock-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const base = (config, args) => ({ workspaceRoot: config.workspaceRoot ?? process.cwd(), manifestPath: args.manifestPath, artifactDir: args.artifactDir })
const defineJsonTool = ({ name, description, parameters, execute }) => ({
  name, description,
  parameters: { type: 'object', properties: Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, { type: 'string', description: value.description }])), required: Object.entries(parameters).filter(([, value]) => value.required).map(([key]) => key), additionalProperties: false },
  output: { schema: {}, render: renderJson },
  execute(args) { for (const [key, value] of Object.entries(parameters)) if (value.required && (typeof args?.[key] !== 'string' || args[key].length === 0)) throw new TypeError(`${key} must be a non-empty string`); return execute(args) }
})
export function createDefinitions(_ctx, config = {}) { return [
  defineJsonTool({ name: 'dsh_profile_lock_inspect', description: 'Inspect immutable DSH profile-lock proof identities without returning manifests, lockfiles or source.', parameters: { manifestPath: { required: true, description: 'Proof manifest relative to workspaceRoot.' } }, execute(args) { return inspectProfileLockProof(base(config, args)) } }),
  defineJsonTool({ name: 'dsh_profile_lock_verify', description: 'Verify declared, locked and installed DSH bundle closure and emit a content-addressed proof.', parameters: { manifestPath: { required: true, description: 'Proof manifest relative to workspaceRoot.' }, artifactDir: { required: true, description: 'Only report directory that may be written, relative to workspaceRoot.' } }, execute(args) { return verifyProfileLockProof(base(config, args)) } })
] }
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
