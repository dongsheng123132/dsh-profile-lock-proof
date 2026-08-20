import { access, readFile } from 'node:fs/promises'
const required = ['.codex-plugin/plugin.json', '.mcp.json', 'mcp-server.mjs', 'bin/dsh-profile-lock-proof.mjs', 'cordis.patch.yml', 'index.js', 'lib/profile-lock-proof.mjs', 'README.md', 'README.zh-CN.md', 'SECURITY.md', 'test/stock-web-loader-smoke.mjs']
await Promise.all(required.map((file) => access(file)))
const pkg = JSON.parse(await readFile('package.json', 'utf8')); const plugin = JSON.parse(await readFile('.codex-plugin/plugin.json', 'utf8')); const mcp = JSON.parse(await readFile('.mcp.json', 'utf8'))
if (pkg.name !== plugin.name || pkg.version !== plugin.version || plugin.mcpServers !== './.mcp.json') throw new Error('package/plugin identity or MCP path mismatch')
if (!mcp.mcpServers?.['dsh-profile-lock-proof']) throw new Error('MCP declaration missing')
if (['preinstall', 'install', 'postinstall', 'prepare'].some((name) => pkg.scripts?.[name])) throw new Error('lifecycle scripts are forbidden')
const index = await readFile('index.js', 'utf8'); const core = await readFile('lib/profile-lock-proof.mjs', 'utf8'); const server = await readFile('mcp-server.mjs', 'utf8')
if (/export\s+default\b/.test(index)) throw new Error('default export is forbidden: stock DSH Loader must receive namespace inject metadata')
if (index.includes('@deepseek-ai/dsh-tools')) throw new Error('plugin entry must not bundle a second DSH runtime')
for (const guard of ['verifiedByReadBack', 'returnsSourceContents', 'FORBIDDEN_FIELD', 'escapes workspaceRoot', 'regular non-symlink file']) if (!core.includes(guard)) throw new Error(`guard missing: ${guard}`)
for (const shared of ['inspectProfileLockProofManifestJson', 'verifyProfileLockProofInline']) if (!server.includes(shared)) throw new Error(`MCP must use shared proof core ${shared}`)
process.stdout.write(`${JSON.stringify({ ok: true, requiredFiles: required.length, lifecycleScripts: false, mcp: true, namespaceLoaderSafe: true, hostNeutralTools: true, proofOnlyMcp: true })}\n`)
