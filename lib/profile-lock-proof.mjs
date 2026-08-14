import { createHash, randomUUID } from 'node:crypto'
import { link, lstat, mkdir, readFile, realpath, unlink, writeFile } from 'node:fs/promises'
import path from 'node:path'
import YAML from 'yaml'

const MAX_BYTES = 4_194_304
const MAX_PACKAGES = 200
const ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/
const PACKAGE = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/
const HASH = /^[a-f0-9]{64}$/
const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const GITHUB_COMMIT = /^github:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+#[a-f0-9]{40}$/
const FORBIDDEN_KEY = /(authorization|api.?key|secret|token|password|credential|cookie|private.?key|stdout|stderr|raw.?content|prompt|message)/i
const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare']
const sha = (value) => createHash('sha256').update(value).digest('hex')
const stable = (value) => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value
const stableJson = (value) => `${JSON.stringify(stable(value), null, 2)}\n`

export class ProfileLockProofError extends Error { constructor(code, message) { super(message); this.name = 'ProfileLockProofError'; this.code = code } }
function object(value, label) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ProfileLockProofError('INVALID_SCHEMA', `${label} must be an object`) }
function safeManifest(value, at = '$', counter = { value: 0 }) {
  counter.value += 1; if (counter.value > 20_000) throw new ProfileLockProofError('INPUT_TOO_COMPLEX', 'manifest exceeds 20000 nodes')
  if (typeof value === 'string' && value.length > 2048) throw new ProfileLockProofError('VALUE_TOO_LARGE', `string at ${at} is too large`)
  if (Array.isArray(value)) { value.forEach((item, i) => safeManifest(item, `${at}[${i}]`, counter)); return }
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) { if (FORBIDDEN_KEY.test(key)) throw new ProfileLockProofError('FORBIDDEN_FIELD', `secret or raw-output shaped field at ${at}.${key}`); safeManifest(child, `${at}.${key}`, counter) }
}
async function rootDirectory(value) { const root = await realpath(value); const info = await lstat(root); if (!info.isDirectory() || info.isSymbolicLink()) throw new ProfileLockProofError('UNSAFE_PATH', 'workspaceRoot must be a real directory'); return root }
async function safeFile(rootValue, relativePath, label, optional = false) {
  if (typeof relativePath !== 'string' || !relativePath || path.isAbsolute(relativePath)) throw new ProfileLockProofError('UNSAFE_PATH', `${label} must be workspace-relative`)
  const root = await rootDirectory(rootValue); const target = path.resolve(root, relativePath); const rel = path.relative(root, target)
  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new ProfileLockProofError('UNSAFE_PATH', `${label} escapes workspaceRoot`)
  let info; try { info = await lstat(target) } catch (error) { if (optional && error.code === 'ENOENT') return { root, target, missing: true }; throw error }
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_BYTES) throw new ProfileLockProofError('UNSAFE_PATH', `${label} must be a regular non-symlink file no larger than ${MAX_BYTES} bytes`)
  const resolved = await realpath(target); const resolvedRel = path.relative(root, resolved); if (resolvedRel.startsWith('..') || path.isAbsolute(resolvedRel)) throw new ProfileLockProofError('UNSAFE_PATH', `${label} resolves outside workspaceRoot`)
  return { root, target: resolved, missing: false }
}
async function artifactDirectory(rootValue, relativePath) {
  if (typeof relativePath !== 'string' || !relativePath || path.isAbsolute(relativePath)) throw new ProfileLockProofError('UNSAFE_PATH', 'artifactDir must be workspace-relative')
  const root = await rootDirectory(rootValue); const target = path.resolve(root, relativePath); const rel = path.relative(root, target); if (rel.startsWith('..') || path.isAbsolute(rel)) throw new ProfileLockProofError('UNSAFE_PATH', 'artifactDir escapes workspaceRoot')
  await mkdir(target, { recursive: true }); const info = await lstat(target); if (!info.isDirectory() || info.isSymbolicLink()) throw new ProfileLockProofError('UNSAFE_PATH', 'artifactDir must be a real directory')
  const resolved = await realpath(target); const resolvedRel = path.relative(root, resolved); if (resolvedRel.startsWith('..') || path.isAbsolute(resolvedRel)) throw new ProfileLockProofError('UNSAFE_PATH', 'artifactDir resolves outside workspaceRoot')
  return { root, target: resolved }
}
function immutableSpecifier(value) { if (EXACT_SEMVER.test(value)) return 'exact-semver'; if (GITHUB_COMMIT.test(value)) return 'github-commit'; return null }
function validateManifest(value) {
  object(value, 'manifest'); safeManifest(value)
  if (value.schemaVersion !== 1 || !ID.test(value.proofId)) throw new ProfileLockProofError('INVALID_SCHEMA', 'schemaVersion must be 1 and proofId must be stable')
  object(value.profile, 'profile'); object(value.lockfile, 'lockfile')
  for (const [label, item] of [['profile', value.profile], ['lockfile', value.lockfile]]) if (typeof item.path !== 'string' || !HASH.test(item.sha256)) throw new ProfileLockProofError('INVALID_SCHEMA', `${label} path or sha256 is invalid`)
  if (typeof value.lockfile.importer !== 'string' || !value.lockfile.importer || value.lockfile.importer.length > 256) throw new ProfileLockProofError('INVALID_SCHEMA', 'lockfile importer is invalid')
  if (!Array.isArray(value.packages) || !value.packages.length || value.packages.length > MAX_PACKAGES) throw new ProfileLockProofError('INVALID_SCHEMA', `packages must contain 1-${MAX_PACKAGES} entries`)
  const ids = new Set(); const names = new Set()
  for (const [i, item] of value.packages.entries()) {
    object(item, `packages[${i}]`)
    if (!ID.test(item.id) || ids.has(item.id) || !PACKAGE.test(item.name) || names.has(item.name) || !immutableSpecifier(item.expectedSpecifier) || typeof item.installedManifestPath !== 'string' || !HASH.test(item.installedManifestSha256) || typeof item.expectedVersion !== 'string' || !EXACT_SEMVER.test(item.expectedVersion) || typeof item.patchPath !== 'string' || !HASH.test(item.patchSha256)) throw new ProfileLockProofError('INVALID_SCHEMA', `packages[${i}] identity, immutable specifier, version, paths or hashes are invalid`)
    ids.add(item.id); names.add(item.name)
  }
  return value
}
async function readPinned(root, item, label, parser) {
  const located = await safeFile(root, item.path, `${label}.path`, true); if (located.missing) return { status: 'missing', expectedSha256: item.sha256, actualSha256: null }
  const bytes = await readFile(located.target); const actualSha256 = sha(bytes); let value
  try { value = parser(bytes.toString('utf8')) } catch { return { status: 'invalid', expectedSha256: item.sha256, actualSha256 } }
  return { status: actualSha256 === item.sha256 ? 'current' : 'stale', expectedSha256: item.sha256, actualSha256, value }
}
async function load(root, manifestPath) {
  const { target } = await safeFile(root, manifestPath, 'manifestPath'); const bytes = await readFile(target); let value
  try { value = validateManifest(JSON.parse(bytes.toString('utf8'))) } catch (error) { if (error instanceof ProfileLockProofError) throw error; throw new ProfileLockProofError('INVALID_JSON', 'manifestPath is not valid JSON') }
  return { manifest: value, manifestSha256: sha(bytes) }
}
function lockEntry(lock, importer, name) { return lock?.importers?.[importer]?.dependencies?.[name] ?? lock?.importers?.[importer]?.devDependencies?.[name] ?? lock?.importers?.[importer]?.optionalDependencies?.[name] }
async function evaluatePackage(root, item, profile, lock, importer) {
  const declared = profile?.dependencies?.[item.name] ?? profile?.devDependencies?.[item.name] ?? profile?.optionalDependencies?.[item.name]
  const locked = lockEntry(lock, importer, item.name)
  const lockSpecifier = typeof locked === 'string' ? locked : locked?.specifier
  const installed = await readPinned(root, { path: item.installedManifestPath, sha256: item.installedManifestSha256 }, `${item.id}.installedManifest`, JSON.parse)
  let patch = { status: 'unchecked', expectedSha256: item.patchSha256, actualSha256: null }; let installedIdentity = 'unknown'; let installedVersion = null; let lifecycleScripts = []
  if (installed.value) {
    installedIdentity = installed.value.name === item.name ? 'matched' : 'mismatched'; installedVersion = typeof installed.value.version === 'string' ? installed.value.version : null
    lifecycleScripts = LIFECYCLE.filter((name) => typeof installed.value.scripts?.[name] === 'string')
    const declaredPatch = installed.value.dsh?.bundle?.patch; if (declaredPatch !== item.patchPath) patch = { status: 'path-mismatch', expectedSha256: item.patchSha256, actualSha256: null }
    else { const found = await safeFile(root, path.posix.join(path.posix.dirname(item.installedManifestPath.replaceAll('\\', '/')), item.patchPath), `${item.id}.patch`, true); if (found.missing) patch = { status: 'missing', expectedSha256: item.patchSha256, actualSha256: null }; else { const bytes = await readFile(found.target); const actualSha256 = sha(bytes); patch = { status: actualSha256 === item.patchSha256 ? 'current' : 'stale', expectedSha256: item.patchSha256, actualSha256 } } }
  }
  const checks = { declaration: declared === item.expectedSpecifier ? 'matched' : declared === undefined ? 'missing' : 'mismatched', lockSpecifier: lockSpecifier === item.expectedSpecifier ? 'matched' : lockSpecifier === undefined ? 'missing' : 'mismatched', immutable: immutableSpecifier(item.expectedSpecifier) ? 'yes' : 'no', installedManifest: installed.status, installedIdentity, installedVersion: installedVersion === item.expectedVersion ? 'matched' : installedVersion === null ? 'missing' : 'mismatched', patch: patch.status, lifecycleScripts: lifecycleScripts.length ? 'present' : 'absent' }
  const pass = Object.values(checks).every((status) => ['matched', 'yes', 'current', 'absent'].includes(status))
  return { id: item.id, name: item.name, specifierKind: immutableSpecifier(item.expectedSpecifier), expectedSpecifierSha256: sha(item.expectedSpecifier), expectedVersion: item.expectedVersion, checks, lifecycleScriptNames: lifecycleScripts, installedManifest: { expectedSha256: item.installedManifestSha256, actualSha256: installed.actualSha256 }, patch, verdict: pass ? 'pass' : 'fail' }
}
async function writeReport(rootValue, artifactDir, report) {
  const { root, target: directory } = await artifactDirectory(rootValue, artifactDir); const body = stableJson(report); const reportSha256 = sha(body); const filename = `profile-lock-proof-${reportSha256}.json`; const target = path.join(directory, filename); const temporary = path.join(directory, `.${filename}.${randomUUID()}.tmp`)
  try { await writeFile(temporary, body, { encoding: 'utf8', flag: 'wx' }); try { await link(temporary, target) } catch (error) { if (error.code !== 'EEXIST') throw error }; const reread = await readFile(target, 'utf8'); if (reread !== body || sha(reread) !== reportSha256) throw new ProfileLockProofError('WRITE_VERIFY_FAILED', 'proof read-back verification failed'); return { path: path.relative(root, target).replaceAll(path.sep, '/'), sha256: reportSha256 } } finally { try { await unlink(temporary) } catch {} }
}
export async function inspectProfileLockProof({ workspaceRoot: root = process.cwd(), manifestPath }) {
  const { manifest, manifestSha256 } = await load(root, manifestPath)
  return { schemaVersion: 1, operation: 'inspect', returnsSourceContents: false, proofId: manifest.proofId, manifestSha256, profile: { expectedSha256: manifest.profile.sha256 }, lockfile: { importer: manifest.lockfile.importer, expectedSha256: manifest.lockfile.sha256 }, packages: manifest.packages.map((item) => ({ id: item.id, name: item.name, specifierKind: immutableSpecifier(item.expectedSpecifier), expectedSpecifierSha256: sha(item.expectedSpecifier), expectedVersion: item.expectedVersion })) }
}
export async function verifyProfileLockProof({ workspaceRoot: root = process.cwd(), manifestPath, artifactDir }) {
  const { manifest, manifestSha256 } = await load(root, manifestPath)
  const profile = await readPinned(root, manifest.profile, 'profile', JSON.parse); const lockfile = await readPinned(root, manifest.lockfile, 'lockfile', YAML.parse)
  const packages = []
  if (profile.value && lockfile.value) for (const item of manifest.packages) packages.push(await evaluatePackage(root, item, profile.value, lockfile.value, manifest.lockfile.importer))
  const failedPackageIds = packages.filter(({ verdict }) => verdict === 'fail').map(({ id }) => id); const inputFailures = [profile.status, lockfile.status].some((status) => status !== 'current'); const pass = !inputFailures && packages.length === manifest.packages.length && !failedPackageIds.length
  const report = { schemaVersion: 1, operation: 'verify', returnsSourceContents: false, proofId: manifest.proofId, manifestSha256, status: pass ? 'verified' : 'failed', verdict: pass ? 'pass' : 'fail', inputs: { profile: { status: profile.status, expectedSha256: profile.expectedSha256, actualSha256: profile.actualSha256 }, lockfile: { status: lockfile.status, importer: manifest.lockfile.importer, expectedSha256: lockfile.expectedSha256, actualSha256: lockfile.actualSha256 } }, packages, disclosure: { failedPackageIds, missingInputs: Object.entries({ profile: profile.status, lockfile: lockfile.status }).filter(([, status]) => status === 'missing').map(([name]) => name), staleInputs: Object.entries({ profile: profile.status, lockfile: lockfile.status }).filter(([, status]) => status === 'stale').map(([name]) => name), invalidInputs: Object.entries({ profile: profile.status, lockfile: lockfile.status }).filter(([, status]) => status === 'invalid').map(([name]) => name) } }
  const artifact = await writeReport(root, artifactDir, report); return { ...report, artifact }
}
