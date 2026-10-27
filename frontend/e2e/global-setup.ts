import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FullConfig } from '@playwright/test';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const pythonHarness = resolve(repoRoot, 'tests/browser/serve.py');
const children: ChildProcess[] = [];
let dataRoot = '';
const DIAGNOSTIC_LIMIT = 4_000;
const STARTUP_TIMEOUT_MS = 120_000;

interface TestCredentials {
  username: string;
  password: string;
}

function appendBounded(current: string, chunk: string): string {
  return (current + chunk).slice(-DIAGNOSTIC_LIMIT);
}

async function stopOwned(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  if (process.platform === 'win32' && child.pid) {
    // `py.exe` may launch a separate python.exe; terminate only this fixture's process tree.
    const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
      stdio: 'ignore', windowsHide: true,
    });
    await new Promise<void>((resolvePromise) => killer.once('exit', () => resolvePromise()));
  } else {
    child.kill('SIGTERM');
  }
  if (child.exitCode === null) {
    await Promise.race([
      new Promise<void>((resolvePromise) => child.once('exit', () => resolvePromise())),
      new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 5_000)),
    ]);
  }
  if (child.exitCode === null && process.platform !== 'win32') child.kill('SIGKILL');
}

function makeCredentials(): TestCredentials {
  return {
    username: `browser-${randomBytes(4).toString('hex')}`,
    password: randomBytes(24).toString('base64url'),
  };
}

async function start(
  ttl: number,
  credentials: TestCredentials,
  holdScanUntilExpiry = false,
): Promise<{ url: string; username: string; password: string }> {
  const directory = resolve(dataRoot, `ttl-${ttl}`);
  const python = process.env.CHINESCAN_PYTHON ?? (process.platform === 'win32' ? 'py' : 'python3.12');
  const pythonArgs = process.env.CHINESCAN_PYTHON
    ? []
    : process.platform === 'win32' ? ['-3.12'] : [];
  const args = [...pythonArgs, pythonHarness, '--data-dir', directory, '--ttl', String(ttl)];
  if (holdScanUntilExpiry) args.push('--hold-scan-until-expiry');
  const child = spawn(python, args, {
    cwd: repoRoot,
    env: {
      ...process.env,
      PYTHONPATH: [
        repoRoot,
        ...(process.platform === 'win32' && !process.env.CHINESCAN_PYTHON
          ? [resolve(repoRoot, '.venv/Lib/site-packages')]
          : []),
        process.env.PYTHONPATH,
      ].filter(Boolean).join(delimiter),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  children.push(child);
  let stdout = '';
  let stderr = '';
  let credentialsPipeFailed = false;
  child.stdout?.setEncoding('utf8');
  child.stderr?.setEncoding('utf8');
  child.stdout?.on('data', (chunk: string) => { stdout = appendBounded(stdout, chunk); });
  child.stderr?.on('data', (chunk: string) => { stderr = appendBounded(stderr, chunk); });
  try {
    if (!child.stdin) throw new Error('Dashboard fixture credential pipe is unavailable.');
    child.stdin.on('error', () => { credentialsPipeFailed = true; });
    child.stdin.end(`${JSON.stringify(credentials)}\n`);
    const startedAt = Date.now();
    const deadline = startedAt + STARTUP_TIMEOUT_MS;
    let endpoint: { url: string } | undefined;
    while (Date.now() < deadline && !endpoint) {
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error(`Dashboard fixture exited early (code=${child.exitCode}, signal=${child.signalCode}).`);
      }
      if (credentialsPipeFailed) throw new Error('Dashboard fixture could not receive test credentials.');
      const lineEnd = stdout.indexOf('\n');
      if (lineEnd >= 0) endpoint = JSON.parse(stdout.slice(0, lineEnd)) as typeof endpoint;
      else await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    if (!endpoint) {
      const lineEnd = stdout.indexOf('\n');
      if (lineEnd >= 0) endpoint = JSON.parse(stdout.slice(0, lineEnd)) as typeof endpoint;
    }
    if (!endpoint) {
      throw new Error(`Dashboard fixture did not announce a listening URL within ${STARTUP_TIMEOUT_MS / 1000} seconds (elapsed ${((Date.now() - startedAt) / 1000).toFixed(1)}s).`);
    }

    // The child prints only the URL. Require HTTP readiness before sharing credentials with tests.
    const readyDeadline = Date.now() + 10_000;
    while (Date.now() < readyDeadline) {
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error(`Dashboard fixture exited before HTTP readiness (code=${child.exitCode}).`);
      }
      try {
        const response = await fetch(`${endpoint.url}/api/auth/session`, { signal: AbortSignal.timeout(1_000) });
        if (response.status === 401) return { ...endpoint, ...credentials };
      } catch { /* Continue until the bounded readiness deadline. */ }
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    throw new Error('Dashboard fixture announced a URL but did not become HTTP-ready within 10 seconds.');
  } catch (error) {
    await stopOwned(child);
    throw new Error(`${String(error)}\nFixture stderr (last ${DIAGNOSTIC_LIMIT} chars):\n${stderr}`);
  }
}

export default async function globalSetup(_config: FullConfig) {
  dataRoot = await mkdtemp(resolve(tmpdir(), 'chinescan-playwright-'));
  try {
    const urls = {
      standard: await start(1800, makeCredentials()),
      expiry: await start(15, makeCredentials(), true),
    };
    process.env.CHINESCAN_BROWSER_TEST_URLS = JSON.stringify(urls);
  } catch (error) {
    await Promise.all(children.map(stopOwned));
    await rm(dataRoot, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    throw error;
  }
  return async () => {
    await Promise.all(children.map(stopOwned));
    delete process.env.CHINESCAN_BROWSER_TEST_URLS;
    await rm(dataRoot, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
  };
}
