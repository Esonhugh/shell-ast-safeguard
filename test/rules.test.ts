import { describe, expect, test } from 'bun:test'
import { decide, scan } from '../src/index.ts'

const behavior = async (source: string, rules: Parameters<typeof decide>[1]) => decide(await scan(source), rules).behavior

describe('no over-blocking', () => {
  for (const source of [
    'echo touch',
    'git commit -m "touch me"',
    'grep -rn touch .',
    'cat touch.txt',
    'command -v touch',
    "echo 'bash -c touch'",
  ]) {
    test(source, async () => expect(await behavior(source, { deny: ['touch:*'] })).toBe('passthrough'))
  }
})

describe('rule forms', () => {
  test('multi-word prefix sees through path and wrappers', async () => {
    expect(await behavior('sudo /usr/bin/git push origin', { deny: ['git push:*'] })).toBe('deny')
    expect(await behavior('git -C . push', { deny: ['git push:*'] })).toBe('passthrough')
  })
  test('exact rule needs the exact line and no expansions', async () => {
    expect(await behavior('rm -rf /', { deny: ['rm -rf /'] })).toBe('deny')
    expect(await behavior('rm -rf / x', { deny: ['rm -rf /'] })).toBe('passthrough')
  })
  test('wildcard with trailing space-star also matches no arguments', async () => {
    expect(await behavior('npm run', { allow: ['npm run *'] })).toBe('allow')
    expect(await behavior('npm run build --x', { allow: ['npm run *'] })).toBe('allow')
    expect(await behavior('npm runx', { allow: ['npm run *'] })).toBe('passthrough')
  })
  test('deny wins over ask, ask over allow', async () => {
    const rules = { deny: ['rm:*'], ask: ['git:*'], allow: ['git:*', 'rm:*'] }
    expect(await behavior('git status; rm x', rules)).toBe('deny')
    expect(await behavior('git status', rules)).toBe('ask')
  })
})

describe('allow', () => {
  test('every command must be allowed', async () => {
    expect(await behavior('ls && touch a', { allow: ['ls:*'] })).toBe('passthrough')
    expect(await behavior('ls && touch a', { allow: ['ls:*', 'touch:*'] })).toBe('allow')
  })
  test('nested commands count', async () => {
    expect(await behavior('echo $(rm -rf x)', { allow: ['echo:*'] })).toBe('passthrough')
  })
  test('privilege wrappers and loader variables are not covered', async () => {
    expect(await behavior('sudo touch a', { allow: ['touch:*'] })).toBe('passthrough')
    expect(await behavior('LD_PRELOAD=/tmp/x.so touch a', { allow: ['touch:*'] })).toBe('passthrough')
    expect(await behavior('env PATH=/tmp touch a', { allow: ['touch:*'] })).toBe('passthrough')
    expect(await behavior('timeout 5 touch a', { allow: ['touch:*'] })).toBe('allow')
  })
  test('unseen code is never allowed', async () => {
    expect(await behavior("bash -c \"$X\"", { allow: ['bash:*'] })).toBe('passthrough')
    expect(await behavior('echo hi | bash', { allow: ['echo:*', 'bash:*'] })).toBe('passthrough')
  })
})

describe('unseen code', () => {
  test('asks by default when guard rules exist', async () => {
    const result = await scan('bash -c "$CMD"')
    expect(result.opaque).toEqual([{ kind: 'shell-c', text: 'bash -c "$CMD"' }])
    expect(decide(result, { deny: ['rm:*'] })).toMatchObject({ behavior: 'ask', reason: 'unseen' })
    expect(decide(result, { deny: ['rm:*'] }, { unseen: 'ignore' }).behavior).toBe('passthrough')
  })
  test('parse errors are unseen', async () => {
    const result = await scan('echo $(')
    expect(result.parseError).toBe(true)
    expect(decide(result, { deny: ['rm:*'] }).behavior).toBe('ask')
  })
  test('nested payloads are read to a depth limit', async () => {
    const result = await scan(`bash -c "sh -c 'eval rm x'"`)
    expect(result.commands.map(c => [c.program, c.origin])).toEqual([
      ['bash', 'script'],
      ['sh', 'shell-c'],
      ['eval', 'shell-c'],
      ['rm', 'eval'],
    ])
    expect((await scan(`bash -c "sh -c 'rm x'"`, { maxDepth: 1 })).opaque[0]?.kind).toBe('shell-c')
  })
  test('env -S runs its split string', async () => {
    expect(await behavior("env -S 'touch a'", { deny: ['touch:*'] })).toBe('deny')
    expect(await behavior('env --split-string="touch a"', { deny: ['touch:*'] })).toBe('deny')
  })
  test('stdin scripts are unseen', async () => {
    expect((await scan('bash < script.sh')).opaque[0]?.kind).toBe('shell-stdin')
    expect((await scan('bash <<EOF\nrm x\nEOF')).opaque[0]?.kind).toBe('shell-stdin')
  })
  test('script files are unseen', async () => {
    expect((await scan('bash ./deploy.sh')).opaque[0]?.kind).toBe('script-file')
    expect((await scan('. ./env.sh')).opaque[0]?.kind).toBe('script-file')
  })
})

test('command shape', async () => {
  const { commands } = await scan('FOO=1 sudo -u root env BAR=2 timeout -s KILL 5 /bin/rm -rf "$HOME/x"')
  expect(commands).toEqual([
    {
      text: 'FOO=1 sudo -u root env BAR=2 timeout -s KILL 5 /bin/rm -rf "$HOME/x"',
      program: 'rm',
      argv: ['rm', '-rf', '$HOME/x'],
      wrappers: ['sudo', 'env', 'timeout'],
      assignments: ['FOO=1', 'BAR=2'],
      dynamic: true,
      origin: 'script',
    },
  ])
})
