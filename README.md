# shell-ast-safeguard

List every command a bash string would run, normalized so that permission rules
like `deny rm:*` cannot be dodged by `/bin/rm`, `$(rm …)`, `sudo timeout 5 rm`,
`bash -c 'rm …'` or `find -exec rm`. Built for coding agents that gate shell
commands behind allow / ask / deny rules.

Status: prototype, not published to npm.

```ts
import { scan, decide } from 'shell-ast-safeguard'

const result = await scan(`FOO=1 sudo timeout 5 /bin/rm -rf "$HOME/x"; bash -c 'touch y'`)
result.commands
// [{ program: 'rm', argv: ['rm', '-rf', '$HOME/x'], wrappers: ['sudo', 'timeout'],
//    assignments: ['FOO=1'], dynamic: true, origin: 'script', text: '…' },
//  { program: 'bash', … },
//  { program: 'touch', argv: ['touch', 'y'], origin: 'shell-c', … }]

decide(result, { deny: ['touch:*'], allow: ['rm:*'] })
// { behavior: 'deny', reason: 'rule', rule: 'touch:*', command: { … } }
```

## What it finds

Every simple command anywhere in the script: pipelines, `&&` `||` `;` `&`,
`$(…)` and backticks (also inside strings and heredocs), `( … )`, `{ …; }`,
`<( … )` `>( … )`, `if` / `for` / `while` / `until` / `case` bodies, function
bodies, `declare` / `export` / `local`.

For each one:

- `program` is the basename of the real program (`/usr/bin/git` → `git`), with
  quotes and escapes resolved (`"touch"`, `to''uch`, `\touch`, `$'…'`).
- Wrappers are stripped with their options and recorded in `wrappers`: `env`,
  `timeout`, `nice`, `nohup`, `time`, `command`, `builtin`, `exec`, `noglob`,
  `stdbuf`, `sudo`, `doas`, `ionice`, `setsid`, `coproc`, `busybox`.
  `command -v x` runs nothing and is not unwrapped.
- Leading `NAME=value` words (and `env NAME=value`) go to `assignments`.
- `xargs [opts] cmd` and `find … -exec cmd … ;` yield `cmd` as its own command.
- Literal code handed to another interpreter is parsed and scanned too:
  `bash -c '…'` (any of sh, bash, zsh, dash, ksh), `bash <<< '…'`,
  `source /dev/stdin <<< '…'`, `eval …`, `trap '…' SIG`.

## What it cannot see

When code reaches an interpreter in a form that is not in the string itself,
the place is listed in `opaque` instead of being guessed:

| kind | example |
|---|---|
| `dynamic-program` | `$CMD x`, `$(echo rm) x` |
| `shell-c` | `bash -c "$SCRIPT"` |
| `shell-stdin` | `curl … \| bash`, `bash < file` |
| `script-file` | `bash deploy.sh`, `. ./env.sh` |
| `eval`, `trap` | payload contains expansions |
| `xargs-program`, `find-exec` | program name is an expansion |
| `parse-error` | the parser could not read part of the input |

`decide()` fails closed by default: if any deny or ask rule exists and part of
the script is opaque, the result is `ask` with `reason: 'unseen'`. Pass
`{ unseen: 'ignore' }` to act only on what was seen.

## Rules

Rule strings use the Claude Code `Bash(...)` content syntax, matched against
`argv.join(' ')` of each normalized command:

- `rm:*` prefix: `rm` with any arguments
- `git push:*` multi-word prefix
- `rm -rf /` exact line (never matches when a word is an expansion)
- `npm run *` wildcard; a trailing ` *` also matches no arguments

Order: any deny match → `deny`; any ask match → `ask`; unseen code with guard
rules → `ask`; every command matched by an allow rule → `allow`; otherwise
`passthrough` (the caller's default mode decides). Allow rules never cover a
command run under `sudo` / `doas` or with `PATH`, `LD_*`, `DYLD_*`, `BASH_ENV`,
`IFS` and similar assignments.

## Bring your own parser

The core walks any tree shaped like tree-sitter-bash output
(`{ type, text, children }`), so it needs no WebAssembly:

```ts
import { scanTree } from 'shell-ast-safeguard/core'

const parse = (source: string) => myParser.parse(source) // tree-sitter-bash shaped
scanTree(parse(command), { parse })
```

The default entry loads [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash)
through [web-tree-sitter](https://github.com/tree-sitter/tree-sitter/tree/master/lib/binding_web)
(optional peer dependencies, about 1.6 MB of wasm, loaded once).

## Runtimes

Bun, and Node 22.6+ with `--experimental-strip-types` (default on in newer
Node). A compiled `dist/` build is planned before publishing.

## Tests

```sh
bun install
bun test
```

`test/forms.test.ts` holds 66 shell forms that each run `touch tN`; every one
must either be seen as `touch` (so `deny touch:*` denies it) or be reported as
unseen.

## Provenance

Written from scratch against the documented behavior and the test matrix above.
It contains no code from Claude Code or any other agent.
