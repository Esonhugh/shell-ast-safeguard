// Walks a tree-sitter-bash shaped syntax tree and lists every command the
// script would run, with argv normalized for permission matching.

export type SyntaxNode = {
  type: string
  text: string
  children: readonly SyntaxNode[]
}

/** Parses source into a tree-sitter-bash shaped tree, or null on failure. */
export type ParseFn = (source: string) => SyntaxNode | null

export type Origin =
  | 'script' // written directly in the script, including $(...), (...), loops, pipelines
  | 'shell-c' // bash -c '...' / sh -c '...'
  | 'shell-stdin' // bash <<< '...'
  | 'eval'
  | 'trap'
  | 'find-exec'

export type Command = {
  /** Source text of the command node this came from. */
  text: string
  /** Program name: basename of argv[0] after wrappers. null when computed at run time. */
  program: string | null
  /** Words from the program on, quotes and escapes removed; path of the program reduced to its basename. */
  argv: string[]
  /** Wrappers stripped in order, e.g. ['sudo', 'timeout']. */
  wrappers: string[]
  /** Leading NAME=value assignments, including those given to env. */
  assignments: string[]
  /** Some word depends on an expansion ($x, $(...), globs are left as written). */
  dynamic: boolean
  origin: Origin
}

export type OpaqueKind =
  | 'dynamic-program' // $(echo rm) x, $CMD x
  | 'shell-c' // payload is not a literal string
  | 'shell-stdin' // echo ... | bash, bash < file
  | 'script-file' // bash script.sh, source file
  | 'eval'
  | 'trap'
  | 'xargs-program' // xargs with no visible program
  | 'find-exec'
  | 'parse-error' // the parser could not read this part

/** A place where the script hands code to another program in a form this scan cannot read. */
export type Opaque = { kind: OpaqueKind; text: string }

export type ScanResult = {
  commands: Command[]
  opaque: Opaque[]
  /** The parser reported a syntax error somewhere; the list may be incomplete. */
  parseError: boolean
}

export type ScanOptions = {
  /** Needed to look inside literal bash -c / eval / trap payloads; without it they are reported as opaque. */
  parse?: ParseFn
  /** Nesting limit for re-parsed payloads. Default 8. */
  maxDepth?: number
}

const REDIRECTS = new Set(['file_redirect', 'heredoc_redirect', 'herestring_redirect'])
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'busybox-sh'])
const DYNAMIC = new Set([
  'simple_expansion',
  'expansion',
  'command_substitution',
  'process_substitution',
  'arithmetic_expansion',
  'brace_expression',
])

export function scanTree(root: SyntaxNode, options: ScanOptions = {}): ScanResult {
  const result: ScanResult = { commands: [], opaque: [], parseError: false }
  walk(root, 'script', 0, result, options)
  return result
}

function walk(node: SyntaxNode, origin: Origin, depth: number, out: ScanResult, opts: ScanOptions): void {
  if (node.type === 'ERROR' || node.type === 'MISSING') {
    out.parseError = true
    out.opaque.push({ kind: 'parse-error', text: node.text })
  }
  if (node.type === 'command' || node.type === 'declaration_command' || node.type === 'unset_command') {
    addCommand(node, origin, depth, out, opts)
  }
  for (const child of node.children) walk(child, origin, depth, out, opts)
}

type Word = { value: string; dynamic: boolean }

function readWord(node: SyntaxNode): Word {
  switch (node.type) {
    case 'word':
    case 'command_name': {
      if (node.type === 'command_name' && node.children.length) return readWord(node.children[0]!)
      return { value: node.text.replace(/\\(.)/gs, '$1'), dynamic: false }
    }
    case 'number':
    case 'variable_name':
      return { value: node.text, dynamic: false }
    case 'raw_string':
      return { value: node.text.slice(1, -1), dynamic: false }
    case 'ansi_c_string':
      return { value: decodeAnsiC(node.text.slice(2, -1)), dynamic: false }
    case 'string': {
      let value = ''
      let dynamic = false
      for (const part of node.children) {
        if (part.type === '"') continue
        if (part.type === 'string_content') value += part.text.replace(/\\([$`"\\\n])/g, '$1')
        else {
          const w = readWord(part)
          value += w.value
          dynamic ||= w.dynamic
        }
      }
      return { value, dynamic }
    }
    case 'concatenation': {
      const parts = node.children.map(readWord)
      return { value: parts.map(p => p.value).join(''), dynamic: parts.some(p => p.dynamic) }
    }
    default:
      return { value: node.text, dynamic: true }
  }
}

function decodeAnsiC(s: string): string {
  const map: Record<string, string> = { n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' }
  return s.replace(/\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)/gs, (m, e: string) => {
    if (e[0] === 'x') return String.fromCharCode(parseInt(e.slice(1), 16))
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8))
    return map[e] ?? m
  })
}

const basename = (word: string) => (/\/[^/]/.test(word) ? word.replace(/\/+$/, '').split('/').pop()! : word)

function addCommand(node: SyntaxNode, origin: Origin, depth: number, out: ScanResult, opts: ScanOptions): void {
  const assignments: string[] = []
  const words: Word[] = []
  let herestring: Word | null = null
  for (const [index, child] of node.children.entries()) {
    if (node.type !== 'command' && index === 0) {
      // declare / export / local / readonly / unset keyword
      words.push({ value: child.text, dynamic: false })
    } else if (child.type === 'variable_assignment') {
      if (node.type === 'command') assignments.push(child.text)
      else words.push({ value: child.text, dynamic: child.children.some(c => DYNAMIC.has(c.type)) })
    } else if (REDIRECTS.has(child.type)) {
      if (child.type === 'herestring_redirect') {
        const payload = child.children.find(c => c.type !== '<<<')
        herestring = payload ? readWord(payload) : null
      }
    } else if (child.type !== 'comment') {
      words.push(readWord(child))
    }
  }
  if (!words.length) return
  const cmd = normalize(words, assignments, node.text, origin)
  if (cmd === null) return
  if (cmd.program === null) {
    out.opaque.push({ kind: 'dynamic-program', text: node.text })
    out.commands.push(cmd)
    return
  }
  out.commands.push(cmd)
  lookInside(cmd, node, herestring, depth, out, opts)
}

type Wrapper = {
  /** Options that take a separate value. */
  valued?: RegExp
  /** Number of positional words consumed before the wrapped command (timeout DURATION). */
  positional?: number
  /** Options that mean the wrapper runs nothing (command -v). */
  noRun?: RegExp
  /** NAME=value words are assignments (env). */
  assigns?: boolean
}

const WRAPPERS: Record<string, Wrapper> = {
  env: { valued: /^(-u|--unset|-C|--chdir)$/, assigns: true },
  timeout: { valued: /^(-s|--signal|-k|--kill-after)$/, positional: 1 },
  nice: { valued: /^(-n|--adjustment)$/ },
  nohup: {},
  time: {},
  command: { noRun: /^-[pvV]*[vV]/ },
  builtin: {},
  exec: { valued: /^-a$/ },
  noglob: {},
  stdbuf: { valued: /^-[ioe]$/ },
  sudo: { valued: /^(-u|-g|-h|-p|-C|-D|-r|-t|-U|--user|--group|--host|--prompt|--chdir)$/, assigns: true },
  doas: { valued: /^-[uC]$/ },
  ionice: { valued: /^-[cnp]$/ },
  setsid: {},
  coproc: {},
  busybox: {},
}

function normalize(input: Word[], assignments: string[], text: string, origin: Origin): Command | null {
  let words = input
  const wrappers: string[] = []
  let i = 0
  for (;;) {
    const head = words[i]
    if (!head) return null
    if (head.dynamic) break
    const name = basename(head.value)
    const spec = WRAPPERS[name]
    if (!spec) break
    let j = i + 1
    let noRun = false
    while (j < words.length) {
      const w = words[j]!.value
      if (w === '--') {
        j++
        break
      }
      if (spec.noRun?.test(w)) noRun = true
      const split = name === 'env' ? /^(?:-S|--split-string=?)(.*)$/s.exec(w) : null
      if (split) {
        // env -S 'prog args' runs the split string.
        const value = split[1] || words[j + 1]?.value || ''
        const parts = value.split(/\s+/).filter(Boolean).map(v => ({ value: v, dynamic: words[j]!.dynamic }))
        words = [...words.slice(0, j), ...parts, ...words.slice(split[1] ? j + 1 : j + 2)]
        continue
      }
      if (spec.assigns && /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) {
        assignments.push(w)
        j++
      } else if (w.startsWith('-') && w !== '-') {
        j += spec.valued?.test(w) ? 2 : 1
      } else break
    }
    j += spec.positional ?? 0
    if (noRun || j >= words.length) break
    wrappers.push(name)
    i = j
  }
  const rest = words.slice(i)
  const head = rest[0]!
  const program = head.dynamic ? null : basename(head.value)
  const argv = rest.map(w => w.value)
  if (program !== null) argv[0] = program
  return { text, program, argv, wrappers, assignments, dynamic: rest.some(w => w.dynamic), origin }
}

function lookInside(cmd: Command, node: SyntaxNode, herestring: Word | null, depth: number, out: ScanResult, opts: ScanOptions): void {
  const { program, argv } = cmd
  const payload = (kind: OpaqueKind, origin: Origin, source: string | null) => {
    if (source === null || !opts.parse || depth >= (opts.maxDepth ?? 8)) {
      out.opaque.push({ kind, text: node.text })
      return
    }
    const root = opts.parse(source)
    if (!root) {
      out.opaque.push({ kind, text: node.text })
      return
    }
    walk(root, origin, depth + 1, out, opts)
  }
  // Word values are only trustworthy when no word is dynamic.
  const literal = !cmd.dynamic

  if (SHELLS.has(program!)) {
    const c = argv.findIndex((w, k) => k > 0 && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(w))
    if (c > 0) return payload('shell-c', 'shell-c', literal && argv[c + 1] !== undefined ? argv[c + 1]! : null)
    const script = argv.slice(1).find(w => !w.startsWith('-'))
    if (script !== undefined) return payload('script-file', 'script', null)
    return payload('shell-stdin', 'shell-stdin', herestring && !herestring.dynamic ? herestring.value : null)
  }
  if (program === 'source' || program === '.') {
    const file = argv[1]
    if ((file === '/dev/stdin' || file === '-') && herestring && !herestring.dynamic) return payload('shell-stdin', 'shell-stdin', herestring.value)
    return payload('script-file', 'script', null)
  }
  if (program === 'eval') return payload('eval', 'eval', literal ? argv.slice(1).join(' ') : null)
  if (program === 'trap' && argv.length > 2 && !argv[1]!.startsWith('-')) return payload('trap', 'trap', literal ? argv[1]! : null)
  if (program === 'xargs') return xargsProgram(cmd, out)
  if (program === 'find') return findExec(cmd, out)
}

const XARGS_VALUED = /^(-a|-d|-E|-e|-I|-L|-l|-n|-P|-s|--arg-file|--delimiter|--eof|--replace|--max-lines|--max-args|--max-procs|--max-chars)$/

function xargsProgram(cmd: Command, out: ScanResult): void {
  const { argv } = cmd
  let j = 1
  while (j < argv.length && argv[j]!.startsWith('-') && argv[j] !== '--') j += XARGS_VALUED.test(argv[j]!) ? 2 : 1
  if (argv[j] === '--') j++
  if (j >= argv.length) {
    // Bare xargs runs echo.
    return
  }
  const inner = normalize(
    argv.slice(j).map(value => ({ value, dynamic: cmd.dynamic })),
    [],
    cmd.text,
    cmd.origin,
  )
  if (!inner || inner.program === null) {
    out.opaque.push({ kind: 'xargs-program', text: cmd.text })
    return
  }
  inner.wrappers.unshift(...cmd.wrappers, 'xargs')
  inner.assignments.unshift(...cmd.assignments)
  out.commands.push(inner)
}

function findExec(cmd: Command, out: ScanResult): void {
  const { argv } = cmd
  for (let k = 1; k < argv.length; k++) {
    if (!/^-(exec|execdir|ok|okdir)$/.test(argv[k]!)) continue
    let end = k + 1
    while (end < argv.length && argv[end] !== ';' && argv[end] !== '+') end++
    const inner = normalize(
      argv.slice(k + 1, end).map(value => ({ value, dynamic: cmd.dynamic })),
      [],
      cmd.text,
      'find-exec',
    )
    if (!inner || inner.program === null) out.opaque.push({ kind: 'find-exec', text: cmd.text })
    else out.commands.push(inner)
    k = end
  }
}
