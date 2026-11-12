import type { Command, Opaque, ScanResult } from './scan.ts'

/**
 * Rule content in Claude Code's Bash(...) syntax:
 *   "rm:*"         prefix: `rm` with any arguments
 *   "git push"     exact command line
 *   "npm run *"    wildcard; a trailing " *" also matches no arguments
 */
export type Rule = string

export type Rules = { deny?: Rule[]; ask?: Rule[]; allow?: Rule[] }

export type Decision =
  | { behavior: 'deny' | 'ask'; reason: 'rule'; rule: Rule; command: Command }
  | { behavior: 'ask'; reason: 'unseen'; unseen: Opaque[] }
  | { behavior: 'allow'; rules: Rule[] }
  | { behavior: 'passthrough' }

export type DecideOptions = {
  /**
   * What to do when deny/ask rules exist but part of the script runs code this
   * scan cannot read (opaque payloads, dynamic program names, parse errors).
   * 'ask' (default) fails closed; 'ignore' only acts on what it saw.
   */
  unseen?: 'ask' | 'ignore'
}

const PRIVILEGE_WRAPPERS = new Set(['sudo', 'doas'])
const UNSAFE_ASSIGNMENT = /^(PATH|LD_\w*|DYLD_\w*|BASH_ENV|ENV|IFS|PS4|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|BASH_FUNC_\w*)=/

function escapeRegExp(s: string): string {
  return s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')
}

export function matchesRule(rule: Rule, command: Command): boolean {
  if (command.program === null) return false
  const line = command.argv.join(' ')
  if (rule.endsWith(':*')) {
    const prefix = rule.slice(0, -2)
    return line === prefix || line.startsWith(prefix + ' ')
  }
  if (rule.includes('*')) {
    let source = rule.split('*').map(escapeRegExp).join('.*')
    if (rule.endsWith(' *')) source = source.slice(0, -' .*'.length) + '( .*)?'
    return new RegExp(`^${source}$`, 's').test(line)
  }
  return !command.dynamic && line === rule
}

/** Allow rules only cover a command run as itself: no sudo, no PATH/LD_PRELOAD style assignments. */
function allowable(command: Command): boolean {
  return (
    !command.wrappers.some(w => PRIVILEGE_WRAPPERS.has(w)) &&
    !command.assignments.some(a => UNSAFE_ASSIGNMENT.test(a))
  )
}

export function decide(scan: ScanResult, rules: Rules, options: DecideOptions = {}): Decision {
  for (const behavior of ['deny', 'ask'] as const) {
    for (const command of scan.commands) {
      const rule = rules[behavior]?.find(r => matchesRule(r, command))
      if (rule !== undefined) return { behavior, reason: 'rule', rule, command }
    }
  }
  const unseen = scan.opaque
  const guarded = (rules.deny?.length ?? 0) + (rules.ask?.length ?? 0) > 0
  if (unseen.length && guarded && (options.unseen ?? 'ask') === 'ask') {
    return { behavior: 'ask', reason: 'unseen', unseen }
  }
  if (!unseen.length && scan.commands.length) {
    const used: Rule[] = []
    for (const command of scan.commands) {
      const rule = allowable(command) ? rules.allow?.find(r => matchesRule(r, command)) : undefined
      if (rule === undefined) return { behavior: 'passthrough' }
      used.push(rule)
    }
    return { behavior: 'allow', rules: [...new Set(used)] }
  }
  return { behavior: 'passthrough' }
}
