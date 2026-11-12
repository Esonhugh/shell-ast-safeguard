// The 66 shell forms used to compare Bash permission matching in Claude Code
// builds. Each form runs `touch tN` somehow.
import { describe, expect, test } from 'bun:test'
import { decide, scan } from '../src/index.ts'

const FORMS: string[] = [
  'touch t1',
  '/usr/bin/touch t2',
  '\\touch t3',
  '"touch" t4',
  "to''uch t5",
  'FOO=1 touch t6',
  'timeout 5 touch t7',
  'nice touch t8',
  'nohup touch t9',
  'env touch t10',
  'command touch t11',
  'echo t12 | xargs touch',
  "bash -c 'touch t13'",
  'sh -c "touch t14"',
  'eval touch t15',
  'true; touch t16',
  'true && touch t17',
  'false || touch t18',
  'true\ntouch t19',
  'echo $(touch t20)',
  'echo `touch t21`',
  'true & touch t22',
  'exec touch t23',
  'time touch t24',
  'stdbuf -o0 touch t25',
  '(touch t26)',
  '{ touch t27; }',
  'if true; then touch t28; fi',
  'for f in t29; do touch $f; done',
  'echo hi > >(touch t30)',
  'cat <(touch t31)',
  'nohup nice touch t32',
  'env -i touch t33',
  'builtin command touch t34',
  'xargs -a /dev/null touch t35',
  'find . -maxdepth 0 -exec touch t36 \;',
  'while true; do touch t37; break; done',
  'case x in x) touch t38;; esac',
  'f(){ touch t39; }; f',
  'echo "$(touch t40)"',
  'x=$(touch t41)',
  'cat <<EOF\n$(touch t42)\nEOF',
  'echo | touch t43',
  '! touch t44',
  'nice -n 5 touch t45',
  'exec env touch t46',
  "bash <<< 'touch t47'",
  "echo 'touch t48' | bash",
  "source /dev/stdin <<< 'touch t49'",
  'PATH=/usr/bin touch t50',
  "/bin/sh -c 'touch t51'",
  '$(echo touch) t52',
  'T=touch; $T t53',
  '[[ -n x ]] && touch t54',
  'xargs touch <<< t55',
  'until touch t56; do :; done',
  'coproc touch t57',
  "trap 'touch t58' EXIT",
  'cd . && touch t59',
  'echo x | tee >(touch t60)',
  'xargs -I{} touch {} <<< t61',
  'env -- touch t62',
  'command -p touch t63',
  'timeout -s KILL 5 touch t64',
  '"/usr/bin/touch" t65',
  'busybox touch t66',
]

// Code reaches the shell as data from a pipe or a computed name: nothing to read.
const UNSEEN = new Set([48, 52, 53])

describe('every form is either seen as touch or reported as unseen', () => {
  FORMS.forEach((form, i) => {
    const n = i + 1
    test(`t${n}: ${JSON.stringify(form)}`, async () => {
      const result = await scan(form)
      const touch = result.commands.find(c => c.program === 'touch')
      if (UNSEEN.has(n)) {
        expect(touch).toBeUndefined()
        expect(result.opaque.length).toBeGreaterThan(0)
        expect(decide(result, { deny: ['touch:*'] }).behavior).toBe('ask')
      } else {
        expect(touch?.argv[0]).toBe('touch')
        expect(decide(result, { deny: ['touch:*'] })).toMatchObject({ behavior: 'deny', rule: 'touch:*' })
        expect(decide(result, { ask: ['touch:*'] })).toMatchObject({ behavior: 'ask', reason: 'rule' })
      }
    })
  })
})
