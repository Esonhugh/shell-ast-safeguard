import { scanTree, type ParseFn, type ScanOptions, type ScanResult } from './scan.ts'
import { createTreeSitterParse } from './treeSitter.ts'

export * from './core.ts'
export { createTreeSitterParse }

/** Scans a bash command string with the bundled tree-sitter-bash parser. */
export async function scan(source: string, options: Omit<ScanOptions, 'parse'> = {}): Promise<ScanResult> {
  const parse: ParseFn = await createTreeSitterParse()
  const root = parse(source)
  if (!root) return { commands: [], opaque: [{ kind: 'parse-error', text: source }], parseError: true }
  return scanTree(root, { ...options, parse })
}
