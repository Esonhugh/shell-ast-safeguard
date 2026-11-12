// Default parser: tree-sitter-bash on web-tree-sitter (both MIT, optional peer dependencies).
import { createRequire } from 'node:module'
import { Language, Parser } from 'web-tree-sitter'
import type { ParseFn, SyntaxNode } from './scan.ts'

let parser: Promise<Parser> | undefined

async function load(): Promise<Parser> {
  await Parser.init()
  const wasm = createRequire(import.meta.url).resolve('tree-sitter-bash/tree-sitter-bash.wasm')
  const p = new Parser()
  p.setLanguage(await Language.load(wasm))
  return p
}

/** Loads the grammar once and returns a synchronous parse function. */
export async function createTreeSitterParse(): Promise<ParseFn> {
  const p = await (parser ??= load())
  return (source: string) => (p.parse(source)?.rootNode as unknown as SyntaxNode | undefined) ?? null
}
