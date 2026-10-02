import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, resolve, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const project = resolve(frontend, '..')
const output = join(frontend, 'src', 'api', 'generated.ts')
const temporary = mkdtempSync(join(tmpdir(), 'soc-openapi-'))
const schemaPath = join(temporary, 'openapi.json')
const generatedPath = join(temporary, 'generated.ts')
try {
  const python = String.raw`import json; from api.app import app; print(json.dumps(app.openapi(), sort_keys=True, separators=(",", ":")))`
  const schemaText = execFileSync(process.env.PYTHON || 'python', ['-c', python], {
    cwd: project,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  }).trim()
  writeFileSync(schemaPath, schemaText)
  const packageJson = JSON.parse(readFileSync(join(frontend, 'node_modules', 'openapi-typescript', 'package.json'), 'utf8'))
  const cli = join(frontend, 'node_modules', 'openapi-typescript', packageJson.bin['openapi-typescript'])
  execFileSync(process.execPath, [cli, schemaPath, '-o', generatedPath], { cwd: frontend, stdio: 'inherit' })
  const digest = createHash('sha256').update(schemaText).digest('hex')
  writeFileSync(output, `// OpenAPI-SHA256: ${digest}\n${readFileSync(generatedPath, 'utf8')}`)
  console.log(`Generated ${output} from the running FastAPI OpenAPI schema (${digest.slice(0, 12)}).`)
} finally {
  rmSync(temporary, { recursive: true, force: true })
}
