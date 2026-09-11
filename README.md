# Skill Scan

Preflight de solo lectura para revisar skills y plugins de agentes antes de instalarlos. No ejecuta el contenido, no modifica el objetivo y no envía datos.

## Uso rápido

```bash
python3 skill_scan.py --self-test
python3 skill_scan.py ./skill-o-plugin-descargado
python3 skill_scan.py                 # busca instalaciones conocidas
python3 skill_scan.py ./plugin --json
python3 skill_scan.py ./plugin --json --inventory > reporte.json
```

Sin argumentos recorre roots de Claude, Codex, Cursor, OpenClaw, Grok, OpenCode, Pi y `.agents`, mas `.claude/skills` (y equivalentes) del directorio actual.

`--inventory` agrega el SHA-256 de cada archivo al reporte JSON. El reporte también incluye el hash del scanner que lo produjo. El scanner decodifica blobs base64 y hex antes de aplicar las reglas, y marca caracteres ocultos (bidi, zero-width, Unicode tags).

## Como skill de agente

Copia esta carpeta a la ruta de skills de tu agente, por ejemplo `~/.claude/skills/skill-scan/` o `~/.codex/skills/skill-scan/`. El `SKILL.md` le dice al agente que corra `skill_scan.py` y que trate el objetivo como datos, no como instrucciones.

## Leak gate

Preflight para prompts, no para skills. Revisa un texto *antes* de mandarlo a una API frontier. No envia el contenido: hashea, compara contra watchwords y corta dumps de pruebas en latex.

```bash
python3 leak_gate.py --self-test
python3 leak_gate.py check ./draft.md
echo "rewrite this paragraph" | python3 leak_gate.py check --json
python3 leak_gate.py stamp ./notes.lean
python3 leak_gate.py serve --upstream https://api.x.ai/v1 --port 8787 --mode redact
python3 leak_gate.py wrap --upstream https://api.x.ai/v1 -- -- claude
```

El proxy solo escucha en localhost. Watchwords de research y dumps de pruebas se bloquean. Secrets y tarjetas se pueden redactar (`--mode redact`) y restaurar en la respuesta; el mapeo vive en memoria, no en disco. Lineas `re:` en `~/.leak-gate/watchwords.txt` son regex. El ledger guarda el SHA-256, nunca el prompt. Si el gate no puede parsear el request, no lo reenvia.

Para el agente, copia `leak-gate/SKILL.md` a `~/.claude/skills/leak-gate/` (deja `leak_gate.py` un nivel arriba, o ajusta la ruta). Un `PASS` no prueba que el texto sea seguro de enviar.

Esto no sustituye un modelo local ni Lean. Si el trabajo no publicado necesita un modelo, correlo en la maquina. El gate solo evita el envio tonto.

## Cómo leer el resultado

| Veredicto | Significado | Acción |
| --- | --- | --- |
| `PASS` | No encontró patrones conocidos | Revisar procedencia y permisos antes de instalar |
| `REVIEW` | Encontró señales medias o bajas | Revisar cada hallazgo manualmente |
| `BLOCK` | Encontró señales altas, críticas o un escaneo incompleto | No instalar hasta entender y corregir cada hallazgo |

Exit codes: `0` para `PASS`, `1` para `REVIEW` y `2` para `BLOCK`. Un resultado limpio no prueba que la extensión sea segura.

## Compartir y verificar

El archivo `SHA256SUMS` permite comprobar que `skill_scan.py`, `leak_gate.py` y los `SKILL.md` no cambiaron durante el envío:

```bash
shasum -a 256 -c SHA256SUMS       # macOS
sha256sum -c SHA256SUMS           # Linux
```

Para WhatsApp, envía el script, `SKILL.md` y `SHA256SUMS` como archivos. Comparte también el hash por un mensaje separado o por otro canal; un checksum enviado junto al archivo no protege contra el reemplazo de ambos.

## Incidentes npm

Incluye una lista mínima fechada el 2026-08-05 para las campañas de `axios` y `keyv/cacheable`. Para usar la lista completa y actual de Wiz Research:

```bash
curl --proto '=https' --tlsv1.2 -fLo keyv-packages.csv https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/keyv-packages.csv
python3 skill_scan.py ./plugin --ioc-csv keyv-packages.csv
```

Antes de instalar dependencias de un plugin no confiable:

```bash
npm config set strict-allow-scripts true --location=project
npm config set min-release-age 7 --location=project
npm ci --ignore-scripts
npm approve-scripts --allow-scripts-pending
```

Revisa y fija cada excepción antes de permitir scripts. El scanner marca `.npmrc` que habiliten `dangerously-allow-all-scripts`.

## Segunda opinión opcional

Estas herramientas se ejecutan por separado. `skill_scan.py` nunca las instala ni las llama:

```bash
skillspector scan ./plugin --no-llm
guarddog npm scan ./plugin
```

[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) amplía el análisis estático de skills. [GuardDog](https://github.com/DataDog/guarddog) revisa código y metadatos de paquetes npm dentro de un sandbox. Instálalas y verifica su checksum siguiendo sus repositorios oficiales.

Fuentes: [IoCs de Wiz Research](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv), [controles de instalación de npm](https://docs.npmjs.com/cli/install/) y [aprobación de scripts](https://docs.npmjs.com/cli/v11/commands/npm-approve-scripts/).

Licencia: MIT.
