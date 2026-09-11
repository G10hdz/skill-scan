---
name: leak-gate
description: >
  Keep unpublished research on the local machine. Before sending a prompt,
  file, or proof sketch to a frontier API, run leak_gate.py to block
  watchwords, latex proof dumps, and user codenames. Use when the user is
  working on unpublished math or research, mentions leak-gate, leak budget,
  do not send this to the cloud, or is about to paste a proof into Claude,
  Codex, ChatGPT, or Grok.
---

# Leak gate

El trabajo no publicado se queda en el laptop. Un modelo frontier no es un cuaderno.

## Reglas

- No envies a ninguna API el planteo global, el nombre real del problema, lemas propios, ni archivos de `~/` que el usuario trate como privados.
- Antes de cada llamada cloud, corre el gate. Si dice `BLOCK`, no reescribas el prompt para colarlo. Recorta hasta que pase, o trabaja en local.
- El ledger guarda SHA-256, no el texto. No copies el prompt al chat "para chequearlo".
- `PASS` no prueba que sea seguro mandarlo. Solo dice que no matcheo la lista.

## Flujo

`SKILL_DIR` es el directorio de este skill. El script vive un nivel arriba, junto a `skill_scan.py`:

```bash
python3 "$SKILL_DIR/../leak_gate.py" --self-test
python3 "$SKILL_DIR/../leak_gate.py" check --json
python3 "$SKILL_DIR/../leak_gate.py" check ./draft.md --json
python3 "$SKILL_DIR/../leak_gate.py" stamp ./notes.lean
```

`check` sin archivos lee stdin. Exit `0` = `PASS`, `2` = `BLOCK`.

Watchwords extra en `~/.leak-gate/watchwords.txt` (un termino por linea, o `re:patron` para regex). Ahi van nombres reales, codenames y arXiv de *tu* draft.

El gate tambien corta secrets (AWS/GitHub/OpenAI/PEM), dumps latex, texto oculto y blobs base64/hex. `--mode redact` en el proxy sustituye secrets por `<<LG:n>>` y los restaura en la respuesta; los watchwords de research siguen en `BLOCK`. El ledger guarda SHA-256, nunca el prompt ni el secreto.

```bash
python3 "$SKILL_DIR/../leak_gate.py" serve --upstream https://api.x.ai/v1 --port 8787 --mode redact
python3 "$SKILL_DIR/../leak_gate.py" wrap --upstream https://api.x.ai/v1 -- -- your-cli
```

`wrap` apunta `OPENAI_BASE_URL` y `ANTHROPIC_BASE_URL` a localhost. Un `403` con `leak_gate_blocked` es un `BLOCK`. Si el gate falla, cierra (no reenvia).

## Si BLOCK

1. Saca nombres propios, el objetivo global y el dump de prueba.
2. Deja un subproblema que se pueda leer como texto de libro.
3. Vuelve a correr `check`.
4. Si aun bloquea, no lo mandes. Usa el modelo local o Lean.

## Informe

```
# Leak gate

**Veredicto:** PASS | BLOCK
**SHA-256:** {hash}
**Hits:** {rule detail, o ninguno}

{una frase: se puede mandar recortado / no sale de esta maquina}
```

Escribe el informe en el idioma del usuario.
