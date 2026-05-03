# Demo GIF

This directory holds the README's hero GIF and the bits needed to regenerate it.

- `demo.gif` — the rendered animation.
- `demo.tape` — [VHS](https://github.com/charmbracelet/vhs) tape that drives the
  recording.
- `demo_player.sh` — a deterministic shell script that prints a
  representative scan transcript with realistic timing.

## Why a player instead of a live scan?

The GIF needs to ship in a public repo. A live `gisweep arcgis <url>` invocation
would either fail (no real target on `localhost`) or expose third-party
infrastructure. The player simulates a real run against a fictional
`http://localhost/arcgis/rest/` and emits the same colour, layout, and severity
roll-up the real scanner produces.

## Re-render

```bash
cd docs/demo
vhs demo.tape
```

Requires VHS plus its `ttyd` and `ffmpeg` runtime dependencies.
