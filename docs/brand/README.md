# Brand mark

The mark is a document with a scan bar across it. `icon.svg` is the source; the
rest are colour variants and the PNG sizes exported from it.

The admin UI does not load any of these at runtime. It is a single embedded HTML
file, so the glyph is inlined twice in `internal/scanui/ui/index.html`: once in
the header tile (`.mark`, drawn in `currentColor` on the amber tile) and once in
the favicon data URI. Editing a file here changes nothing on its own; the two
copies in `index.html` have to be updated with it.

The favicon and the header tile use a reduced glyph. At 16 to 26 px the rails and
the text lines inside the document blur into a grey smear, so only the document
outline and the scan bar survive at that size.

Note that `tile-amber.svg` and `tile-dark.svg` place the glyph at
`translate(8.96 8.96) scale(0.72)` on a 64 canvas, which leaves it sitting in the
top-left rather than centred. Centring it needs `translate(10.24 10.24)`. The
copies inlined in the UI are centred already.
