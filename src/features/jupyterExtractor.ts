/**
 * Jupyter Notebook Extractor
 *
 * Parses .ipynb files and produces a flat, scannable text representation.
 * Each cell's source is emitted with a header comment so rules fire at
 * accurate virtual line numbers that the scanner can report back.
 *
 * Also extracts cell outputs (stream text, error text, plain/html mime
 * types) because credentials are frequently leaked in notebook outputs.
 */

interface NotebookCell {
  cell_type: 'code' | 'markdown' | 'raw';
  source: string | string[];
  outputs?: NotebookOutput[];
  metadata?: Record<string, unknown>;
}

interface NotebookOutput {
  output_type: 'stream' | 'error' | 'display_data' | 'execute_result';
  text?: string | string[];
  traceback?: string[];
  data?: Record<string, string | string[]>;
}

interface Notebook {
  nbformat?: number;
  cells?: NotebookCell[];
}

export interface JupyterExtractionResult {
  /** The synthetic flat text to scan */
  text: string;
  /**
   * Maps virtual line numbers (1-based, in `text`) back to the original
   * cell index and within-cell line number for finding annotations.
   */
  lineMap: { cellIndex: number; cellType: string; withinCellLine: number }[];
}

function joinSource(source: string | string[]): string {
  return Array.isArray(source) ? source.join('') : source;
}

function extractOutputText(output: NotebookOutput): string {
  const parts: string[] = [];
  if (output.text) parts.push(joinSource(output.text));
  if (output.traceback) parts.push(output.traceback.join('\n'));
  if (output.data) {
    for (const [mime, value] of Object.entries(output.data)) {
      if (mime === 'text/plain' || mime === 'text/html' || mime === 'application/json') {
        parts.push(joinSource(value));
      }
    }
  }
  return parts.join('\n');
}

/**
 * Extract scannable text from a parsed Jupyter notebook.
 *
 * The emitted format is:
 *   # [FERRET:CELL:N:TYPE]
 *   <cell source lines>
 *   # [FERRET:OUTPUT:N]
 *   <output lines>
 *
 * The comment markers let context-aware readers identify which cell a
 * finding belongs to without disrupting line-number arithmetic.
 */
export function extractJupyterText(notebookJson: string): JupyterExtractionResult {
  let notebook: Notebook;
  try {
    notebook = JSON.parse(notebookJson) as Notebook;
  } catch {
    // Not valid JSON — return raw so other rules can still flag it
    return {
      text: notebookJson,
      lineMap: [],
    };
  }

  const cells = notebook.cells ?? [];
  const lines: string[] = [];
  const lineMap: JupyterExtractionResult['lineMap'] = [];

  const pushLine = (content: string, cellIndex: number, cellType: string, withinCellLine: number): void => {
    lines.push(content);
    lineMap.push({ cellIndex, cellType, withinCellLine });
  };

  for (let i = 0; i < cells.length; i++) {
    const cell = cells[i]!;
    const cellType = cell.cell_type ?? 'code';

    // Cell header (one virtual line)
    pushLine(`# [FERRET:CELL:${i}:${cellType}]`, i, cellType, 0);

    // Cell source
    const src = joinSource(cell.source ?? '');
    const srcLines = src.split('\n');
    for (let j = 0; j < srcLines.length; j++) {
      pushLine(srcLines[j]!, i, cellType, j + 1);
    }

    // Cell outputs (code cells only)
    if (cell.outputs && cell.outputs.length > 0) {
      pushLine(`# [FERRET:OUTPUT:${i}]`, i, cellType, 0);
      const outputText = cell.outputs.map(extractOutputText).join('\n');
      const outputLines = outputText.split('\n');
      for (let j = 0; j < outputLines.length; j++) {
        pushLine(outputLines[j]!, i, cellType, -(j + 1)); // negative = output line
      }
    }
  }

  return { text: lines.join('\n'), lineMap };
}

/**
 * Annotate a finding's metadata with the originating cell reference.
 * Call this after the scanner resolves a virtual line number.
 */
export function resolveCellReference(
  virtualLine: number,
  lineMap: JupyterExtractionResult['lineMap']
): { cellIndex: number; cellType: string; withinCellLine: number } | null {
  const entry = lineMap[virtualLine - 1];
  return entry ?? null;
}
