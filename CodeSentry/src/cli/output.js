const OUTPUT_MODES = {
  TERMINAL: 'terminal',
  JSON: 'json',
  SILENT: 'silent',
};

class OutputHandler {
  constructor(options = {}) {
    this.mode = options.mode || OUTPUT_MODES.TERMINAL;
    this.stdout = options.stdout || process.stdout;
    this.stderr = options.stderr || process.stderr;
  }

  print(message) {
    if (this.mode === OUTPUT_MODES.SILENT) return;
    
    if (this.mode === OUTPUT_MODES.JSON) {
      this.stderr.write(message + '\n');
    } else {
      this.stdout.write(message + '\n');
    }
  }

  printError(message) {
    if (this.mode === OUTPUT_MODES.JSON) {
      this.stderr.write(message + '\n');
    } else {
      this.stderr.write(message + '\n');
    }
  }

  printJSON(data) {
    if (this.mode !== OUTPUT_MODES.JSON) return;
    
    try {
      const json = JSON.stringify(data, null, 2);
      this.stdout.write(json + '\n');
    } catch (err) {
      this.printError(`Failed to serialize JSON: ${err.message}`);
    }
  }

  printTable(rows, options = {}) {
    if (this.mode === OUTPUT_MODES.JSON) return;
    
    const { headers, alignments } = options;
    const columnWidths = this.calculateColumnWidths(rows, headers);
    
    if (headers) {
      const headerRow = this.formatRow(headers, columnWidths, alignments);
      this.print(headerRow);
      this.print('─'.repeat(headerRow.length));
    }
    
    for (const row of rows) {
      this.print(this.formatRow(row, columnWidths, alignments));
    }
  }

  calculateColumnWidths(rows, headers) {
    const allRows = headers ? [headers, ...rows] : rows;
    const widths = [];
    
    for (let col = 0; col < allRows[0].length; col++) {
      let maxWidth = 0;
      for (const row of allRows) {
        const cell = String(row[col] || '');
        maxWidth = Math.max(maxWidth, cell.length);
      }
      widths.push(maxWidth);
    }
    
    return widths;
  }

  formatRow(cells, widths, alignments = []) {
    return cells
      .map((cell, i) => {
        const str = String(cell || '');
        const width = widths[i];
        const align = alignments[i] || 'left';
        
        if (align === 'right') {
          return str.padStart(width);
        } else if (align === 'center') {
          return str.padStart(Math.floor((width + str.length) / 2)).padEnd(width);
        } else {
          return str.padEnd(width);
        }
      })
      .join('  ');
  }

  printBox(content, options = {}) {
    if (this.mode === OUTPUT_MODES.JSON) return;
    
    const { width = 40, title } = options;
    const lines = Array.isArray(content) ? content : content.split('\n');
    
    const top = `╭${'─'.repeat(width)}╮`;
    const bottom = `╰${'─'.repeat(width)}╯`;
    
    if (title) {
      const titleLine = `╭─ ${title} ${'─'.repeat(Math.max(0, width - title.length - 4))}╮`;
      this.print(titleLine);
    } else {
      this.print(top);
    }
    
    for (const line of lines) {
      const contentLine = `│ ${line.padEnd(width - 2)} │`;
      this.print(contentLine);
    }
    
    this.print(bottom);
  }

  printSeparator() {
    if (this.mode === OUTPUT_MODES.JSON) return;
    this.print('─'.repeat(76));
  }
}

function createOutputHandler(options = {}) {
  return new OutputHandler(options);
}

module.exports = {
  OUTPUT_MODES,
  OutputHandler,
  createOutputHandler,
};