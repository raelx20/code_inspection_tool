/**
 * CodeSentry Typewriter Component & Diagnostics Catalog
 *
 * Provides character-by-character typewriter animation and a curated catalog
 * of authentic DevSecOps & programming-themed telemetry status messages.
 */

'use strict';

const theme = require('../theme');

const PROGRAMMING_MESSAGES = {
  discovering: [
    'Discovering source files & AST syntax tree...',
    'Resolving workspace dependency hierarchy...',
    'Extracting module declarations & symbol graph...',
    'Indexing codebase entrypoints & package manifests...',
    'Scanning directory topology & ignore filters...',
    'Enumerating function call sites & signatures...',
  ],
  analyzing: [
    'Running static analyzers (Ruff, Bandit, Semgrep)...',
    'Auditing CWE vulnerabilities & taint injection sinks...',
    'Tracing unescaped input parameters & sanitizers...',
    'Inspecting cryptographic entropy & hash algorithms...',
    'Scanning for hardcoded API keys & cloud credentials...',
    'Evaluating memory allocation bounds & leak vectors...',
    'Checking concurrency locks & thread-safety invariants...',
    'Profiling algorithmic complexity & recursion limits...',
  ],
  processing: [
    'Deduplicating finding fingerprints & rule IDs...',
    'Cross-referencing CVSS severity & blast radius...',
    'Synthesizing security posture & aggregation metrics...',
  ],
  ai_analysis: [
    'Triaging findings with OpenRouter AI...',
    'Querying neural reasoning model for root cause analysis...',
    'Correlating multi-vector vulnerability chains...',
    'Synthesizing surgical remediation patches & diffs...',
    'Evaluating exploitability likelihood & attack paths...',
  ],
  generating: [
    'Compiling executive DevSecOps audit report...',
    'Formatting markdown tables & code snippets...',
    'Flushing report artifacts to filesystem...',
  ],
};

/**
 * Returns a random programming-themed message for a given scan state
 */
function getRandomProgrammingMessage(state) {
  const list = PROGRAMMING_MESSAGES[state] || PROGRAMMING_MESSAGES.analyzing;
  return list[Math.floor(Math.random() * list.length)];
}

class Typewriter {
  constructor(options = {}) {
    this.text = options.text || '';
    this.cursor = options.cursor !== false;
    this.cursorChar = options.cursorChar || '▌';
    this.visibleLength = options.playing === false ? this.text.length : 0;
    this.done = this.visibleLength >= this.text.length;
  }

  setText(newText) {
    this.text = newText;
    this.visibleLength = 0;
    this.done = false;
  }

  step() {
    if (this.visibleLength < this.text.length) {
      this.visibleLength++;
    }
    this.done = this.visibleLength >= this.text.length;
    return this.render();
  }

  render() {
    const slice = this.text.slice(0, this.visibleLength);
    if (this.cursor && !this.done) {
      return `${slice}${theme.colors.cyan(this.cursorChar)}`;
    }
    return slice;
  }

  isDone() {
    return this.done;
  }
}

module.exports = {
  Typewriter,
  PROGRAMMING_MESSAGES,
  getRandomProgrammingMessage,
};
