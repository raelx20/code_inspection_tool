/**
 * CodeSentry Progress Tracker
 * Animated arrow loader (arrows_3) with Typewriter text animation,
 * pulsing status indicators, and randomized programming-themed telemetry.
 */

'use strict';

const { Typewriter, getRandomProgrammingMessage, PROGRAMMING_MESSAGES } = require('./components/typewriter');
const { formatStatusIndicator, StatusIndicator } = require('./components/status-indicator');

const PROGRESS_STATES = {
  STARTED: 'started',
  DISCOVERING: 'discovering',
  ANALYZING: 'analyzing',
  PROCESSING: 'processing',
  AI_ANALYSIS: 'ai_analysis',
  GENERATING: 'generating',
  COMPLETED: 'completed',
  FAILED: 'failed',
};

const PROGRESS_MESSAGES = {
  [PROGRESS_STATES.STARTED]: 'Inspecting codebase topology...',
  [PROGRESS_STATES.DISCOVERING]: 'Discovering files & syntax trees...',
  [PROGRESS_STATES.ANALYZING]: 'Running static analyzers (Ruff, Bandit, Semgrep)...',
  [PROGRESS_STATES.PROCESSING]: 'Processing and deduplicating findings...',
  [PROGRESS_STATES.AI_ANALYSIS]: 'Triaging findings with OpenRouter AI...',
  [PROGRESS_STATES.GENERATING]: 'Compiling DevSecOps audit report...',
  [PROGRESS_STATES.COMPLETED]: 'Scan complete',
  [PROGRESS_STATES.FAILED]: 'Scan failed',
};

// ── arrows_3 Loader Specification ────────────────────────────────────────────
const ARROWS_3 = {
  speed: 100, // ms
  keyframes: ['▹▹▹▹▹', '▸▹▹▹▹', '▹▸▹▹▹', '▹▹▸▹▹', '▹▹▹▸▹', '▹▹▹▹▸'],
};

class ProgressTracker {
  constructor(options = {}) {
    this.verbose = options.verbose || false;
    this.jsonMode = options.jsonMode || false;
    this.currentState = null;
    this.currentMessage = PROGRESS_MESSAGES[PROGRESS_STATES.STARTED];
    this.steps = [];
    this.startTime = Date.now();
    this.intervalId = null;
    this.frameIdx = 0;
    this.pulseIdx = 0;
    this.ticksSinceStateChange = 0;

    // Typewriter instance for smooth character typing
    this.typewriter = new Typewriter({
      text: this.currentMessage,
      cursor: true,
      cursorChar: '▌',
    });
  }

  start() {
    this.currentState = PROGRESS_STATES.STARTED;
    this.currentMessage = PROGRESS_MESSAGES[PROGRESS_STATES.STARTED];
    this.typewriter.setText(this.currentMessage);

    if (this.jsonMode) return;

    const isTTY = Boolean(process.stdout && process.stdout.isTTY);

    if (isTTY) {
      const { center, colors, bold } = require('./theme');

      this.intervalId = setInterval(() => {
        this.frameIdx = (this.frameIdx + 1) % ARROWS_3.keyframes.length;
        this.pulseIdx = (this.pulseIdx + 1) % StatusIndicator.PULSE_FRAMES.length;
        this.ticksSinceStateChange++;

        // Step typewriter characters
        const typedText = this.typewriter.step();

        // Every ~25 ticks (2.5s) if still in same phase, randomize to another programming telemetry message
        if (
          this.ticksSinceStateChange > 25 &&
          this.currentState &&
          PROGRAMMING_MESSAGES[this.currentState]
        ) {
          this.ticksSinceStateChange = 0;
          const nextMsg = getRandomProgrammingMessage(this.currentState);
          this.typewriter.setText(nextMsg);
        }

        const arrowFrame = ARROWS_3.keyframes[this.frameIdx];
        const pulseDot = StatusIndicator.PULSE_FRAMES[this.pulseIdx];

        // Format:  ▹▹▹▹▹  ●  <typedText>
        const line = `${colors.cyan(bold(arrowFrame))}  ${colors.green(pulseDot)} ${colors.white(typedText)}`;
        process.stdout.write(`\r\x1b[2K${center(line)}`);
      }, ARROWS_3.speed);

      if (this.intervalId.unref) {
        this.intervalId.unref();
      }
    } else {
      const { center, colors } = require('./theme');
      this.log(center(colors.gray('● Inspecting codebase...')));
    }
  }

  update(state, message) {
    if (!PROGRESS_MESSAGES[state]) {
      throw new Error(`Invalid progress state: "${state}"`);
    }

    this.currentState = state;
    this.ticksSinceStateChange = 0;
    this.currentMessage = message || getRandomProgrammingMessage(state) || PROGRESS_MESSAGES[state];
    this.typewriter.setText(this.currentMessage);

    const step = {
      state,
      message: this.currentMessage,
      timestamp: Date.now(),
    };
    this.steps.push(step);

    if (this.verbose && !this.jsonMode) {
      this._clearLine();
      const { center, colors } = require('./theme');
      this.log(center(colors.green('✔ ') + colors.gray(this.currentMessage)));
    }
  }

  warn(message) {
    if (this.verbose && !this.jsonMode) {
      this._clearLine();
      const { center, colors } = require('./theme');
      this.log(center(colors.yellow('⚠ ') + colors.yellow(message)));
    }
  }

  error(message) {
    this._stopLoader();
    if (!this.jsonMode) {
      const { center, colors } = require('./theme');
      this.log(center(colors.red('✖ ') + colors.red(message)));
    }
  }

  complete(success = true) {
    this._stopLoader();

    this.currentState = success ? PROGRESS_STATES.COMPLETED : PROGRESS_STATES.FAILED;
    const message = success
      ? PROGRESS_MESSAGES[PROGRESS_STATES.COMPLETED]
      : PROGRESS_MESSAGES[PROGRESS_STATES.FAILED];

    if (this.verbose && !this.jsonMode) {
      const { center, colors } = require('./theme');
      this.log(center(colors.green('✔ ') + colors.gray(message)));
    }

    return this.getSummary();
  }

  getSummary() {
    const duration = Date.now() - this.startTime;
    return {
      steps: this.steps,
      duration,
      success: this.currentState === PROGRESS_STATES.COMPLETED,
    };
  }

  _stopLoader() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this._clearLine();
  }

  _clearLine() {
    if (process.stdout && process.stdout.isTTY) {
      try {
        process.stdout.write('\r\x1b[2K');
      } catch {}
    }
  }

  log(message) {
    if (!this.jsonMode) {
      console.error(message);
    }
  }
}

function createProgressTracker(options = {}) {
  return new ProgressTracker(options);
}

module.exports = {
  PROGRESS_STATES,
  PROGRESS_MESSAGES,
  ARROWS_3,
  ProgressTracker,
  createProgressTracker,
};