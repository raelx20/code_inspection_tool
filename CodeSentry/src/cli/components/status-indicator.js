/**
 * CodeSentry Status Indicator Component
 *
 * Usage:
 *   const { StatusIndicator } = require('./components/status-indicator');
 *
 *   const line = StatusIndicator.format({
 *     status: 'online',
 *     label: 'OpenRouter AI active',
 *   });
 */

'use strict';

const theme = require('../theme');

const PULSE_FRAMES = ['●', '◉', '●', '○'];

function getStatusColor(status) {
  const c = theme.colors;
  switch (status) {
    case 'online':
    case 'success':
      return c.green;
    case 'offline':
    case 'error':
      return c.red;
    case 'warning':
    case 'loading':
      return c.yellow;
    case 'cyan':
    case 'active':
      return c.cyan;
    case 'idle':
    default:
      return c.gray;
  }
}

function getStaticDot(status) {
  switch (status) {
    case 'online':
    case 'success':
      return '●';
    case 'offline':
      return '○';
    case 'error':
      return '✖';
    case 'warning':
      return '⚠';
    case 'loading':
      return '◉';
    case 'active':
      return '●';
    case 'idle':
    default:
      return '○';
  }
}

function formatStatusIndicator({ status = 'idle', label = '', pulse = false, frameIndex = 0 }) {
  const colorFn = getStatusColor(status);
  const dot = pulse
    ? PULSE_FRAMES[frameIndex % PULSE_FRAMES.length]
    : getStaticDot(status);

  return `${colorFn(dot)} ${theme.colors.white(label)}`;
}

class StatusIndicator {
  constructor(options = {}) {
    this.status = options.status || 'idle';
    this.label = options.label || '';
    this.pulse = options.pulse || false;
    this.frameIndex = 0;
  }

  toString() {
    return formatStatusIndicator({
      status: this.status,
      label: this.label,
      pulse: this.pulse,
      frameIndex: this.frameIndex,
    });
  }

  nextFrame() {
    this.frameIndex = (this.frameIndex + 1) % PULSE_FRAMES.length;
    return this.toString();
  }
}

StatusIndicator.format = formatStatusIndicator;
StatusIndicator.PULSE_FRAMES = PULSE_FRAMES;

module.exports = {
  StatusIndicator,
  formatStatusIndicator,
  getStatusColor,
  getStaticDot,
};
