const SEVERITY_WEIGHTS = {
  BLOCKER: 10,
  HIGH: 5,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

function score(aggregation) {
  if (!aggregation || typeof aggregation !== 'object') {
    throw new Error('aggregation must be an object');
  }

  const { total, bySeverity } = aggregation;

  if (total === 0) {
    return { value: 100, max: 100, breakdown: {} };
  }

  let penalty = 0;
  const breakdown = {};

  for (const [severity, count] of Object.entries(bySeverity)) {
    const weight = SEVERITY_WEIGHTS[severity] || 0;
    const severityPenalty = weight * count;
    penalty += severityPenalty;
    if (severityPenalty > 0) {
      breakdown[severity] = severityPenalty;
    }
  }

  // Calculate max possible penalty based on actual findings' severities
  // (if all findings were BLOCKER severity)
  const maxPossiblePenalty = total * SEVERITY_WEIGHTS.BLOCKER;
  const value = Math.max(0, Math.round(100 - (penalty / maxPossiblePenalty) * 100));

  return {
    value,
    max: 100,
    penalty,
    maxPossiblePenalty,
    breakdown,
  };
}

module.exports = {
  score,
  SEVERITY_WEIGHTS,
};
