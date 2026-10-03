function verdict(scoreResult) {
  if (!scoreResult || typeof scoreResult !== 'object') {
    throw new Error('scoreResult must be an object');
  }

  const { value } = scoreResult;

  if (typeof value !== 'number') {
    throw new Error('scoreResult.value must be a number');
  }

  if (value >= 80) {
    return {
      status: 'PASS',
      message: 'Codebase meets quality thresholds.',
      score: value,
    };
  }

  if (value >= 50) {
    return {
      status: 'WARN',
      message: 'Codebase has moderate issues that should be addressed.',
      score: value,
    };
  }

  return {
    status: 'FAIL',
    message: 'Codebase has significant issues that must be resolved.',
    score: value,
  };
}

module.exports = {
  verdict,
};
