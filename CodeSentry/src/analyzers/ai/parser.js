const VALID_SEVERITIES = ['HIGH', 'MEDIUM', 'LOW'];
const VALID_CONFIDENCE_RANGE = { min: 0.0, max: 1.0 };

class AIResponseParser {
  constructor(options = {}) {
    this.strictMode = options.strictMode || false;
  }

  parse(response) {
    if (!response) {
      throw new Error('AI response is empty');
    }

    if (typeof response === 'string') {
      return this.parseJSON(response);
    }

    if (typeof response === 'object') {
      return this.validateObject(response);
    }

    throw new Error('Invalid AI response format');
  }

  parseJSON(jsonString) {
    try {
      // Try to extract JSON from the response (non-greedy match)
      const jsonMatch = jsonString.match(/\{[\s\S]*?\}/);
      if (!jsonMatch) {
        throw new Error('No JSON object found in response');
      }

      const parsed = JSON.parse(jsonMatch[0]);
      return this.validateObject(parsed);
    } catch (error) {
      if (error.message.includes('JSON')) {
        throw new Error(`Failed to parse AI response JSON: ${error.message}`);
      }
      throw error;
    }
  }

  validateObject(obj) {
    const errors = [];

    // Validate required fields
    if (!obj.explanation || typeof obj.explanation !== 'string') {
      errors.push('Missing or invalid "explanation" field');
    }

    if (!obj.severity || !VALID_SEVERITIES.includes(obj.severity)) {
      errors.push(`Invalid "severity" field. Must be one of: ${VALID_SEVERITIES.join(', ')}`);
    }

    if (typeof obj.confidence !== 'number' || 
        obj.confidence < VALID_CONFIDENCE_RANGE.min || 
        obj.confidence > VALID_CONFIDENCE_RANGE.max) {
      errors.push(`Invalid "confidence" field. Must be between ${VALID_CONFIDENCE_RANGE.min} and ${VALID_CONFIDENCE_RANGE.max}`);
    }

    if (typeof obj.falsePositiveProbability !== 'number' || 
        obj.falsePositiveProbability < VALID_CONFIDENCE_RANGE.min || 
        obj.falsePositiveProbability > VALID_CONFIDENCE_RANGE.max) {
      errors.push(`Invalid "falsePositiveProbability" field. Must be between ${VALID_CONFIDENCE_RANGE.min} and ${VALID_CONFIDENCE_RANGE.max}`);
    }

    if (!obj.impact || typeof obj.impact !== 'string') {
      errors.push('Missing or invalid "impact" field');
    }

    if (!obj.suggestedFix || typeof obj.suggestedFix !== 'string') {
      errors.push('Missing or invalid "suggestedFix" field');
    }

    if (errors.length > 0) {
      if (this.strictMode) {
        throw new Error(`AI response validation failed: ${errors.join('; ')}`);
      }
      
      // In non-strict mode, try to fix or provide defaults
      return this.repairObject(obj, errors);
    }

    return this.normalizeObject(obj);
  }

  repairObject(obj, errors) {
    const repaired = { ...obj };

    // Fix missing explanation
    if (!repaired.explanation || typeof repaired.explanation !== 'string') {
      repaired.explanation = 'AI analysis completed but explanation was not provided.';
    }

    // Fix invalid severity
    if (!repaired.severity || !VALID_SEVERITIES.includes(repaired.severity)) {
      repaired.severity = 'MEDIUM';
    }

    // Fix invalid confidence
    if (typeof repaired.confidence !== 'number' || 
        repaired.confidence < VALID_CONFIDENCE_RANGE.min || 
        repaired.confidence > VALID_CONFIDENCE_RANGE.max) {
      repaired.confidence = 0.5;
    }

    // Fix invalid falsePositiveProbability
    if (typeof repaired.falsePositiveProbability !== 'number' || 
        repaired.falsePositiveProbability < VALID_CONFIDENCE_RANGE.min || 
        repaired.falsePositiveProbability > VALID_CONFIDENCE_RANGE.max) {
      repaired.falsePositiveProbability = 0.2;
    }

    // Fix missing impact
    if (!repaired.impact || typeof repaired.impact !== 'string') {
      repaired.impact = 'Impact assessment requires manual review.';
    }

    // Fix missing suggestedFix
    if (!repaired.suggestedFix || typeof repaired.suggestedFix !== 'string') {
      repaired.suggestedFix = 'Review the code and apply appropriate remediation.';
    }

    return this.normalizeObject(repaired);
  }

  normalizeObject(obj) {
    return {
      explanation: String(obj.explanation),
      severity: String(obj.severity).toUpperCase(),
      confidence: Number(obj.confidence),
      falsePositiveProbability: Number(obj.falsePositiveProbability),
      impact: String(obj.impact),
      suggestedFix: String(obj.suggestedFix),
    };
  }

  parseCorrelationResponse(response) {
    try {
      const parsed = this.parse(response);
      
      if (!parsed.correlations || !Array.isArray(parsed.correlations)) {
        return {
          correlations: [],
          rootCause: parsed.rootCause || 'Unable to determine root cause',
          prioritizedFixes: parsed.prioritizedFixes || [],
        };
      }

      return {
        correlations: parsed.correlations.map(c => ({
          findingIndices: Array.isArray(c.findingIndices) ? c.findingIndices : [],
          relationship: String(c.relationship || ''),
          riskLevel: VALID_SEVERITIES.includes(c.riskLevel) ? c.riskLevel : 'MEDIUM',
          explanation: String(c.explanation || ''),
        })),
        rootCause: String(parsed.rootCause || ''),
        prioritizedFixes: Array.isArray(parsed.prioritizedFixes) ? parsed.prioritizedFixes : [],
      };
    } catch (error) {
      return {
        correlations: [],
        rootCause: 'Failed to parse correlation analysis',
        prioritizedFixes: [],
      };
    }
  }

  parseSeverityReconciliation(response) {
    try {
      const parsed = this.parse(response);
      
      return {
        reconciledSeverity: VALID_SEVERITIES.includes(parsed.reconciledSeverity) 
          ? parsed.reconciledSeverity 
          : 'MEDIUM',
        reconciledConfidence: typeof parsed.reconciledConfidence === 'number' 
          ? parsed.reconciledConfidence 
          : 0.5,
        reasoning: String(parsed.reasoning || ''),
      };
    } catch (error) {
      return {
        reconciledSeverity: 'MEDIUM',
        reconciledConfidence: 0.5,
        reasoning: 'Failed to parse severity reconciliation',
      };
    }
  }
}

function createAIResponseParser(options = {}) {
  return new AIResponseParser(options);
}

module.exports = {
  AIResponseParser,
  createAIResponseParser,
  VALID_SEVERITIES,
  VALID_CONFIDENCE_RANGE,
};