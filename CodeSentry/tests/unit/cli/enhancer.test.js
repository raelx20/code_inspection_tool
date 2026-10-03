'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  extractProjectContext,
  queryAISecuritySuggestions,
  formatAISuggestionCard,
  exportAISuggestionsToMarkdown,
} = require('../../../src/cli/enhancer');

describe('AI Security Enhancer', () => {
  it('should extract project context including package.json dependencies', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentry-ctx-'));
    const pkg = {
      name: 'secure-api',
      dependencies: { express: '^4.18.2' },
      devDependencies: { typescript: '^5.0.0' },
    };
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(pkg));

    const ctx = extractProjectContext(tmpDir);
    assert.equal(ctx.projectName, path.basename(tmpDir));
    assert.ok(ctx.languages.includes('javascript'));
    assert.ok(ctx.languages.includes('typescript'));
    assert.ok(ctx.frameworks.includes('express'));

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should query AI model and return structured suggestions in mock mode', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentry-ai-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'node-app', dependencies: { express: '4.0.0' } }));

    const res = await queryAISecuritySuggestions(tmpDir, {
      mockMode: true,
      model: 'poolside/laguna-s-2.1:free',
    });

    assert.ok(res.model.includes('laguna-s-2.1'));
    assert.ok(res.summary);
    assert.ok(Array.isArray(res.suggestions));
    assert.ok(res.suggestions.length >= 2);

    const first = res.suggestions[0];
    assert.ok(first.title);
    assert.ok(first.explanation);
    assert.ok(first.suggestedFix);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should format AI suggestion card with model attribution and code', () => {
    const suggestion = {
      title: 'Harden HTTP Security Headers',
      category: 'headers',
      priority: 'HIGH',
      explanation: 'Protect endpoints against clickjacking and MIME sniffing.',
      suggestedFix: 'Install helmet middleware.',
      codeExample: "const helmet = require('helmet');\napp.use(helmet());",
    };

    const card = formatAISuggestionCard(suggestion, 0, 3, 'poolside/laguna-s-2.1:free');
    assert.ok(card);
    assert.ok(card.includes('Harden HTTP Security Headers'));
    assert.ok(card.includes('AI SECURITY HARDENING'));
    assert.ok(card.includes('laguna-s-2.1'));
  });

  it('should export AI suggestions to markdown file cleanly', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codesentry-export-'));
    const aiResult = {
      model: 'poolside/laguna-s-2.1:free',
      summary: 'Baseline clean. Implement defense-in-depth.',
      suggestions: [
        {
          title: 'Implement Helmet',
          category: 'headers',
          priority: 'HIGH',
          explanation: 'Essential headers protection.',
          suggestedFix: 'Install helmet.',
          codeExample: 'app.use(helmet());',
        },
      ],
    };

    const exportedPath = exportAISuggestionsToMarkdown(tmpDir, aiResult);
    assert.ok(fs.existsSync(exportedPath));
    const content = fs.readFileSync(exportedPath, 'utf8');

    assert.ok(content.includes('# 🤖 AI Proactive Security Hardening Suggestions'));
    assert.ok(content.includes('laguna-s-2.1'));
    assert.ok(content.includes('Implement Helmet'));
    assert.ok(content.includes('app.use(helmet());'));

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
