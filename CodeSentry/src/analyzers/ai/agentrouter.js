/**
 * AgentRouter AI Client for CodeSentry
 *
 * Provides a resilient, high-speed alternative to OpenRouter for code repair
 * and semantic inspection. Implements the standard CodeSentry AI adapter interface:
 *   - repairFileBatch({ filePath, originalContent, findings, preferredModel })
 *   - chatCompletion({ messages, model, temperature, maxTokens })
 *   - mockMode
 *
 * Endpoint: https://agentrouter.ai/v1 (or AGENTROUTER_BASE_URL)
 */

'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');

const AGENTROUTER_BASE_URL = process.env.AGENTROUTER_BASE_URL || 'https://agentrouter.ai/v1';

// 50+ Model Catalog for AgentRouter
const AGENTROUTER_MODELS = {
  // Flagship reasoning & coding
  MINIMAX_M3:             'minimax/minimax-m3',
  DEEPSEEK_CHAT:          'deepseek/deepseek-chat',
  DEEPSEEK_R1:            'deepseek/deepseek-r1',
  QWEN_CODER_32B:         'qwen/qwen-2.5-coder-32b-instruct',
  LLAMA_3_3_70B:          'meta-llama/llama-3.3-70b-instruct',
  CLAUDE_SONNET_3_7:      'anthropic/claude-3.7-sonnet',
  CLAUDE_SONNET_3_5:      'anthropic/claude-3.5-sonnet',
  GPT_4O:                 'openai/gpt-4o',
  GEMINI_2_5_PRO:         'google/gemini-2.5-pro',
  CODESTRAL_2501:         'mistralai/codestral-2501',

  // Fast / Budget models
  DEEPSEEK_V4_1_FLASH:    'deepseek/deepseek-v4.1-flash',
  QWEN_3_8_FLASH:         'qwen/qwen3.8-flash',
  GEMINI_3_8_FLASH:       'google/gemini-3.8-flash',
  GEMINI_2_FLASH_001:     'google/gemini-2.0-flash-001',
  GPT_4O_MINI:            'openai/gpt-4o-mini',
  CLAUDE_3_HAIKU:         'anthropic/claude-3-haiku',
  MISTRAL_SMALL_24B:      'mistralai/mistral-small-24b-instruct-2501',

  // Free Tier
  AGENTROUTER_FREE:       'agentrouter/free',
  GEMINI_2_FLASH_FREE:    'google/gemini-2.0-flash-exp:free',
  DEEPSEEK_R1_FREE:       'deepseek/deepseek-r1:free',
  DEEPSEEK_CHAT_FREE:     'deepseek/deepseek-chat:free',
  LLAMA_3_3_70B_FREE:     'meta-llama/llama-3.3-70b-instruct:free',
  QWEN_CODER_32B_FREE:    'qwen/qwen-2.5-coder-32b-instruct:free',
};

const AGENTROUTER_FALLBACK_CHAIN = [
  'minimax/minimax-m3',
  'deepseek/deepseek-chat',
  'qwen/qwen-2.5-coder-32b-instruct',
  'google/gemini-2.0-flash-exp:free',
  'deepseek/deepseek-chat:free',
  'meta-llama/llama-3.3-70b-instruct:free',
  'openai/gpt-4o-mini',
];

function selectModel(scanContext = {}) {
  if (scanContext.model) return scanContext.model;
  return AGENTROUTER_MODELS.MINIMAX_M3;
}

class AgentRouterClient {
  constructor(options = {}) {
    this.provider = 'agentrouter';
    this.apiKey = options.apiKey || process.env.AGENTROUTER_API_KEY || process.env.OPENROUTER_API_KEY || '';
    this.baseUrl = options.baseUrl || AGENTROUTER_BASE_URL;
    this.model = options.model || selectModel(options.scanContext);
    this.maxTokens = options.maxTokens || 4096;
    this.temperature = options.temperature ?? 0.1;
    this.timeout = options.timeout || 8000;
    this.mockMode = Boolean(options.mockMode);
  }

  async chatCompletion({ messages, model, temperature, maxTokens, timeout }) {
    if (this.mockMode || !this.apiKey) {
      return {
        content: `// CodeSentry mock AI repair\n${messages[messages.length - 1].content.slice(0, 100)}`,
        model: model || this.model,
      };
    }

    const effectiveModel = model || this.model;
    const effectiveTimeout = timeout || this.timeout;
    const bodyData = JSON.stringify({
      model: effectiveModel,
      messages,
      temperature: temperature ?? this.temperature,
      max_tokens: maxTokens || this.maxTokens,
    });

    const parsedUrl = new URL(`${this.baseUrl}/chat/completions`);
    const isHttps = parsedUrl.protocol === 'https:';
    const requestFn = isHttps ? https.request : http.request;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        req.destroy(new Error(`AgentRouter request timed out after ${effectiveTimeout}ms`));
      }, effectiveTimeout);

      const req = requestFn(parsedUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'x-api-key': this.apiKey,
          'User-Agent': 'claude-cli/1.0 (external, cli)',
          'anthropic-version': '2023-06-01',
          'HTTP-Referer': 'https://github.com/codesentry',
          'X-Title': 'CodeSentry Autonomous Inspection & Repair',
          'Content-Length': Buffer.byteLength(bodyData),
        },
      }, (res) => {
        let rawData = '';
        res.on('data', (chunk) => { rawData += chunk; });
        res.on('end', () => {
          clearTimeout(timer);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const parsed = JSON.parse(rawData);
              const messageContent = parsed.choices?.[0]?.message?.content || '';
              resolve({
                content: messageContent,
                model: parsed.model || effectiveModel,
                usage: parsed.usage,
              });
            } catch (err) {
              reject(new Error(`Failed to parse AgentRouter response: ${err.message}`));
            }
          } else {
            reject(new Error(`AgentRouter HTTP ${res.statusCode}: ${rawData.slice(0, 200)}`));
          }
        });
      });

      req.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      req.write(bodyData);
      req.end();
    });
  }

  async repairFileBatch(options = {}) {
    const file = options.file || options.filePath || '';
    const fileContent = options.fileContent || options.originalContent || '';
    const findings = options.findings || [];
    const preferredModel = options.preferredModel;
    const onModelSwitch = options.onModelSwitch;

    const modelsToTry = [preferredModel || this.model, ...AGENTROUTER_FALLBACK_CHAIN].filter(
      (m, idx, arr) => arr.indexOf(m) === idx
    );

    const issuesSummary = findings.map((f, i) =>
      `${i + 1}. Line ${f.line || 1} [${f.rule || f.category}]: ${f.message}${f.suggestedFix ? ` -> Recommended: ${f.suggestedFix}` : ''}`
    ).join('\n');

    const prompt = [
      `File: ${file}`,
      'The static analysis engine found the following issues in this file:',
      issuesSummary,
      '',
      'Source code of the file:',
      '\`\`\`',
      fileContent,
      '\`\`\`',
      '',
      'Please resolve ALL of the above issues in this file simultaneously.',
      'Respond with ONLY a JSON object in this format:',
      '{"fixes": [{"explanation": "...", "oldSnippet": "exact code substring to replace", "newSnippet": "replacement code"}]}',
    ].join('\n');

    const messages = [
      { role: 'system', content: 'You are CodeSentry automated code repair engine. Respond with valid JSON only.' },
      { role: 'user',   content: prompt },
    ];

    let lastError = null;
    for (let i = 0; i < modelsToTry.length; i++) {
      const activeModel = modelsToTry[i];
      try {
        const res = await this.chatCompletion({
          model: activeModel,
          messages,
          timeout: 8000,
        });

        const fixes = this._parseBatchRepairResponse(res.content, fileContent);
        if (fixes && fixes.length > 0) {
          return {
            fixes,
            modelUsed: activeModel,
            switchedFrom: i > 0 ? modelsToTry[0] : null,
          };
        }
      } catch (err) {
        lastError = err;
        const isQuota = /free-models-per-day|rate limit|quota|credit|balance|insufficient|429|402/i.test(err.message || '');
        if (isQuota) {
          // Account-level quota / rate limit reached: all models on this tier will fail. Stop immediately.
          break;
        }
        if (onModelSwitch && i + 1 < modelsToTry.length) {
          onModelSwitch({
            failedModel: activeModel,
            nextModel: modelsToTry[i + 1],
            error: err.message,
            isTokenExpire: false,
          });
        }
      }
    }

    return {
      fixes: [],
      error: lastError?.message || 'AgentRouter repair unavailable; using offline deterministic rules',
    };
  }

  _parseBatchRepairResponse(content, fileContent) {
    try {
      if (!content) return null;
      let cleaned = content.trim();
      cleaned = cleaned.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
      cleaned = cleaned.replace(/^\`\`\`(?:json)?\s*/i, '').replace(/\s*\`\`\`$/i, '');
      const jsonMatch = cleaned.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
      if (!jsonMatch) return null;

      const parsed = JSON.parse(jsonMatch[0]);
      const list = Array.isArray(parsed) ? parsed : (parsed.fixes || [parsed]);
      const validFixes = [];
      const normalizedFileContent = (fileContent || '').replace(/\r\n/g, '\n');

      for (const item of list) {
        if (item && item.oldSnippet && item.newSnippet) {
          let old = item.oldSnippet;
          const normalizedOld = old.replace(/\r\n/g, '\n');

          if (fileContent && !fileContent.includes(old)) {
            if (normalizedFileContent.includes(normalizedOld)) {
              old = normalizedOld;
            } else {
              const trimmed = old.trim();
              if (fileContent.includes(trimmed) || normalizedFileContent.includes(trimmed)) {
                old = trimmed;
              } else {
                continue;
              }
            }
          }
          validFixes.push({
            oldSnippet: old,
            newSnippet: item.newSnippet,
            explanation: item.explanation || 'Applied AI batch code repair',
          });
        }
      }
      return validFixes.length > 0 ? validFixes : null;
    } catch {
      return null;
    }
  }
}

function createAgentRouterClient(options = {}) {
  return new AgentRouterClient(options);
}

module.exports = {
  createAgentRouterClient,
  AGENTROUTER_MODELS,
  AGENTROUTER_FALLBACK_CHAIN,
  selectModel,
};
