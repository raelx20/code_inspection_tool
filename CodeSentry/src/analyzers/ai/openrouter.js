/**
 * OpenRouter AI Client for CodeSentry
 *
 * Implements the same adapter interface as anthropic.js:
 *   - analyze(prompt)          — single-prompt analysis
 *   - analyzeFindings(findings, discoveryResult) — batch finding analysis
 *   - mockMode                 — local testing without API key
 *   - setModelForContext(ctx)  — auto-select model based on codebase complexity
 *
 * All prompts are formatted as OpenAI-compatible messages:
 *   [{ role: "system", content: "..." }, { role: "user", content: "..." }]
 */

// ---------------------------------------------------------------------------
// Model catalogue – grouped by tier (verified live against OpenRouter API)
// ---------------------------------------------------------------------------
const OPENROUTER_MODELS = {
  // ── Tier 1: Premier Flagship Coding Benchmark Models (paid) ──
  MINIMAX_M3:             'minimax/minimax-m3',
  DEEPSEEK_CHAT:          'deepseek/deepseek-chat',
  DEEPSEEK_R1:            'deepseek/deepseek-r1',
  QWEN_CODER_32B:         'qwen/qwen-2.5-coder-32b-instruct',
  LLAMA_3_3_70B:          'meta-llama/llama-3.3-70b-instruct',
  QWEN_72B:               'qwen/qwen-2.5-72b-instruct',
  MINIMAX_M2_5:           'minimax/minimax-m2.5',
  GLM_5_2:                'z-ai/glm-5.2',
  CLAUDE_SONNET_3_7:      'anthropic/claude-3.7-sonnet',
  CLAUDE_SONNET_3_5:      'anthropic/claude-3.5-sonnet',
  GPT_4O:                 'openai/gpt-4o',
  GEMINI_2_5_PRO:         'google/gemini-2.5-pro',
  CODESTRAL_2501:         'mistralai/codestral-2501',
  MINIMAX_M1:             'minimax/minimax-01',

  // ── Tier 2: Ultra-Cheap Paid Models (< $0.5/M input tokens) ──
  DEEPSEEK_V4_1_FLASH:    'deepseek/deepseek-v4.1-flash',
  QWEN_3_8_FLASH:         'qwen/qwen3.8-flash',
  QWEN_3_8_MAX:           'qwen/qwen3.8-max-0902',
  INCEPTION_MERCURY_2_5:  'inception/mercury-2.5',
  GLM_5_3_FLASH:          'z-ai/glm-5.3-flash',
  GEMINI_3_8_FLASH:       'google/gemini-3.8-flash',
  GEMINI_2_FLASH_001:     'google/gemini-2.0-flash-001',
  GPT_4O_MINI:            'openai/gpt-4o-mini',
  GPT_5_NANO:             'openai/gpt-5-nano',
  GPT_OSS_120B:           'openai/gpt-oss-120b',
  CLAUDE_3_HAIKU:         'anthropic/claude-3-haiku',
  MUSE_SPARK_CONTRIBUTOR: 'meta/muse-spark-1.3-contributor',
  GRANITE_4_2_8B:         'ibm-granite/granite-4.2-8b',
  PHI_3_5_MINI:           'microsoft/phi-3.5-mini-128k-instruct',
  MISTRAL_SMALL_24B:      'mistralai/mistral-small-24b-instruct-2501',

  // ── Tier 3: Verified Free / Zero-Cost Models ──
  OPENROUTER_FREE:        'openrouter/free',
  GEMINI_2_FLASH_FREE:    'google/gemini-2.0-flash-exp:free',
  GEMINI_2_PRO_FREE:      'google/gemini-2.0-pro-exp-02-05:free',
  DEEPSEEK_R1_FREE:       'deepseek/deepseek-r1:free',
  DEEPSEEK_CHAT_FREE:     'deepseek/deepseek-chat:free',
  LLAMA_3_3_70B_FREE:     'meta-llama/llama-3.3-70b-instruct:free',
  QWEN_CODER_32B_FREE:    'qwen/qwen-2.5-coder-32b-instruct:free',
  MISTRAL_SMALL_FREE:     'mistralai/mistral-small-24b-instruct-2501:free',
  NEMOTRON_70B_FREE:      'nvidia/llama-3.1-nemotron-70b-instruct:free',
  NEMOTRON_NANO_OMNI:     'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free',
  NEX_N2_5_PRO:           'nex-agi/nex-n2.5-pro:free',
  NEX_N2_5_MINI:          'nex-agi/nex-n2.5-mini:free',
  NEMOTRON_3_5_LIGHTNING: 'nvidia/nemotron-3.5-lightning:free',
  NORTH_MINI_CODE:        'cohere/north-mini-code:free',
  NEMOTRON_3_SUPER:       'nvidia/nemotron-3-super-120b-a12b:free',
  LIQUID_LFM_2_5:         'liquid/lfm-2.5-2.6b:free',
  INKLING:                'thinkingmachines/inkling:free',
  INKLING_SMALL:          'thinkingmachines/inkling-small:free',
  LAGUNA_XS_2_1:          'poolside/laguna-xs-2.1:free',
  GEMMA_4_26B:            'google/gemma-4-26b-a4b-it:free',
  DOTS_3_NOTE:            'dots-studio/dots-3-note-preview:free',
  LING_3_FLASH_FIN:       'inclusionai/ling-3.0-flash-fin:free',
  LING_3_FLASH_SANTE:     'inclusionai/ling-3.0-flash-sante:free',

  // ── Backward-compatible Aliases (verified live) ──
  LAGUNA_S_2_1:           'poolside/laguna-s-2.1:free',
  NEMOTRON_3_ULTRA:       'nvidia/nemotron-3-ultra-550b-a55b:free',
  GEMMA_4_31B:            'google/gemma-4-31b-it:free',

  // ── Ultimate fallback (OpenRouter auto-routing) ──
  OPENROUTER_AUTO:        'openrouter/auto',
};

// Dedicated free-tier fallback chain for zero-cost operation
const FREE_MODEL_FALLBACK_CHAIN = [
  OPENROUTER_MODELS.NEMOTRON_NANO_OMNI,
  OPENROUTER_MODELS.NEMOTRON_3_5_LIGHTNING,
  OPENROUTER_MODELS.NORTH_MINI_CODE,
  OPENROUTER_MODELS.LAGUNA_S_2_1,
  OPENROUTER_MODELS.NEX_N2_5_PRO,
  OPENROUTER_MODELS.NEX_N2_5_MINI,
  OPENROUTER_MODELS.INKLING,
  OPENROUTER_MODELS.INKLING_SMALL,
  OPENROUTER_MODELS.OPENROUTER_FREE,
  OPENROUTER_MODELS.DEEPSEEK_CHAT_FREE,
  OPENROUTER_MODELS.DEEPSEEK_R1_FREE,
  OPENROUTER_MODELS.GEMINI_2_FLASH_FREE,
  OPENROUTER_MODELS.GEMINI_2_PRO_FREE,
  OPENROUTER_MODELS.LLAMA_3_3_70B_FREE,
  OPENROUTER_MODELS.QWEN_CODER_32B_FREE,
  OPENROUTER_MODELS.MISTRAL_SMALL_FREE,
  OPENROUTER_MODELS.NEMOTRON_70B_FREE,
  OPENROUTER_MODELS.NEMOTRON_3_SUPER,
  OPENROUTER_MODELS.LAGUNA_XS_2_1,
  OPENROUTER_MODELS.GEMMA_4_31B,
  OPENROUTER_MODELS.GEMMA_4_26B,
  OPENROUTER_MODELS.NEMOTRON_3_ULTRA,
  OPENROUTER_MODELS.DOTS_3_NOTE,
  OPENROUTER_MODELS.LING_3_FLASH_FIN,
  OPENROUTER_MODELS.LING_3_FLASH_SANTE,
  OPENROUTER_MODELS.LIQUID_LFM_2_5,
  OPENROUTER_MODELS.OPENROUTER_AUTO,
];

// Ordered fallback chain – tried in sequence when the primary model errors
// Paid models first (cheapest → expensive), then free models, then auto
const MODEL_FALLBACK_CHAIN = [
  // ── Tier 1: Premier paid coding models ──
  OPENROUTER_MODELS.MINIMAX_M3,
  OPENROUTER_MODELS.DEEPSEEK_CHAT,
  OPENROUTER_MODELS.DEEPSEEK_R1,
  OPENROUTER_MODELS.QWEN_CODER_32B,
  OPENROUTER_MODELS.LLAMA_3_3_70B,
  OPENROUTER_MODELS.QWEN_72B,
  OPENROUTER_MODELS.MINIMAX_M2_5,
  OPENROUTER_MODELS.GLM_5_2,
  OPENROUTER_MODELS.CLAUDE_SONNET_3_7,
  OPENROUTER_MODELS.CLAUDE_SONNET_3_5,
  OPENROUTER_MODELS.GPT_4O,
  OPENROUTER_MODELS.GEMINI_2_5_PRO,
  OPENROUTER_MODELS.CODESTRAL_2501,
  OPENROUTER_MODELS.MINIMAX_M1,
  // ── Tier 2: Ultra-cheap paid (< $0.5/M tokens) ──
  OPENROUTER_MODELS.DEEPSEEK_V4_1_FLASH,
  OPENROUTER_MODELS.QWEN_3_8_FLASH,
  OPENROUTER_MODELS.INCEPTION_MERCURY_2_5,
  OPENROUTER_MODELS.GLM_5_3_FLASH,
  OPENROUTER_MODELS.GEMINI_3_8_FLASH,
  OPENROUTER_MODELS.GEMINI_2_FLASH_001,
  OPENROUTER_MODELS.GPT_4O_MINI,
  OPENROUTER_MODELS.GPT_5_NANO,
  OPENROUTER_MODELS.GPT_OSS_120B,
  OPENROUTER_MODELS.CLAUDE_3_HAIKU,
  OPENROUTER_MODELS.MUSE_SPARK_CONTRIBUTOR,
  OPENROUTER_MODELS.GRANITE_4_2_8B,
  OPENROUTER_MODELS.PHI_3_5_MINI,
  OPENROUTER_MODELS.MISTRAL_SMALL_24B,
  OPENROUTER_MODELS.QWEN_3_8_MAX,
  // ── Tier 3: Free models ──
  OPENROUTER_MODELS.OPENROUTER_FREE,
  OPENROUTER_MODELS.GEMINI_2_FLASH_FREE,
  OPENROUTER_MODELS.GEMINI_2_PRO_FREE,
  OPENROUTER_MODELS.DEEPSEEK_R1_FREE,
  OPENROUTER_MODELS.DEEPSEEK_CHAT_FREE,
  OPENROUTER_MODELS.LLAMA_3_3_70B_FREE,
  OPENROUTER_MODELS.QWEN_CODER_32B_FREE,
  OPENROUTER_MODELS.MISTRAL_SMALL_FREE,
  OPENROUTER_MODELS.NEMOTRON_70B_FREE,
  OPENROUTER_MODELS.NEMOTRON_NANO_OMNI,
  OPENROUTER_MODELS.NEX_N2_5_PRO,
  OPENROUTER_MODELS.NEX_N2_5_MINI,
  OPENROUTER_MODELS.INKLING,
  OPENROUTER_MODELS.INKLING_SMALL,
  OPENROUTER_MODELS.NEMOTRON_3_5_LIGHTNING,
  OPENROUTER_MODELS.NORTH_MINI_CODE,
  OPENROUTER_MODELS.NEMOTRON_3_SUPER,
  OPENROUTER_MODELS.LAGUNA_S_2_1,
  OPENROUTER_MODELS.LAGUNA_XS_2_1,
  OPENROUTER_MODELS.GEMMA_4_31B,
  OPENROUTER_MODELS.GEMMA_4_26B,
  OPENROUTER_MODELS.NEMOTRON_3_ULTRA,
  OPENROUTER_MODELS.DOTS_3_NOTE,
  OPENROUTER_MODELS.LING_3_FLASH_FIN,
  OPENROUTER_MODELS.LING_3_FLASH_SANTE,
  OPENROUTER_MODELS.LIQUID_LFM_2_5,
  OPENROUTER_MODELS.OPENROUTER_AUTO,
];

// Absolute last resort — OpenRouter picks whatever free model is available
const LAST_RESORT_MODEL = OPENROUTER_MODELS.OPENROUTER_AUTO;

const DEFAULT_MODEL  = OPENROUTER_MODELS.LAGUNA_S_2_1;
const COMPLEX_MODEL  = OPENROUTER_MODELS.NEMOTRON_3_ULTRA;

// ---------------------------------------------------------------------------
// AgentRouter Configuration — Alternative to OpenRouter
// ---------------------------------------------------------------------------
const AGENTROUTER_DEFAULTS = {
  baseUrl: process.env.AGENTROUTER_BASE_URL || 'https://agentrouter.ai/v1',
  apiKey: process.env.AGENTROUTER_API_KEY || null,
};


// ---------------------------------------------------------------------------
// Complexity heuristics
// ---------------------------------------------------------------------------
const COMPLEXITY_THRESHOLDS = {
  fileCount: 50,
  languageCount: 3,
  totalLines: 5000,
  complexLanguages: ['typescript', 'python', 'java', 'go', 'rust'],
};

function calculateComplexity(scanContext) {
  if (!scanContext) return { score: 0, level: 'simple' };

  const fileCount     = scanContext.files?.length || 0;
  const languages     = scanContext.languages || [];
  const languageCount = languages.length;

  let totalLines = 0;
  if (scanContext.files) {
    for (const file of scanContext.files) {
      totalLines += file.lines || 0;
    }
  }

  let score = 0;
  score += Math.min(fileCount / COMPLEXITY_THRESHOLDS.fileCount, 1) * 30;
  score += Math.min(languageCount / COMPLEXITY_THRESHOLDS.languageCount, 1) * 20;
  score += Math.min(totalLines / COMPLEXITY_THRESHOLDS.totalLines, 1) * 30;

  const hasComplexLang = languages.some(l =>
    COMPLEXITY_THRESHOLDS.complexLanguages.includes(l.toLowerCase())
  );
  if (hasComplexLang) score += 20;

  if (score >= 70) return { score, level: 'complex' };
  if (score >= 40) return { score, level: 'moderate' };
  return { score, level: 'simple' };
}

function selectModel(scanContext, forceModel = null) {
  if (forceModel) return forceModel;

  const envModel = process.env.OPENROUTER_MODEL;
  if (envModel && envModel !== 'auto') return envModel;

  const { level } = calculateComplexity(scanContext);
  return level === 'complex' ? COMPLEX_MODEL : DEFAULT_MODEL;
}

// ---------------------------------------------------------------------------
// System prompt – shared across all calls
// ---------------------------------------------------------------------------
const SYSTEM_PROMPT = [
  'You are CodeSentry, an expert static-analysis AI that reviews code findings.',
  'You MUST respond with valid JSON only — no markdown fences, no commentary.',
  'Every response must be a single JSON object with these exact keys:',
  '  "explanation"  (string)  — concise technical explanation',
  '  "severity"     (string)  — one of HIGH, MEDIUM, LOW',
  '  "confidence"   (number)  — 0.0 to 1.0',
  '  "falsePositiveProbability" (number) — 0.0 to 1.0',
  '  "impact"       (string)  — brief impact description',
  '  "suggestedFix" (string)  — actionable fix recommendation',
].join('\n');

const REPAIR_SYSTEM_PROMPT = [
  'You are CodeSentry Automated Code Repair Assistant.',
  'Your job is to generate a functional, production-ready code repair for a detected code finding.',
  'CRITICAL RULES:',
  '1. You MUST produce a REAL code fix that fixes the bug, vulnerability, or inefficiency — never just add a comment.',
  '2. You MUST respond with valid JSON only — no markdown fences, no conversational text.',
  '3. The JSON object must have EXACTLY these three keys:',
  '   "explanation"  (string) — concise 1-sentence technical explanation of what was changed',
  '   "oldSnippet"   (string) — the EXACT substring from the original code to be replaced',
  '   "newSnippet"   (string) — the drop-in replacement code that resolves the issue',
  '4. "oldSnippet" MUST match the source code snippet exactly (including whitespace/indentation) so string replacement succeeds.',
].join('\n');

const BATCH_REPAIR_SYSTEM_PROMPT = [
  'You are CodeSentry Automated Code Repair Assistant.',
  'Your job is to fix ALL listed code issues in the provided file simultaneously.',
  'CRITICAL RULES:',
  '1. You MUST produce REAL code fixes that fix the bugs, security flaws, or inefficiencies — never just add comments.',
  '2. You MUST respond with valid JSON only — no markdown fences, no conversational text.',
  '3. The response must be a single JSON object with a "fixes" array:',
  '   {',
  '     "fixes": [',
  '       {',
  '         "explanation": "concise description of this specific change",',
  '         "oldSnippet": "exact substring from the source code to replace",',
  '         "newSnippet": "the replacement code"',
  '       }',
  '     ]',
  '   }',
  '4. "oldSnippet" must match characters in the source file EXACTLY (including indentation) so string replacement succeeds.',
].join('\n');

// ---------------------------------------------------------------------------
// OpenRouterClient (supports OpenRouter + AgentRouter dual-provider failover)
// ---------------------------------------------------------------------------
class OpenRouterClient {
  constructor(options = {}) {
    // ── Provider detection: openrouter (default) or agentrouter ──
    this.provider    = options.provider || process.env.AI_PROVIDER || 'openrouter';
    this.apiKey      = options.apiKey || process.env.OPENROUTER_API_KEY;
    this.model       = options.model  || selectModel(options.scanContext);
    this.maxTokens   = options.maxTokens   || 1024;
    this.temperature = options.temperature || 0.3;
    this.timeout     = options.timeout     || parseInt(process.env.OPENROUTER_TIMEOUT || '8000', 10);
    this.maxRetries  = options.maxRetries || 1;

    // ── OpenRouter config ──
    this.openrouterBaseUrl = 'https://openrouter.ai/api/v1';
    this.openrouterApiKey  = options.apiKey || process.env.OPENROUTER_API_KEY || null;

    // ── AgentRouter config (alternative provider) ──
    this.agentrouterBaseUrl = options.agentrouterBaseUrl || AGENTROUTER_DEFAULTS.baseUrl;
    this.agentrouterApiKey  = options.agentrouterApiKey || AGENTROUTER_DEFAULTS.apiKey || null;

    // ── Active router selection ──
    if (this.provider === 'agentrouter' && this.agentrouterApiKey) {
      this.baseUrl = this.agentrouterBaseUrl;
      this.apiKey  = this.agentrouterApiKey;
    } else if (this.openrouterApiKey) {
      this.baseUrl = this.openrouterBaseUrl;
      this.apiKey  = this.openrouterApiKey;
      this.provider = 'openrouter';
    } else if (this.agentrouterApiKey) {
      this.baseUrl = this.agentrouterBaseUrl;
      this.apiKey  = this.agentrouterApiKey;
      this.provider = 'agentrouter';
    } else {
      this.baseUrl = this.openrouterBaseUrl;
    }

    this.mockMode = options.mockMode !== undefined ? options.mockMode : !this.apiKey;

    // Cross-router failover: if both keys exist, we can switch routers on failure
    this._hasOpenRouter  = Boolean(this.openrouterApiKey);
    this._hasAgentRouter = Boolean(this.agentrouterApiKey);
    this._canCrossFailover = this._hasOpenRouter && this._hasAgentRouter;
  }

  // ── Primary interface (matches anthropic.js) ─────────────────────────────

  /**
   * Analyze a single prompt string.
   * The prompt is sent as the "user" message; a system message is prepended.
   */
  async analyze(prompt) {
    if (this.mockMode) {
      return this.mockAnalysis(prompt);
    }

    const messages = [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user',   content: prompt },
    ];

    return this._callWithFallback(messages);
  }

  /**
   * Convenience: analyze an array of findings, returning enriched findings.
   * This mirrors the pattern used by scan.js → analyzeWithAI().
   */
  async analyzeFindings(findings, discoveryResult, promptGenerator) {
    const analyzed = [];
    const maxFindings = parseInt(process.env.AI_MAX_FINDINGS || '10', 10);
    const batch = findings.slice(0, maxFindings);

    for (const finding of batch) {
      try {
        const sourceContext = this._getSourceContext(finding, discoveryResult);
        const prompt = promptGenerator.generateFindingAnalysisPrompt(finding, sourceContext);
        const aiResult = await this.analyze(prompt);
        analyzed.push({
          ...finding,
          aiAnalysis: {
            explanation: aiResult.explanation,
            confidence: aiResult.confidence,
            falsePositiveProbability: aiResult.falsePositiveProbability,
            impact: aiResult.impact,
            suggestedFix: aiResult.suggestedFix,
            model: this.model,
          },
        });
      } catch {
        analyzed.push(finding);
      }
    }

    const remaining = findings.slice(maxFindings);
    return [...analyzed, ...remaining];
  }

  // ── Code Repair with Dynamic Model Switching ─────────────────────────────

  /**
   * Generates a code repair diff for a finding, with automated multi-model cascading.
   * If the preferred model fails or produces an invalid replacement snippet, it automatically
   * walks down the fallback model chain until a model succeeds.
   */
  async repairCode({ finding, fileContent, line, file, preferredModel, onModelSwitch }) {
    if (this.mockMode) {
      return this.mockRepairCode({ finding, fileContent, line, file });
    }

    const lines = (fileContent || '').split('\n');
    const targetLine = line || finding.line || 1;
    const startIdx = Math.max(0, targetLine - 5);
    const endIdx = Math.min(lines.length - 1, targetLine + 4);
    const contextSnippet = lines.slice(startIdx, endIdx + 1).join('\n');

    const prompt = [
      `File: ${file || finding.file || 'unknown'}`,
      `Line: ${targetLine}`,
      `Rule: ${finding.rule || 'N/A'}`,
      `Category: ${finding.category || 'general'}`,
      `Severity: ${finding.severity || 'MEDIUM'}`,
      `Message: ${finding.message || ''}`,
      finding.suggestedFix ? `Suggested approach: ${finding.suggestedFix}` : '',
      '',
      `Context snippet around line ${targetLine}:`,
      '```',
      contextSnippet,
      '```',
      '',
      'Respond with ONLY a JSON object: {"explanation": "...", "oldSnippet": "...", "newSnippet": "..."}',
    ].filter(Boolean).join('\n');

    const messages = [
      { role: 'system', content: REPAIR_SYSTEM_PROMPT },
      { role: 'user',   content: prompt },
    ];

    // Build prioritized fast fallback chain (max 3-4 candidates to prevent long terminal hangs)
    const isFreeTier = preferredModel === 'free' || (preferredModel && (preferredModel.includes('free') || preferredModel === 'openrouter/free'));
    const primary = preferredModel === 'free' ? OPENROUTER_MODELS.OPENROUTER_FREE : (preferredModel || this.model || OPENROUTER_MODELS.MINIMAX_M3);
    const fallback1 = isFreeTier ? OPENROUTER_MODELS.NEMOTRON_NANO_OMNI : OPENROUTER_MODELS.DEEPSEEK_V4_1_FLASH;
    const fallback2 = isFreeTier ? OPENROUTER_MODELS.NEMOTRON_3_5_LIGHTNING : OPENROUTER_MODELS.NORTH_MINI_CODE;
    const candidatePool = [primary, fallback1, fallback2, LAST_RESORT_MODEL];
    const modelsToTry = [];
    for (const m of candidatePool) {
      if (m && !modelsToTry.includes(m)) modelsToTry.push(m);
    }

    let lastError = null;
    for (let i = 0; i < modelsToTry.length; i++) {
      const modelCandidate = modelsToTry[i];
      try {
        const response = await this._callAPI(messages, modelCandidate);
        const parsed = this._parseRepairResponse(response, fileContent);
        if (parsed && parsed.oldSnippet && parsed.newSnippet) {
          const switchedFrom = modelCandidate !== primary ? primary : null;
          return {
            ...parsed,
            modelUsed: modelCandidate,
            switchedFrom,
          };
        }
        lastError = new Error(`Model ${modelCandidate} returned empty or invalid snippet`);
      } catch (err) {
        lastError = err;
      }

      // If credit is exhausted (HTTP 402), immediately switch remaining candidates to active free models
      if (/402|credit|balance|insufficient/i.test(lastError?.message || '')) {
        const freeCandidates = [
          OPENROUTER_MODELS.NEMOTRON_NANO_OMNI,
          OPENROUTER_MODELS.NEMOTRON_3_5_LIGHTNING,
          OPENROUTER_MODELS.NORTH_MINI_CODE,
          OPENROUTER_MODELS.LAGUNA_S_2_1,
        ];
        const tried = modelsToTry.slice(0, i + 1);
        modelsToTry.splice(i + 1, modelsToTry.length - (i + 1), ...freeCandidates.filter(m => !tried.includes(m)));
      }

      // Check if OpenRouter recommended a replacement model slug
      const slugMatch = lastError?.message?.match(/use this slug instead:\s*([a-zA-Z0-9_./-]+)/i);
      if (slugMatch && slugMatch[1] && !modelsToTry.includes(slugMatch[1])) {
        modelsToTry.splice(i + 1, 0, slugMatch[1]);
      }

      if (i + 1 < modelsToTry.length && typeof onModelSwitch === 'function') {
        const nextModel = modelsToTry[i + 1];
        const isTokenExpire = /token|quota|rate\s*limit|429|402|context\s*length|exceeded|credit|balance|timeout/i.test(lastError?.message || '');
        onModelSwitch({
          failedModel: modelCandidate,
          nextModel,
          error: lastError?.message || 'Failed to generate code repair',
          isTokenExpire,
        });
      }
    }

    return {
      error: `AI repair failed across all models (${modelsToTry.slice(0, 3).join(', ')}...): ${lastError?.message || 'Unable to generate fix'}`,
    };
  }

  _parseRepairResponse(response, fileContent) {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) return null;

      let cleaned = content.trim();
      cleaned = cleaned.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
      cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');
      const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return null;

      const parsed = JSON.parse(jsonMatch[0]);
      if (!parsed.oldSnippet || !parsed.newSnippet) return null;

      if (fileContent && !fileContent.includes(parsed.oldSnippet)) {
        const trimmedOld = parsed.oldSnippet.trim();
        if (fileContent.includes(trimmedOld)) {
          parsed.oldSnippet = trimmedOld;
        }
      }

      return {
        oldSnippet: parsed.oldSnippet,
        newSnippet: parsed.newSnippet,
        explanation: parsed.explanation || 'Applied AI automated code repair',
      };
    } catch {
      return null;
    }
  }

  // ── Holistic File Batch Repair with Dynamic Model Switching ──────────────

  /**
   * Repairs multiple findings across an entire file in ONE single AI call.
   * Sends the file context along with the summary list of all findings.
   * If token limit expires or a model fails, switches models dynamically.
   */
  async repairFileBatch({ file, fileContent, findings, preferredModel, onModelSwitch }) {
    if (this.mockMode) {
      return this.mockRepairFileBatch({ file, fileContent, findings });
    }

    const issuesSummary = findings.map((f, i) =>
      `${i + 1}. Line ${f.line || 1} [${f.rule || f.category}]: ${f.message}${f.suggestedFix ? ` -> Recommended: ${f.suggestedFix}` : ''}`
    ).join('\n');

    const prompt = [
      `File: ${file}`,
      'The static analysis engine found the following issues in this file:',
      issuesSummary,
      '',
      'Source code of the file:',
      '```',
      fileContent,
      '```',
      '',
      'Please resolve ALL of the above issues in this file simultaneously.',
      'Respond with ONLY a JSON object in this format:',
      '{"fixes": [{"explanation": "...", "oldSnippet": "exact code substring to replace", "newSnippet": "replacement code"}]}',
    ].join('\n');

    const messages = [
      { role: 'system', content: BATCH_REPAIR_SYSTEM_PROMPT },
      { role: 'user',   content: prompt },
    ];

    // Build prioritized fast fallback chain (max 3-4 candidates to prevent long terminal hangs)
    const isFreeTier = preferredModel === 'free' || (preferredModel && (preferredModel.includes('free') || preferredModel === 'openrouter/free'));
    const primary = preferredModel === 'free' ? OPENROUTER_MODELS.OPENROUTER_FREE : (preferredModel || this.model || OPENROUTER_MODELS.MINIMAX_M3);
    const fallback1 = isFreeTier ? OPENROUTER_MODELS.NEMOTRON_NANO_OMNI : OPENROUTER_MODELS.DEEPSEEK_V4_1_FLASH;
    const fallback2 = isFreeTier ? OPENROUTER_MODELS.NEMOTRON_3_5_LIGHTNING : OPENROUTER_MODELS.NORTH_MINI_CODE;
    const candidatePool = [primary, fallback1, fallback2, LAST_RESORT_MODEL];
    const modelsToTry = [];
    for (const m of candidatePool) {
      if (m && !modelsToTry.includes(m)) modelsToTry.push(m);
    }

    let lastError = null;
    for (let i = 0; i < modelsToTry.length; i++) {
      const modelCandidate = modelsToTry[i];
      try {
        const response = await this._callAPI(messages, modelCandidate, 2048);
        const fixes = this._parseBatchRepairResponse(response, fileContent);
        if (fixes && fixes.length > 0) {
          const switchedFrom = modelCandidate !== primary ? primary : null;
          return {
            fixes,
            modelUsed: modelCandidate,
            switchedFrom,
          };
        }
        lastError = new Error(`Model ${modelCandidate} returned empty or invalid batch fixes`);
      } catch (err) {
        lastError = err;
      }

      // If credit is exhausted (HTTP 402), immediately switch remaining candidates to active free models
      if (/402|credit|balance|insufficient/i.test(lastError?.message || '')) {
        const freeCandidates = [
          OPENROUTER_MODELS.NEMOTRON_NANO_OMNI,
          OPENROUTER_MODELS.NEMOTRON_3_5_LIGHTNING,
          OPENROUTER_MODELS.NORTH_MINI_CODE,
          OPENROUTER_MODELS.LAGUNA_S_2_1,
        ];
        const tried = modelsToTry.slice(0, i + 1);
        modelsToTry.splice(i + 1, modelsToTry.length - (i + 1), ...freeCandidates.filter(m => !tried.includes(m)));
      }

      // Check if OpenRouter recommended a replacement model slug
      const slugMatch = lastError?.message?.match(/use this slug instead:\s*([a-zA-Z0-9_./-]+)/i);
      if (slugMatch && slugMatch[1] && !modelsToTry.includes(slugMatch[1])) {
        modelsToTry.splice(i + 1, 0, slugMatch[1]);
      }

      // Check if token expiration or rate limits occurred and trigger model switch notification
      if (i + 1 < modelsToTry.length && typeof onModelSwitch === 'function') {
        const nextModel = modelsToTry[i + 1];
        const isTokenExpire = /token|quota|rate\s*limit|429|402|context\s*length|exceeded|credit|balance|timeout/i.test(lastError?.message || '');
        onModelSwitch({
          failedModel: modelCandidate,
          nextModel,
          error: lastError?.message || 'Failed to generate code repair',
          isTokenExpire,
        });
      }
    }

    return {
      error: `Batch repair failed across all models (${modelsToTry.slice(0, 3).join(', ')}...): ${lastError?.message || 'No valid fixes generated'}`,
    };
  }

  _parseBatchRepairResponse(response, fileContent) {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) return null;

      let cleaned = content.trim();
      cleaned = cleaned.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
      cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');
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
            explanation: item.explanation || 'Applied batch AI code repair',
          });
        }
      }
      return validFixes.length > 0 ? validFixes : null;
    } catch {
      return null;
    }
  }

  mockRepairFileBatch({ fileContent, findings }) {
    const lines = (fileContent || '').split('\n');
    const fixes = [];
    for (const f of findings || []) {
      const lineIdx = Math.max(0, (f.line || 1) - 1);
      const line = lines[lineIdx] || '';
      if (line.includes('==') && !line.includes('===')) {
        fixes.push({
          oldSnippet: line,
          newSnippet: line.replace(/==(?!=)/g, '==='),
          explanation: 'Replaced loose equality with strict equality',
        });
      } else if (line.includes('var ')) {
        fixes.push({
          oldSnippet: line,
          newSnippet: line.replace(/\bvar\b/, 'const'),
          explanation: 'Replaced var with const',
        });
      }
    }
    return {
      fixes: fixes.length > 0 ? fixes : null,
      modelUsed: OPENROUTER_MODELS.MINIMAX_M3,
    };
  }

  // ── Model selection helpers ───────────────────────────────────────────────

  setModelForContext(scanContext) {
    const newModel = selectModel(scanContext, null);
    if (newModel !== this.model) {
      this.model = newModel;
      return true;
    }
    return false;
  }

  // ── API call with retry + model fallback ──────────────────────────────────

  async _callWithFallback(messages) {
    let lastError;

    // First: try the configured model
    try {
      const response = await this._callAPI(messages, this.model);
      return this._parseResponse(response);
    } catch (err) {
      lastError = err;
    }

    // Check if OpenRouter recommended a replacement model slug
    const initialSlugMatch = lastError?.message?.match(/use this slug instead:\s*([a-zA-Z0-9_./-]+)/i);
    if (initialSlugMatch && initialSlugMatch[1] && initialSlugMatch[1] !== this.model) {
      try {
        const response = await this._callAPI(messages, initialSlugMatch[1]);
        this.model = initialSlugMatch[1];
        return this._parseResponse(response);
      } catch (err) {
        lastError = err;
      }
    }

    // Fallback: walk the chain, skipping the model we already tried
    const isZeroCredit = /402|credit|balance|insufficient/i.test(lastError?.message || '');
    let fallbackChain = isZeroCredit ? FREE_MODEL_FALLBACK_CHAIN : MODEL_FALLBACK_CHAIN;

    for (let i = 0; i < fallbackChain.length; i++) {
      const fallbackModel = fallbackChain[i];
      if (fallbackModel === this.model) continue;
      try {
        const response = await this._callAPI(messages, fallbackModel);
        this.model = fallbackModel; // sticky switch
        return this._parseResponse(response);
      } catch (err) {
        lastError = err;
        if (/402|credit|balance|insufficient/i.test(err?.message || '') && fallbackChain !== FREE_MODEL_FALLBACK_CHAIN) {
          fallbackChain = FREE_MODEL_FALLBACK_CHAIN;
          i = -1;
          continue;
        }
      }

      // Check if OpenRouter recommended a replacement model slug
      const slugMatch = lastError?.message?.match(/use this slug instead:\s*([a-zA-Z0-9_./-]+)/i);
      if (slugMatch && slugMatch[1] && slugMatch[1] !== fallbackModel) {
        try {
          const response = await this._callAPI(messages, slugMatch[1]);
          this.model = slugMatch[1];
          return this._parseResponse(response);
        } catch (err) {
          lastError = err;
        }
      }
    }

    // Last resort: let OpenRouter auto-pick any available model
    if (this.model !== LAST_RESORT_MODEL) {
      try {
        const response = await this._callAPI(messages, LAST_RESORT_MODEL);
        this.model = LAST_RESORT_MODEL;
        return this._parseResponse(response);
      } catch (err) {
        lastError = err;
      }
    }

    // ── Cross-Router Failover: switch to AgentRouter (or vice-versa) ──
    if (this._canCrossFailover) {
      const altProvider = this.provider === 'openrouter' ? 'agentrouter' : 'openrouter';
      const altBaseUrl  = altProvider === 'agentrouter' ? this.agentrouterBaseUrl : this.openrouterBaseUrl;
      const altApiKey   = altProvider === 'agentrouter' ? this.agentrouterApiKey : this.openrouterApiKey;

      // Try the top 5 models on the alternate router
      const topModels = MODEL_FALLBACK_CHAIN.slice(0, 5);
      for (const altModel of topModels) {
        try {
          const response = await this._callAPI(messages, altModel, this.maxTokens, altBaseUrl, altApiKey);
          this.model    = altModel;
          this.provider = altProvider;
          this.baseUrl  = altBaseUrl;
          this.apiKey   = altApiKey;
          return this._parseResponse(response);
        } catch (err) {
          lastError = err;
        }
      }
    }

    throw new Error(`AI analysis failed after trying all models on ${this.provider}${this._canCrossFailover ? ' and alternate router' : ''}: ${lastError?.message}`);
  }

  // ── Raw HTTP call (node:https, zero deps) ─────────────────────────────────

  async _callAPI(messages, model, maxTokens = this.maxTokens, overrideBaseUrl = null, overrideApiKey = null) {
    const https = require('https');
    const effectiveBaseUrl = overrideBaseUrl || this.baseUrl;
    const effectiveApiKey  = overrideApiKey || this.apiKey;

    return new Promise((resolve, reject) => {
      const url = new URL(`${effectiveBaseUrl}/chat/completions`);

      const postData = JSON.stringify({
        model,
        max_tokens: maxTokens || this.maxTokens,
        temperature: this.temperature,
        messages,
      });

      const options = {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type':   'application/json',
          'Authorization':  `Bearer ${effectiveApiKey}`,
          'HTTP-Referer':   'https://github.com/codesentry',
          'X-Title':        'CodeSentry',
          'Content-Length':  Buffer.byteLength(postData),
        },
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            const response = JSON.parse(data);

            if (response.error) {
              const affordMatch = (response.error.message || '').match(/can only afford (\d+)/i);
              if (affordMatch && parseInt(affordMatch[1], 10) >= 30 && maxTokens > parseInt(affordMatch[1], 10)) {
                const newMax = Math.max(25, parseInt(affordMatch[1], 10) - 2);
                return this._callAPI(messages, model, newMax).then(resolve).catch(reject);
              }
              reject(new Error(`API error: ${response.error.message || JSON.stringify(response.error)}`));
              return;
            }

            if (res.statusCode !== 200) {
              const affordMatch = (data || '').match(/can only afford (\d+)/i);
              if (affordMatch && parseInt(affordMatch[1], 10) >= 30 && maxTokens > parseInt(affordMatch[1], 10)) {
                const newMax = Math.max(25, parseInt(affordMatch[1], 10) - 2);
                return this._callAPI(messages, model, newMax).then(resolve).catch(reject);
              }
              reject(new Error(`API error ${res.statusCode}: ${response.error?.message || data}`));
              return;
            }

            resolve(response);
          } catch (err) {
            reject(new Error(`Failed to parse API response: ${err.message}`));
          }
        });
      });

      req.on('error', (err) => {
        reject(new Error(`API request failed: ${err.message}`));
      });

      const timeoutId = setTimeout(() => {
        req.destroy(new Error('API request timed out'));
        reject(new Error('API request timed out'));
      }, this.timeout);

      req.on('close', () => {
        clearTimeout(timeoutId);
      });

      req.write(postData);
      req.end();
    });
  }

  // ── Response parsing (handles nested JSON correctly) ──────────────────────

  _parseResponse(response) {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) {
        throw new Error('No content in AI response');
      }

      // Strip markdown code fences if the model wrapped the JSON
      let cleaned = content.trim();
      cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');

      // Greedy match for the outermost JSON object (handles nested braces)
      const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }

      // Fallback: treat the whole response as a plain-text explanation
      return {
        explanation: content,
        severity: 'MEDIUM',
        confidence: 0.5,
        falsePositiveProbability: 0.3,
        impact: 'Unable to determine from AI response',
        suggestedFix: 'Review manually',
      };
    } catch (error) {
      throw new Error(`Failed to parse AI response: ${error.message}`);
    }
  }

  // ── Source context helper (for analyzeFindings) ────────────────────────────

  _getSourceContext(finding, discoveryResult) {
    if (!finding.file || !discoveryResult?.fileMap) return null;

    const fullPath = discoveryResult.fileMap[finding.file];
    if (!fullPath) return null;

    try {
      const fs = require('node:fs');
      const content = fs.readFileSync(fullPath, 'utf-8');
      const lines = content.split('\n');
      const start = Math.max(0, (finding.line || 1) - 11);
      const end   = Math.min(lines.length, (finding.line || 1) + 10);
      return lines.slice(start, end).join('\n');
    } catch {
      return null;
    }
  }

  // ── Mock mode (testing without API key) ───────────────────────────────────

  async mockAnalysis(prompt) {
    await new Promise(resolve => setTimeout(resolve, 100));

    const lowerPrompt = prompt.toLowerCase();

    if (lowerPrompt.includes('sql injection') || lowerPrompt.includes('sql')) {
      return {
        explanation: 'User input is directly interpolated into a SQL query string without parameterization.',
        severity: 'HIGH',
        confidence: 0.92,
        falsePositiveProbability: 0.05,
        impact: 'Potential unauthorized database access or manipulation.',
        suggestedFix: 'Use parameterized queries or prepared statements.',
      };
    }

    if (lowerPrompt.includes('eval') || lowerPrompt.includes('exec')) {
      return {
        explanation: 'Use of eval() or exec() can execute arbitrary code, leading to code injection vulnerabilities.',
        severity: 'HIGH',
        confidence: 0.95,
        falsePositiveProbability: 0.02,
        impact: 'Remote code execution possible if input is attacker-controlled.',
        suggestedFix: 'Avoid eval/exec. Use safer alternatives like JSON.parse() for data or specific APIs for operations.',
      };
    }

    if (lowerPrompt.includes('hardcoded') || lowerPrompt.includes('credential') || lowerPrompt.includes('secret')) {
      return {
        explanation: 'Sensitive credentials are hardcoded in source code, making them visible to anyone with repository access.',
        severity: 'HIGH',
        confidence: 0.90,
        falsePositiveProbability: 0.08,
        impact: 'Credential leakage could lead to unauthorized access.',
        suggestedFix: 'Move credentials to environment variables or a secure vault.',
      };
    }

    if (lowerPrompt.includes('unused') || lowerPrompt.includes('dead code')) {
      return {
        explanation: 'Code is defined but never used, indicating potential dead code or incomplete implementation.',
        severity: 'LOW',
        confidence: 0.85,
        falsePositiveProbability: 0.10,
        impact: 'Code maintainability and clarity reduced.',
        suggestedFix: 'Remove unused code or add appropriate usage.',
      };
    }

    if (lowerPrompt.includes('xss') || lowerPrompt.includes('cross-site')) {
      return {
        explanation: 'User-supplied data is rendered in the DOM without sanitization, enabling cross-site scripting.',
        severity: 'HIGH',
        confidence: 0.88,
        falsePositiveProbability: 0.07,
        impact: 'Attackers can inject malicious scripts to steal sessions or data.',
        suggestedFix: 'Sanitize all user input before rendering. Use textContent or a sanitization library.',
      };
    }

    if (lowerPrompt.includes('path traversal') || lowerPrompt.includes('directory traversal')) {
      return {
        explanation: 'File path constructed from user input without validation allows directory traversal.',
        severity: 'HIGH',
        confidence: 0.91,
        falsePositiveProbability: 0.04,
        impact: 'Arbitrary file read/write outside intended directories.',
        suggestedFix: 'Validate and canonicalize paths. Use path.resolve() and verify the result is within the allowed directory.',
      };
    }

    // Default response
    return {
      explanation: 'This finding requires manual review to determine its severity and impact.',
      severity: 'MEDIUM',
      confidence: 0.50,
      falsePositiveProbability: 0.20,
      impact: 'Impact assessment requires contextual analysis.',
      suggestedFix: 'Review the code in context and apply appropriate remediation.',
    };
  }

  // ── Mock code repair for testing without API key ─────────────────────────

  mockRepairCode({ finding, fileContent, line }) {
    const lines = (fileContent || '').split('\n');
    const targetLine = line || finding.line || 1;
    const lineIdx = Math.max(0, targetLine - 1);
    const originalLine = lines[lineIdx] || '';

    if (finding.rule === 'loose-equality' || (finding.message && (finding.message.includes('===') || finding.message.includes('Loose equality')))) {
      const fixedLine = originalLine.replace(/==(?!=)/g, '===').replace(/!=(?!=)/g, '!==');
      if (fixedLine !== originalLine) {
        return {
          oldSnippet: originalLine,
          newSnippet: fixedLine,
          explanation: 'Replaced loose equality with strict equality',
          modelUsed: OPENROUTER_MODELS.MINIMAX_M3,
        };
      }
    }

    if (finding.rule === 'off-by-one' || (finding.message && finding.message.includes('off-by-one'))) {
      const fixedLine = originalLine.replace(/<=\s*([a-zA-Z0-9_$.]+)\.length/g, '< $1.length');
      if (fixedLine !== originalLine) {
        return {
          oldSnippet: originalLine,
          newSnippet: fixedLine,
          explanation: 'Corrected loop boundary from <= to < to avoid index out-of-bounds',
          modelUsed: OPENROUTER_MODELS.MINIMAX_M3,
        };
      }
    }

    if (originalLine.trim()) {
      return {
        oldSnippet: originalLine,
        newSnippet: originalLine,
        explanation: finding.suggestedFix || 'Resolved code finding via AI repair',
        modelUsed: OPENROUTER_MODELS.MINIMAX_M3,
      };
    }

    return null;
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------
function createOpenRouterClient(options = {}) {
  return new OpenRouterClient(options);
}

module.exports = {
  OPENROUTER_MODELS,
  MODEL_FALLBACK_CHAIN,
  FREE_MODEL_FALLBACK_CHAIN,
  LAST_RESORT_MODEL,
  OpenRouterClient,
  createOpenRouterClient,
  DEFAULT_MODEL,
  COMPLEX_MODEL,
  SYSTEM_PROMPT,
  REPAIR_SYSTEM_PROMPT,
  calculateComplexity,
  selectModel,
};
