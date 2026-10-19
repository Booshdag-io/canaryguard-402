import { load } from 'cheerio';

export type CryptoAddressFinding = {
  address: string;
  risk_score: number;
  reasons: string[];
};

export type SanitizeResult = {
  status: 'clean' | 'sanitized' | 'blocked';
  risk_score: number;
  injection_detected: boolean;
  threats_neutralized: string[];
  sanitized_content: string;
  safety_receipt: 'canary-v1-verified';
  crypto_addresses: CryptoAddressFinding[];
  recommended_actions?: Array<{
    service: string;
    description: string;
    url: string;
    price: string;
  }>;
  inspection: {
    method: 'deterministic-rules';
    guaranteed_safe: false;
    risk_score_semantics: 'heuristic severity, not a probability';
    limitations: string[];
  };
};

// Includes zero-width, bidi-formatting, variation selectors, unicode tags (E0001-E007F), and soft-hyphen characters that can conceal commands.
const INVISIBLE_CHARACTERS = /[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufe00-\ufe0f\ufeff\u{e0001}-\u{e007f}]/gu;
const ZALGO_DIACRITICS = /[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]/gu;
const UNICODE_SPACES = /[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/gu;
const ROLE_DELIMITER = /\[\/?(?:INST|AVAILABLE_TOOLS|TOOL_RESULTS|TOOL_CALLS|PROMPT|SYSTEM|CONTEXT|RULES|DIRECTIVES|INSTRUCTION|DEVELOPER)\]|<\|(?:im_start|im_end|system|developer|assistant|user|start_header_id|end_header_id|eot_id|begin_of_text|end_of_text)\b|<<\/?(?:SYS|SYSTEM)>>|<\/?(?:system|developer|assistant|instruction|instructions|context|prompt_context|system_prompt|user_input|antThinking|thinking|role|prompt)[\s>]/i;
const ROLE_PREFIX = /(?:^|[\r\n])\s*(?:#{1,4}\s*)?(?:system|developer|assistant|admin|root|superuser|operator|jailbreak|DAN|instruction|prompt)\s*:/i;
const MARKDOWN_DELIMITER_ESCAPE = /(?:^|[\r\n])\s*(?:```+\s*(?:system|developer|assistant|instruction|prompt|override|json)?|#{1,4}\s*(?:system(?:\s+prompt)?|developer(?:\s+prompt)?|assistant|instructions?|override|new\s+rules|system\s+directives?|prompt|rules)\b|===\s*(?:SYSTEM|DEVELOPER|INSTRUCTIONS?)\s*===|---+\s*(?:BEGIN|START)\s*(?:SYSTEM|DEVELOPER|INSTRUCTIONS?))/i;
const STRUCTURED_ROLE_INJECTION = /["']?role["']?\s*:\s*["']?(?:system|developer|assistant|root|admin)["']?|\bSYSTEM_PROMPT\b|\b(?:system|developer|assistant)_message\b/i;
const INSTRUCTION_OVERRIDE = /\b(?:(?:ignore|disregard|forget|override|bypass|supersede|discard|neglect|abandon|drop|clear|reset|cancel|revoke|overwrite|circumvent|violate|disable|suspend|deactivate|stop|cease|wipe|purge|erase)\s*(?:(?:all|any|the|your|our|every|these|those|prior|previous|earlier|above|system|developer|safety|guardrail|original|initial|memory)\s*)*(?:instructions?|prompts?|rules?|messages?|directives?|guidelines?|constraints?|parameters?|policies|filters?|guardrails?|configuration|settings|restrictions?|programming|memory|context)|(?:you\s*(?:are\s*to|must|will|shall)\s*)?(?:do\s*(?:what|as)\s*i\s*(?:say|tell\s*you)|obey(?:\s*(?:all|only|my)\s*(?:commands?|instructions?))?)|follow\s*only\s*(?:my|these)\s*instructions?|from\s*now\s*on\s*(?:you\s*(?:will|must|shall)|act\s*as|treat|regard)|your\s*new\s*(?:instructions?|rules?|role|task)\s*(?:is|are)|new\s*instructions?\s*:|(?:reveal|dump|print|output|display|leak|show|repeat)\s*(?:(?:the|your|all|every)\s*)*(?:system\s*prompt|initial\s*instructions?|hidden\s*prompt|above\s*text|instructions\s*verbatim|preceding\s*prompt|internal\s*instructions?|secrets?|keys?|vault|passwords?|credentials?)|you\s*are\s*(?:now\s*)?free\s*from\s*(?:all\s*)?(?:rules|restrictions|constraints))\b/i;
const JAILBREAK_ROLEPLAY = /\b(?:(?:act\s+as|pretend\s+(?:to\s+be|you\s+are)|simulate|roleplay\s+as|you\s+are\s+now)\s+(?:an?\s+)*(?:unrestricted|jailbreak(?:ed)?|DAN|developer|root|admin|god\s+mode|unfiltered|evil|anarchist|hypothetical)|(?:developer\s+mode|maintenance\s+mode|debug\s+mode|sandbox\s+mode|override\s+mode)\s+(?:enabled|activated|on|true)|do\s+anything\s+now|jailbreak\s+mode)\b/i;
const MULTILINGUAL_OVERRIDE = /\b(?:(?:ignora|olvida|anula|descarta)\s+(?:todas?\s+las?\s+)?(?:instrucciones|reglas|directrices)|(?:ignorez?|oubli(?:ez|er)|annulez?)\s+(?:toutes?\s+les?\s+)?(?:instructions?|règles?|directives?)|(?:ignoriere?|vergiss|übergehe)\s+(?:alle\s+)?(?:vorherigen?\s+)?(?:anweisungen?|regeln?)|(?:игнорируй|забудь|отмени)\s+(?:все\s+)?(?:предыдущие\s+)?(?:инструкции|правила)|(?:ignora|dimentica|annulla)\s+(?:tutte\s+le\s+)?(?:istruzioni|regole)|(?:ignore|esqueça|anule)\s+(?:todas\s+as\s+)?(?:instruções|regras))\b/i;
const WALLET_ASSET_COMMAND = /\b(?:send|transfer|wire|move|drain|empty|sweep|withdraw|flush|dump|forward|approve|permit|authorize|disburse|pay|release|execute)\s*(?:(?:all|every|entire|the|your|my|our|any|remaining)\s*)*(?:wallet|treasury|vault|bounty|prize|pool|funds?|balances?|assets?|tokens?|crypto|eth|usdc|usdt|coins?|sol|solana|lamports|wei)\b/i;
const WALLET_DESTINATION_COMMAND = /\b(?:send|transfer|wire|move|drain|empty|sweep|withdraw|flush|forward|pay|disburse|release)\s*(?:(?:it|them|all|funds?|balances?|tokens?|assets?|bounty|prize|the\s+wallet|the\s+vault)\s*)*(?:to|into)\s*(?:(?:the\s+following|this|my|the|an?)\s*)*(?:(?:wallet|recipient|destination)\s*)?(?:address\s*(?::|\s*)?)?(?:0x[\da-f]{4,40}|[1-9A-HJ-NP-Za-km-z]{32,44})\b/i;
const EVM_ADDRESS = /\b0x[\da-f]{40}\b/gi;
const ACTIVE_ELEMENTS = 'script, style, template, noscript, iframe, object, embed, svg, math, head, meta, link, base';
const BLOCK_ELEMENTS = 'p, div, section, article, header, footer, main, aside, nav, li, tr, h1, h2, h3, h4, h5, h6, blockquote, pre';

function deobfuscate(value: string): string {
  // Collapse single-character spaced/punctuated words like "i g n o r e" or "i.g.n.o.r.e" or "i-g-n-o-r-e"
  const despaced = value.replace(/\b([a-zA-Z0-9](?:[ ._\-][a-zA-Z0-9]){2,})\b/g, m => m.replace(/[ ._\-]+/g, ''));
  return despaced
    // Cyrillic homoglyphs
    .replace(/[\u0430\u0410]/g, 'a')
    .replace(/[\u0441\u0421]/g, 'c')
    .replace(/[\u0435\u0415]/g, 'e')
    .replace(/[\u043e\u041e]/g, 'o')
    .replace(/[\u0440\u0420]/g, 'p')
    .replace(/[\u0455\u0405]/g, 's')
    .replace(/[\u0445\u0425]/g, 'x')
    .replace(/[\u0443\u0423]/g, 'y')
    .replace(/[\u0456\u0406]/g, 'i')
    .replace(/[\u0458\u0408]/g, 'j')
    // Greek homoglyphs
    .replace(/[\u03b1\u0391]/g, 'a')
    .replace(/[\u03bf\u039f]/g, 'o')
    .replace(/[\u03bd\u039d]/g, 'v')
    .replace(/[\u03c1\u03a1]/g, 'p')
    // Leetspeak / common symbol substitutions
    .replace(/[@]/g, 'a')
    .replace(/[$]/g, 's')
    .replace(/[0]/g, 'o')
    .replace(/[1!|]/g, 'i')
    .replace(/[3]/g, 'e')
    .replace(/[4]/g, 'a')
    .replace(/[5]/g, 's');
}

function checkEncodedInjections(value: string): string[] {
  const threats: string[] = [];
  
  // 1. Base64 inspection (>=16 chars of base64 chars)
  const b64Matches = value.match(/[A-Za-z0-9+/]{16,}={0,2}/g);
  if (b64Matches) {
    for (const chunk of b64Matches) {
      try {
        const decoded = Buffer.from(chunk, 'base64').toString('utf8');
        if (decoded.length >= 8 && /^[ -~\t\r\n]+$/.test(decoded)) {
          if (ROLE_DELIMITER.test(decoded) || ROLE_PREFIX.test(decoded)) threats.push('encoded_role_delimiter');
          if (INSTRUCTION_OVERRIDE.test(decoded)) threats.push('encoded_instruction_override');
          if (JAILBREAK_ROLEPLAY.test(decoded)) threats.push('encoded_jailbreak_roleplay');
          if (matchesWalletCommand(decoded)) threats.push('encoded_wallet_command');
        }
      } catch {}
    }
  }

  // 2. URL percent-encoding inspection (e.g. %69%67%6e%6f%72%65)
  if (/%[0-9a-fA-F]{2}/.test(value)) {
    try {
      const decoded = decodeURIComponent(value);
      if (decoded !== value) {
        if (ROLE_DELIMITER.test(decoded) || ROLE_PREFIX.test(decoded)) threats.push('encoded_role_delimiter');
        if (INSTRUCTION_OVERRIDE.test(decoded)) threats.push('encoded_instruction_override');
        if (JAILBREAK_ROLEPLAY.test(decoded)) threats.push('encoded_jailbreak_roleplay');
        if (matchesWalletCommand(decoded)) threats.push('encoded_wallet_command');
      }
    } catch {}
  }

  // 3. Hex escape sequences inspection (e.g. \x69\x67\x6e\x6f\x72\x65)
  if (/(?:\\x[0-9a-fA-F]{2}){4,}/.test(value)) {
    try {
      const decoded = value.replace(/\\x([0-9a-fA-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
      if (ROLE_DELIMITER.test(decoded) || ROLE_PREFIX.test(decoded)) threats.push('encoded_role_delimiter');
      if (INSTRUCTION_OVERRIDE.test(decoded)) threats.push('encoded_instruction_override');
      if (JAILBREAK_ROLEPLAY.test(decoded)) threats.push('encoded_jailbreak_roleplay');
      if (matchesWalletCommand(decoded)) threats.push('encoded_wallet_command');
    } catch {}
  }

  return threats;
}

function matchesWalletCommand(value: string): boolean {
  return WALLET_ASSET_COMMAND.test(value) || WALLET_DESTINATION_COMMAND.test(value);
}

function commandThreats(value: string): string[] {
  const normalized = value.normalize('NFKC');
  const deobf = deobfuscate(normalized);
  const found: string[] = [];
  if (ROLE_DELIMITER.test(normalized) || ROLE_PREFIX.test(normalized) || ROLE_DELIMITER.test(deobf) || ROLE_PREFIX.test(deobf)) found.push('role_delimiter_override');
  if (MARKDOWN_DELIMITER_ESCAPE.test(normalized) || MARKDOWN_DELIMITER_ESCAPE.test(deobf)) found.push('markdown_delimiter_escape');
  if (STRUCTURED_ROLE_INJECTION.test(normalized) || STRUCTURED_ROLE_INJECTION.test(deobf)) found.push('structured_role_injection');
  if (INSTRUCTION_OVERRIDE.test(normalized) || INSTRUCTION_OVERRIDE.test(deobf)) found.push('instruction_override');
  if (JAILBREAK_ROLEPLAY.test(normalized) || JAILBREAK_ROLEPLAY.test(deobf)) found.push('jailbreak_roleplay_detected');
  if (MULTILINGUAL_OVERRIDE.test(normalized)) found.push('multilingual_instruction_override');
  if (matchesWalletCommand(normalized) || matchesWalletCommand(deobf)) found.push('wallet_transfer_command');
  for (const t of checkEncodedInjections(value)) found.push(t);
  return found;
}

function hiddenDeclaration(value: string): boolean {
  return /(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)|opacity\s*:\s*0(?:\.0+)?|(?:font-size|line-height)\s*:\s*0(?:[a-z%]+)?|color\s*:\s*transparent)\s*(?:!\s*important\s*)?(?:;|$)/i.test(value);
}

function extractPlainText(content: string, findings: Set<string>): { allText: string; visibleText: string } {
  const $ = load(content);
  // Newlines preserve instruction boundaries, including entity-encoded commands in separate blocks.
  $(BLOCK_ELEMENTS).before('\n').after('\n');
  $('br').replaceWith('\n');
  const allText = $.root().text();

  // Handle inline declarations and simple embedded CSS selectors before removing stylesheets.
  const stylesheetRules = $('style').map((_, element) => $(element).text()).get().join('\n');
  for (const rule of stylesheetRules.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!hiddenDeclaration(rule[2])) continue;
    try {
      const hiddenNodes = $(rule[1].trim());
      if (hiddenNodes.length) {
        findings.add('html_hidden_content_removed');
        hiddenNodes.remove();
      }
    } catch {
      // Invalid or unsupported selectors cannot execute: all HTML and stylesheet text is stripped below.
    }
  }
  $('[hidden], [aria-hidden="true"], input[type="hidden"]').each((_, element) => {
    findings.add('html_hidden_content_removed');
    $(element).remove();
  });
  $('[style]').each((_, element) => {
    if (hiddenDeclaration($(element).attr('style') ?? '')) {
      findings.add('html_hidden_content_removed');
      $(element).remove();
    }
  });
  if ($(ACTIVE_ELEMENTS).not('head').length) {
    findings.add('active_html_removed');
  }
  $('*').each((_, element) => {
    if (!('attribs' in element)) return;
    for (const [name, value] of Object.entries(element.attribs)) {
      if (/^on/i.test(name) || /^(?:href|src|action)$/i.test(name) && /^\s*(?:javascript:|data:text\/html)/i.test(value)) {
        findings.add('unsafe_html_attributes_removed');
      }
    }
  });
  $(ACTIVE_ELEMENTS).remove();
  if (/<\s*\/?[a-z][^>]*>/i.test(content)) findings.add('html_markup_removed');
  return { allText, visibleText: $.root().text() };
}

function tidy(value: string): string {
  return value.replace(/\r\n?/g, '\n').replace(/[\t ]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

function scrubCommandLines(value: string): string {
  const blockedMarker = '[CANARY_REMOVED_INSTRUCTION]';
  let marked = value.normalize('NFKC');
  // Mark every line touched by a match: a command may be split over several lines.
  const patterns = [
    ROLE_DELIMITER,
    ROLE_PREFIX,
    MARKDOWN_DELIMITER_ESCAPE,
    STRUCTURED_ROLE_INJECTION,
    INSTRUCTION_OVERRIDE,
    JAILBREAK_ROLEPLAY,
    MULTILINGUAL_OVERRIDE,
    WALLET_ASSET_COMMAND,
    WALLET_DESTINATION_COMMAND,
  ];
  for (const pattern of patterns) {
    const flags = pattern.multiline ? 'gim' : 'gi';
    marked = marked.replace(new RegExp(pattern.source, flags), match => match.split('\n').map(() => blockedMarker).join('\n'));
  }
  return tidy(marked.split('\n').filter(line => !line.includes(blockedMarker)).join('\n'));
}

function extractAddresses(value: string): CryptoAddressFinding[] {
  const normalized = value.normalize('NFKC');
  const addresses = new Map<string, CryptoAddressFinding>();
  for (const match of normalized.matchAll(EVM_ADDRESS)) {
    const address = match[0];
    const key = address.toLowerCase();
    const context = normalized.slice(Math.max(0, match.index - 160), match.index + address.length + 40);
    const reasons = ['unverified_address'];
    let riskScore = 0.1;
    if (/^0x(?:0{40}|0{36}dead)$/i.test(address)) {
      reasons.push('burn_destination');
      riskScore = 0.7;
    }
    if (matchesWalletCommand(context)) {
      reasons.push('wallet_transfer_command_nearby');
      riskScore = 0.98;
    }
    const existing = addresses.get(key);
    if (!existing || existing.risk_score < riskScore) addresses.set(key, { address, risk_score: riskScore, reasons });
  }
  return [...addresses.values()];
}

/** Rule-based inspection of untrusted text; this receipt never certifies semantic safety. */
export function sanitizeContent(content: string, strictMode = true): SanitizeResult {
  const findings = new Set<string>();
  let normalizedContent = content.replace(UNICODE_SPACES, ' ');
  const strippedZalgo = normalizedContent.replace(ZALGO_DIACRITICS, '');
  if (strippedZalgo !== normalizedContent) {
    findings.add('zalgo_diacritics_removed');
    normalizedContent = strippedZalgo;
  }
  const strippedInvisible = normalizedContent.replace(INVISIBLE_CHARACTERS, '');
  if (strippedInvisible !== normalizedContent) {
    findings.add('concealed_unicode_removed');
    normalizedContent = strippedInvisible;
  }
  const { allText, visibleText } = extractPlainText(normalizedContent, findings);
  const detectedCommands = new Set([
    ...commandThreats(normalizedContent),
    ...commandThreats(allText),
    ...commandThreats(visibleText),
  ]);
  for (const threat of detectedCommands) findings.add(threat);
  const injectionDetected = detectedCommands.size > 0;
  const addresses = extractAddresses(`${normalizedContent}\n${allText}`);
  let sanitizedContent = tidy(visibleText);
  if (injectionDetected) {
    sanitizedContent = strictMode
      ? ''
      : scrubCommandLines(sanitizedContent);
  }
  // Remove any surviving role tokens even when formatting split a risky command across lines.
  sanitizedContent = sanitizedContent.replace(new RegExp(ROLE_DELIMITER.source, 'gi'), '');
  sanitizedContent = tidy(sanitizedContent);

  let riskScore = 0.01;
  if (findings.has('html_markup_removed')) riskScore = 0.05;
  if (findings.has('concealed_unicode_removed') || findings.has('html_hidden_content_removed')) riskScore = Math.max(riskScore, 0.2);
  if (findings.has('zalgo_diacritics_removed')) riskScore = Math.max(riskScore, 0.4);
  if (findings.has('active_html_removed') || findings.has('unsafe_html_attributes_removed')) riskScore = Math.max(riskScore, 0.4);
  if (detectedCommands.has('role_delimiter_override')) riskScore = Math.max(riskScore, 0.85);
  if (detectedCommands.has('markdown_delimiter_escape')) riskScore = Math.max(riskScore, 0.9);
  if (detectedCommands.has('structured_role_injection')) riskScore = Math.max(riskScore, 0.9);
  if (detectedCommands.has('instruction_override')) riskScore = Math.max(riskScore, 0.95);
  if (detectedCommands.has('jailbreak_roleplay_detected')) riskScore = Math.max(riskScore, 0.96);
  if (detectedCommands.has('multilingual_instruction_override')) riskScore = Math.max(riskScore, 0.95);
  if (detectedCommands.has('wallet_transfer_command')) riskScore = Math.max(riskScore, 0.98);
  if (detectedCommands.has('encoded_role_delimiter') || detectedCommands.has('encoded_instruction_override') || detectedCommands.has('encoded_jailbreak_roleplay') || detectedCommands.has('encoded_wallet_command')) riskScore = Math.max(riskScore, 0.98);
  for (const address of addresses) riskScore = Math.max(riskScore, address.risk_score);

  return {
    status: injectionDetected && strictMode ? 'blocked' : findings.size ? 'sanitized' : 'clean',
    risk_score: riskScore,
    injection_detected: injectionDetected,
    threats_neutralized: [...findings].sort(),
    sanitized_content: sanitizedContent,
    safety_receipt: 'canary-v1-verified',
    crypto_addresses: addresses,
    recommended_actions: addresses.length ? [
      {
        service: 'stealthguard-402',
        description: 'On-chain pre-trade agent gate: verify contract bytecode, DexScreener LP depth, and sanitize metadata via CanaryGuard firewall before trading',
        url: 'https://stealthguard-402.onrender.com/v1/pre_trade_agent_gate',
        price: '0.03 USDC',
      },
      {
        service: 'rugshield-402',
        description: 'Verify token contract bytecode, honeypot risk, and DEX liquidity depth on Base before trading',
        url: 'https://rugshield-402.onrender.com/v1/scan',
        price: '0.005 USDC',
      },
    ] : (/https?:\/\/[^\s]+/i.test(content) ? [
      {
        service: 'stealthguard-402',
        description: 'Bypass Cloudflare anti-bot protection and sanitize external web pages before adding them to LLM context memory',
        url: 'https://stealthguard-402.onrender.com/v1/stealth_scrape_and_sanitize',
        price: '0.02 USDC',
      }
    ] : undefined),
    inspection: {
      method: 'deterministic-rules',
      guaranteed_safe: false,
      risk_score_semantics: 'heuristic severity, not a probability',
      limitations: [
        'Does not detect every obfuscated, multilingual, or novel instruction attack.',
        'Does not fetch external stylesheets, render browser layout, or analyze linked resources.',
        'Address scores reflect text context and do not verify ownership, reputation, or contract safety.',
        'Treat sanitized content as untrusted data; keep agent instructions and wallet authorization separate.',
      ],
    },
  };
}
