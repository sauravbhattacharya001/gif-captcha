"use strict";

/**
 * CaptchaLocalizationManager — multi-language support for CAPTCHA challenges.
 *
 * Allows challenge text (instructions, labels, error messages, success messages)
 * to be served in multiple languages with automatic locale detection,
 * fallback chains, and pluralization support.
 *
 * Features:
 *   - Built-in translations for 12 languages (en, es, fr, de, pt, it, ja, ko, zh, ar, hi, ru)
 *   - Locale detection from Accept-Language header, navigator, or explicit setting
 *   - Fallback chains (e.g. pt-BR → pt → en)
 *   - Variable interpolation in translation strings: "Click the {{color}} {{shape}}"
 *   - Pluralization rules per language
 *   - Custom translation registration
 *   - Translation coverage reporting
 *   - RTL language detection
 *
 * Usage:
 *   var mgr = createCaptchaLocalizationManager({ defaultLocale: 'en' });
 *   mgr.t('challenge.instruction', { locale: 'es' });
 *   mgr.detectLocale('fr-FR,fr;q=0.9,en;q=0.5');  // → 'fr'
 *   mgr.addTranslations('ja', { 'challenge.instruction': '...' });
 *   var report = mgr.coverageReport();
 *
 * @module gif-captcha/captcha-localization-manager
 */

// ── Built-in translation keys ──────────────────────────────────────

var BUILT_IN_TRANSLATIONS = {
  en: {
    "challenge.instruction": "Select the correct answer to prove you're human",
    "challenge.click_shape": "Click the {{color}} {{shape}}",
    "challenge.count_objects": "How many {{object}}s are in the image?",
    "challenge.sequence": "What comes next in the sequence?",
    "challenge.odd_one_out": "Which item does not belong?",
    "challenge.spatial": "Click the item in the {{position}}",
    "challenge.temporal": "Which frame shows the {{event}}?",
    "error.expired": "This challenge has expired. Please try again.",
    "error.invalid": "Incorrect answer. Please try again.",
    "error.too_many_attempts": "Too many attempts. Please wait {{seconds}} seconds.",
    "error.loading": "Loading challenge...",
    "success.verified": "Verification successful!",
    "success.passed": "You passed the challenge!",
    "ui.submit": "Submit",
    "ui.refresh": "New Challenge",
    "ui.audio": "Audio Challenge",
    "ui.help": "Help",
    "ui.privacy": "Privacy",
    "ui.terms": "Terms",
    "plural.object": "{{count}} object|{{count}} objects"
  },
  es: {
    "challenge.instruction": "Selecciona la respuesta correcta para demostrar que eres humano",
    "challenge.click_shape": "Haz clic en el {{shape}} {{color}}",
    "challenge.count_objects": "¿Cuántos {{object}} hay en la imagen?",
    "challenge.sequence": "¿Qué sigue en la secuencia?",
    "challenge.odd_one_out": "¿Cuál no pertenece?",
    "challenge.spatial": "Haz clic en el elemento en la {{position}}",
    "challenge.temporal": "¿Qué fotograma muestra el {{event}}?",
    "error.expired": "Este desafío ha expirado. Inténtalo de nuevo.",
    "error.invalid": "Respuesta incorrecta. Inténtalo de nuevo.",
    "error.too_many_attempts": "Demasiados intentos. Espera {{seconds}} segundos.",
    "error.loading": "Cargando desafío...",
    "success.verified": "¡Verificación exitosa!",
    "success.passed": "¡Pasaste el desafío!",
    "ui.submit": "Enviar",
    "ui.refresh": "Nuevo Desafío",
    "ui.audio": "Desafío de Audio",
    "ui.help": "Ayuda",
    "ui.privacy": "Privacidad",
    "ui.terms": "Términos",
    "plural.object": "{{count}} objeto|{{count}} objetos"
  },
  fr: {
    "challenge.instruction": "Sélectionnez la bonne réponse pour prouver que vous êtes humain",
    "challenge.click_shape": "Cliquez sur le {{shape}} {{color}}",
    "challenge.count_objects": "Combien de {{object}} y a-t-il dans l'image ?",
    "challenge.sequence": "Que vient ensuite dans la séquence ?",
    "challenge.odd_one_out": "Quel élément n'appartient pas ?",
    "challenge.spatial": "Cliquez sur l'élément dans la {{position}}",
    "challenge.temporal": "Quelle image montre le {{event}} ?",
    "error.expired": "Ce défi a expiré. Veuillez réessayer.",
    "error.invalid": "Réponse incorrecte. Veuillez réessayer.",
    "error.too_many_attempts": "Trop de tentatives. Veuillez attendre {{seconds}} secondes.",
    "error.loading": "Chargement du défi...",
    "success.verified": "Vérification réussie !",
    "success.passed": "Vous avez réussi le défi !",
    "ui.submit": "Soumettre",
    "ui.refresh": "Nouveau Défi",
    "ui.audio": "Défi Audio",
    "ui.help": "Aide",
    "ui.privacy": "Confidentialité",
    "ui.terms": "Conditions",
    "plural.object": "{{count}} objet|{{count}} objets"
  },
  de: {
    "challenge.instruction": "Wählen Sie die richtige Antwort, um zu beweisen, dass Sie ein Mensch sind",
    "challenge.click_shape": "Klicken Sie auf das {{color}} {{shape}}",
    "challenge.count_objects": "Wie viele {{object}} sind im Bild?",
    "challenge.sequence": "Was kommt als nächstes in der Reihenfolge?",
    "challenge.odd_one_out": "Welches Element gehört nicht dazu?",
    "challenge.spatial": "Klicken Sie auf das Element in der {{position}}",
    "challenge.temporal": "Welches Bild zeigt das {{event}}?",
    "error.expired": "Diese Aufgabe ist abgelaufen. Bitte versuchen Sie es erneut.",
    "error.invalid": "Falsche Antwort. Bitte versuchen Sie es erneut.",
    "error.too_many_attempts": "Zu viele Versuche. Bitte warten Sie {{seconds}} Sekunden.",
    "error.loading": "Aufgabe wird geladen...",
    "success.verified": "Verifizierung erfolgreich!",
    "success.passed": "Sie haben die Aufgabe bestanden!",
    "ui.submit": "Absenden",
    "ui.refresh": "Neue Aufgabe",
    "ui.audio": "Audio-Aufgabe",
    "ui.help": "Hilfe",
    "ui.privacy": "Datenschutz",
    "ui.terms": "Nutzungsbedingungen",
    "plural.object": "{{count}} Objekt|{{count}} Objekte"
  },
  pt: {
    "challenge.instruction": "Selecione a resposta correta para provar que você é humano",
    "challenge.click_shape": "Clique no {{shape}} {{color}}",
    "challenge.count_objects": "Quantos {{object}} existem na imagem?",
    "challenge.sequence": "O que vem a seguir na sequência?",
    "challenge.odd_one_out": "Qual item não pertence?",
    "challenge.spatial": "Clique no item na {{position}}",
    "challenge.temporal": "Qual quadro mostra o {{event}}?",
    "error.expired": "Este desafio expirou. Tente novamente.",
    "error.invalid": "Resposta incorreta. Tente novamente.",
    "error.too_many_attempts": "Muitas tentativas. Aguarde {{seconds}} segundos.",
    "error.loading": "Carregando desafio...",
    "success.verified": "Verificação bem-sucedida!",
    "success.passed": "Você passou no desafio!",
    "ui.submit": "Enviar",
    "ui.refresh": "Novo Desafio",
    "ui.audio": "Desafio de Áudio",
    "ui.help": "Ajuda",
    "ui.privacy": "Privacidade",
    "ui.terms": "Termos",
    "plural.object": "{{count}} objeto|{{count}} objetos"
  },
  it: {
    "challenge.instruction": "Seleziona la risposta corretta per dimostrare che sei umano",
    "challenge.click_shape": "Clicca sulla forma {{color}} {{shape}}",
    "challenge.count_objects": "Quanti {{object}} ci sono nell'immagine?",
    "challenge.sequence": "Cosa viene dopo nella sequenza?",
    "challenge.odd_one_out": "Quale elemento non appartiene?",
    "challenge.spatial": "Clicca sull'elemento nella {{position}}",
    "challenge.temporal": "Quale fotogramma mostra il {{event}}?",
    "error.expired": "Questa sfida è scaduta. Riprova.",
    "error.invalid": "Risposta errata. Riprova.",
    "error.too_many_attempts": "Troppi tentativi. Attendi {{seconds}} secondi.",
    "error.loading": "Caricamento sfida...",
    "success.verified": "Verifica riuscita!",
    "success.passed": "Hai superato la sfida!",
    "ui.submit": "Invia",
    "ui.refresh": "Nuova Sfida",
    "ui.audio": "Sfida Audio",
    "ui.help": "Aiuto",
    "ui.privacy": "Privacy",
    "ui.terms": "Termini",
    "plural.object": "{{count}} oggetto|{{count}} oggetti"
  },
  ja: {
    "challenge.instruction": "人間であることを証明するために正しい答えを選択してください",
    "challenge.click_shape": "{{color}}の{{shape}}をクリックしてください",
    "challenge.count_objects": "画像に{{object}}はいくつありますか？",
    "challenge.sequence": "次に来るものは何ですか？",
    "challenge.odd_one_out": "仲間はずれはどれですか？",
    "challenge.spatial": "{{position}}にあるアイテムをクリックしてください",
    "challenge.temporal": "{{event}}を示すフレームはどれですか？",
    "error.expired": "このチャレンジは期限切れです。もう一度お試しください。",
    "error.invalid": "不正解です。もう一度お試しください。",
    "error.too_many_attempts": "試行回数が多すぎます。{{seconds}}秒お待ちください。",
    "error.loading": "チャレンジを読み込み中...",
    "success.verified": "認証成功！",
    "success.passed": "チャレンジに合格しました！",
    "ui.submit": "送信",
    "ui.refresh": "新しいチャレンジ",
    "ui.audio": "音声チャレンジ",
    "ui.help": "ヘルプ",
    "ui.privacy": "プライバシー",
    "ui.terms": "利用規約",
    "plural.object": "{{count}}個"
  },
  ko: {
    "challenge.instruction": "사람임을 증명하기 위해 올바른 답을 선택하세요",
    "challenge.click_shape": "{{color}} {{shape}}을(를) 클릭하세요",
    "challenge.count_objects": "이미지에 {{object}}이(가) 몇 개 있나요?",
    "challenge.sequence": "다음에 오는 것은 무엇인가요?",
    "challenge.odd_one_out": "어울리지 않는 것은?",
    "challenge.spatial": "{{position}}에 있는 항목을 클릭하세요",
    "challenge.temporal": "{{event}}을(를) 보여주는 프레임은?",
    "error.expired": "이 챌린지가 만료되었습니다. 다시 시도해 주세요.",
    "error.invalid": "틀린 답입니다. 다시 시도해 주세요.",
    "error.too_many_attempts": "시도 횟수가 너무 많습니다. {{seconds}}초 후에 다시 시도하세요.",
    "error.loading": "챌린지 로딩 중...",
    "success.verified": "인증 성공!",
    "success.passed": "챌린지를 통과했습니다!",
    "ui.submit": "제출",
    "ui.refresh": "새 챌린지",
    "ui.audio": "오디오 챌린지",
    "ui.help": "도움말",
    "ui.privacy": "개인정보",
    "ui.terms": "이용약관",
    "plural.object": "{{count}}개"
  },
  zh: {
    "challenge.instruction": "选择正确答案以证明您是人类",
    "challenge.click_shape": "点击{{color}}的{{shape}}",
    "challenge.count_objects": "图片中有多少个{{object}}？",
    "challenge.sequence": "序列中接下来是什么？",
    "challenge.odd_one_out": "哪个不属于？",
    "challenge.spatial": "点击{{position}}的项目",
    "challenge.temporal": "哪一帧显示了{{event}}？",
    "error.expired": "此挑战已过期。请重试。",
    "error.invalid": "答案不正确。请重试。",
    "error.too_many_attempts": "尝试次数过多。请等待{{seconds}}秒。",
    "error.loading": "加载挑战中...",
    "success.verified": "验证成功！",
    "success.passed": "您通过了挑战！",
    "ui.submit": "提交",
    "ui.refresh": "新挑战",
    "ui.audio": "音频挑战",
    "ui.help": "帮助",
    "ui.privacy": "隐私",
    "ui.terms": "条款",
    "plural.object": "{{count}}个"
  },
  ar: {
    "challenge.instruction": "اختر الإجابة الصحيحة لإثبات أنك إنسان",
    "challenge.click_shape": "انقر على {{shape}} {{color}}",
    "challenge.count_objects": "كم عدد {{object}} في الصورة؟",
    "challenge.sequence": "ما الذي يأتي بعد ذلك في التسلسل؟",
    "challenge.odd_one_out": "أي عنصر لا ينتمي؟",
    "challenge.spatial": "انقر على العنصر في {{position}}",
    "challenge.temporal": "أي إطار يُظهر {{event}}؟",
    "error.expired": "انتهت صلاحية هذا التحدي. يرجى المحاولة مرة أخرى.",
    "error.invalid": "إجابة خاطئة. يرجى المحاولة مرة أخرى.",
    "error.too_many_attempts": "محاولات كثيرة. يرجى الانتظار {{seconds}} ثانية.",
    "error.loading": "جاري تحميل التحدي...",
    "success.verified": "تم التحقق بنجاح!",
    "success.passed": "لقد اجتزت التحدي!",
    "ui.submit": "إرسال",
    "ui.refresh": "تحدٍ جديد",
    "ui.audio": "تحدي صوتي",
    "ui.help": "مساعدة",
    "ui.privacy": "الخصوصية",
    "ui.terms": "الشروط",
    "plural.object": "{{count}} عنصر|{{count}} عناصر"
  },
  hi: {
    "challenge.instruction": "यह साबित करने के लिए कि आप इंसान हैं, सही उत्तर चुनें",
    "challenge.click_shape": "{{color}} {{shape}} पर क्लिक करें",
    "challenge.count_objects": "चित्र में कितने {{object}} हैं?",
    "challenge.sequence": "अनुक्रम में अगला क्या आता है?",
    "challenge.odd_one_out": "कौन सा आइटम नहीं है?",
    "challenge.spatial": "{{position}} में आइटम पर क्लिक करें",
    "challenge.temporal": "कौन सा फ्रेम {{event}} दिखाता है?",
    "error.expired": "यह चुनौती समाप्त हो गई है। कृपया पुनः प्रयास करें।",
    "error.invalid": "गलत उत्तर। कृपया पुनः प्रयास करें।",
    "error.too_many_attempts": "बहुत अधिक प्रयास। कृपया {{seconds}} सेकंड प्रतीक्षा करें।",
    "error.loading": "चुनौती लोड हो रही है...",
    "success.verified": "सत्यापन सफल!",
    "success.passed": "आपने चुनौती पास कर ली!",
    "ui.submit": "जमा करें",
    "ui.refresh": "नई चुनौती",
    "ui.audio": "ऑडियो चुनौती",
    "ui.help": "सहायता",
    "ui.privacy": "गोपनीयता",
    "ui.terms": "शर्तें",
    "plural.object": "{{count}} वस्तु|{{count}} वस्तुएँ"
  },
  ru: {
    "challenge.instruction": "Выберите правильный ответ, чтобы подтвердить, что вы человек",
    "challenge.click_shape": "Нажмите на {{color}} {{shape}}",
    "challenge.count_objects": "Сколько {{object}} на изображении?",
    "challenge.sequence": "Что идёт дальше в последовательности?",
    "challenge.odd_one_out": "Какой элемент лишний?",
    "challenge.spatial": "Нажмите на элемент в {{position}}",
    "challenge.temporal": "Какой кадр показывает {{event}}?",
    "error.expired": "Время этого задания истекло. Попробуйте снова.",
    "error.invalid": "Неправильный ответ. Попробуйте снова.",
    "error.too_many_attempts": "Слишком много попыток. Подождите {{seconds}} секунд.",
    "error.loading": "Загрузка задания...",
    "success.verified": "Проверка пройдена!",
    "success.passed": "Вы прошли проверку!",
    "ui.submit": "Отправить",
    "ui.refresh": "Новое задание",
    "ui.audio": "Аудио задание",
    "ui.help": "Помощь",
    "ui.privacy": "Конфиденциальность",
    "ui.terms": "Условия",
    "plural.object": "{{count}} объект|{{count}} объекта|{{count}} объектов"
  }
};

// ── RTL languages ───────────────────────────────────────────────────

var RTL_LOCALES = { ar: true, he: true, fa: true, ur: true };

// ── Pluralization rules ─────────────────────────────────────────────

var PLURAL_RULES = {
  // Returns index into pipe-separated plural forms
  en: function(n) { return n === 1 ? 0 : 1; },
  es: function(n) { return n === 1 ? 0 : 1; },
  fr: function(n) { return n <= 1 ? 0 : 1; },
  de: function(n) { return n === 1 ? 0 : 1; },
  pt: function(n) { return n === 1 ? 0 : 1; },
  it: function(n) { return n === 1 ? 0 : 1; },
  ja: function(_n) { return 0; },  // no plural
  ko: function(_n) { return 0; },  // no plural
  zh: function(_n) { return 0; },  // no plural
  ar: function(n) { return n === 1 ? 0 : 1; },  // simplified
  hi: function(n) { return n === 1 ? 0 : 1; },
  ru: function(n) {
    // Russian: 1 form, 2-4 form, 5+ form
    if (n % 10 === 1 && n % 100 !== 11) return 0;
    if (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20)) return 1;
    return 2;
  }
};

// ── Factory ─────────────────────────────────────────────────────────

/**
 * Create a CaptchaLocalizationManager instance.
 *
 * @param {Object} [options]
 * @param {string} [options.defaultLocale='en'] - Default locale for translations
 * @param {Object} [options.translations]       - Additional translations to merge
 * @param {Array}  [options.fallbackChain]      - Custom fallback order (default: detect → default → 'en')
 * @returns {CaptchaLocalizationManager}
 */
function createCaptchaLocalizationManager(options) {
  options = options || {};

  var defaultLocale = options.defaultLocale || 'en';
  var translations = {};
  var customPluralRules = {};

  // Deep-copy built-in translations
  var locales = Object.keys(BUILT_IN_TRANSLATIONS);
  for (var i = 0; i < locales.length; i++) {
    var loc = locales[i];
    translations[loc] = {};
    var keys = Object.keys(BUILT_IN_TRANSLATIONS[loc]);
    for (var j = 0; j < keys.length; j++) {
      translations[loc][keys[j]] = BUILT_IN_TRANSLATIONS[loc][keys[j]];
    }
  }

  // Merge user-provided translations
  if (options.translations) {
    var userLocales = Object.keys(options.translations);
    for (var ui = 0; ui < userLocales.length; ui++) {
      var uLoc = userLocales[ui];
      if (!translations[uLoc]) translations[uLoc] = {};
      var uKeys = Object.keys(options.translations[uLoc]);
      for (var uk = 0; uk < uKeys.length; uk++) {
        translations[uLoc][uKeys[uk]] = options.translations[uLoc][uKeys[uk]];
      }
    }
  }

  // ── Locale resolution ───────────────────────────────────────────

  /**
   * Normalize a locale string: lowercase, replace _ with -.
   */
  function normalizeLocale(locale) {
    if (!locale || typeof locale !== 'string') return defaultLocale;
    return locale.toLowerCase().replace(/_/g, '-');
  }

  /**
   * Get base language from locale (e.g. 'pt-BR' → 'pt').
   */
  function baseLanguage(locale) {
    var normalized = normalizeLocale(locale);
    var dash = normalized.indexOf('-');
    return dash > 0 ? normalized.substring(0, dash) : normalized;
  }

  /**
   * Build fallback chain for a locale.
   * e.g. 'pt-BR' → ['pt-br', 'pt', defaultLocale, 'en']
   */
  function buildFallbackChain(locale) {
    var chain = [];
    var normalized = normalizeLocale(locale);
    chain.push(normalized);
    var base = baseLanguage(normalized);
    if (base !== normalized) chain.push(base);
    if (defaultLocale !== normalized && defaultLocale !== base) chain.push(defaultLocale);
    if (chain.indexOf('en') === -1) chain.push('en');
    return chain;
  }

  /**
   * Detect locale from Accept-Language header string.
   * Returns the best matching supported locale.
   *
   * @param {string} acceptLanguage - e.g. 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7'
   * @returns {string} Best matching locale
   */
  function detectLocale(acceptLanguage) {
    if (!acceptLanguage || typeof acceptLanguage !== 'string') return defaultLocale;

    var parts = acceptLanguage.split(',');
    var candidates = [];

    for (var i = 0; i < parts.length; i++) {
      var part = parts[i].trim();
      var semi = part.indexOf(';');
      var lang, q;
      if (semi > 0) {
        lang = part.substring(0, semi).trim();
        var qMatch = part.substring(semi).match(/q\s*=\s*([\d.]+)/);
        q = qMatch ? parseFloat(qMatch[1]) : 1.0;
      } else {
        lang = part;
        q = 1.0;
      }
      candidates.push({ lang: normalizeLocale(lang), q: q });
    }

    // Sort by quality descending
    candidates.sort(function(a, b) { return b.q - a.q; });

    // Find best match
    for (var c = 0; c < candidates.length; c++) {
      var candidate = candidates[c].lang;
      if (translations[candidate]) return candidate;
      var cBase = baseLanguage(candidate);
      if (translations[cBase]) return cBase;
    }

    return defaultLocale;
  }

  // ── Interpolation ──────────────────────────────────────────────

  /**
   * Replace {{key}} placeholders in a string with values from vars.
   */
  function interpolate(str, vars) {
    if (!vars || typeof str !== 'string') return str;
    return str.replace(/\{\{(\w+)\}\}/g, function(_match, key) {
      return vars[key] !== undefined ? String(vars[key]) : '{{' + key + '}}';
    });
  }

  // ── Pluralization ──────────────────────────────────────────────

  /**
   * Apply pluralization to a pipe-separated string.
   */
  function pluralize(str, count, locale) {
    if (typeof str !== 'string' || str.indexOf('|') === -1) return str;
    var forms = str.split('|');
    var base = baseLanguage(locale);
    var rule = customPluralRules[base] || PLURAL_RULES[base] || PLURAL_RULES.en;
    var idx = rule(count);
    if (idx >= forms.length) idx = forms.length - 1;
    return forms[idx];
  }

  // ── Core translation ─────────────────────────────────────────

  /**
   * Translate a key with optional interpolation and pluralization.
   *
   * @param {string} key     - Translation key (e.g. 'challenge.instruction')
   * @param {Object} [opts]
   * @param {string} [opts.locale]  - Override locale
   * @param {number} [opts.count]   - For pluralization
   * @param {Object} [opts.vars]    - Variables for interpolation (also pulls from opts directly)
   * @returns {string} Translated string, or key if not found
   */
  function t(key, opts) {
    opts = opts || {};
    var locale = opts.locale || defaultLocale;
    var chain = buildFallbackChain(locale);
    var raw = null;

    for (var i = 0; i < chain.length; i++) {
      if (translations[chain[i]] && translations[chain[i]][key] !== undefined) {
        raw = translations[chain[i]][key];
        break;
      }
    }

    if (raw === null) return key;

    // Pluralization
    if (opts.count !== undefined) {
      raw = pluralize(raw, opts.count, locale);
    }

    // Build vars from opts + opts.vars
    var vars = {};
    if (opts.vars) {
      var vKeys = Object.keys(opts.vars);
      for (var v = 0; v < vKeys.length; v++) vars[vKeys[v]] = opts.vars[vKeys[v]];
    }
    // Also pull known var-like keys from opts directly
    var optKeys = Object.keys(opts);
    for (var o = 0; o < optKeys.length; o++) {
      var k = optKeys[o];
      if (k !== 'locale' && k !== 'count' && k !== 'vars' && typeof opts[k] !== 'object') {
        vars[k] = opts[k];
      }
    }
    if (opts.count !== undefined) vars.count = opts.count;

    return interpolate(raw, vars);
  }

  // ── Management API ────────────────────────────────────────────

  /**
   * Add or merge translations for a locale.
   */
  function addTranslations(locale, newTranslations) {
    if (!locale || typeof locale !== 'string') throw new Error('Locale required');
    if (!newTranslations || typeof newTranslations !== 'object') throw new Error('Translations object required');
    var norm = normalizeLocale(locale);
    if (!translations[norm]) translations[norm] = {};
    var keys = Object.keys(newTranslations);
    for (var i = 0; i < keys.length; i++) {
      translations[norm][keys[i]] = newTranslations[keys[i]];
    }
  }

  /**
   * Remove all translations for a locale.
   */
  function removeLocale(locale) {
    var norm = normalizeLocale(locale);
    if (norm === 'en') throw new Error('Cannot remove base locale "en"');
    delete translations[norm];
  }

  /**
   * Register a custom plural rule for a locale.
   */
  function addPluralRule(locale, ruleFn) {
    if (typeof ruleFn !== 'function') throw new Error('Plural rule must be a function');
    customPluralRules[baseLanguage(locale)] = ruleFn;
  }

  /**
   * Get all supported locale codes.
   */
  function getLocales() {
    return Object.keys(translations).sort();
  }

  /**
   * Check if a locale is RTL.
   */
  function isRTL(locale) {
    return !!RTL_LOCALES[baseLanguage(locale)];
  }

  /**
   * Get all translation keys for the base locale (en).
   */
  function getKeys() {
    return Object.keys(translations.en || {}).sort();
  }

  /**
   * Generate a coverage report showing translation completeness.
   */
  function coverageReport() {
    var baseKeys = getKeys();
    var totalKeys = baseKeys.length;
    var report = { totalKeys: totalKeys, locales: {} };
    var allLocales = getLocales();

    for (var i = 0; i < allLocales.length; i++) {
      var loc = allLocales[i];
      var trans = translations[loc] || {};
      var translated = 0;
      var missing = [];
      for (var j = 0; j < baseKeys.length; j++) {
        if (trans[baseKeys[j]] !== undefined) {
          translated++;
        } else {
          missing.push(baseKeys[j]);
        }
      }
      report.locales[loc] = {
        translated: translated,
        total: totalKeys,
        coverage: totalKeys > 0 ? Math.round((translated / totalKeys) * 100) : 0,
        missing: missing
      };
    }

    return report;
  }

  /**
   * Translate all keys for a locale, returning a flat object.
   * Useful for bulk export or client-side hydration.
   */
  function translateAll(locale, vars) {
    var allKeys = getKeys();
    var result = {};
    for (var i = 0; i < allKeys.length; i++) {
      result[allKeys[i]] = t(allKeys[i], { locale: locale, vars: vars });
    }
    return result;
  }

  /**
   * Get the direction attribute value for a locale.
   * @returns {'rtl'|'ltr'}
   */
  function getDirection(locale) {
    return isRTL(locale) ? 'rtl' : 'ltr';
  }

  // ── Public API ────────────────────────────────────────────────

  return {
    t: t,
    translate: t,
    detectLocale: detectLocale,
    addTranslations: addTranslations,
    removeLocale: removeLocale,
    addPluralRule: addPluralRule,
    getLocales: getLocales,
    getKeys: getKeys,
    isRTL: isRTL,
    getDirection: getDirection,
    coverageReport: coverageReport,
    translateAll: translateAll,
    normalizeLocale: normalizeLocale,
    buildFallbackChain: buildFallbackChain
  };
}

// ── Export ───────────────────────────────────────────────────────────

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { createCaptchaLocalizationManager: createCaptchaLocalizationManager };
}
