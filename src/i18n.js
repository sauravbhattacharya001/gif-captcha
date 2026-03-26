"use strict";

// ── Internationalization ────────────────────────────────────────────

/**
 * createI18n — Localization support for CAPTCHA UI strings.
 *
 * Ships with built-in translations for common CAPTCHA labels, instructions,
 * error messages, and accessibility text.  Custom locales can be registered
 * at runtime.
 *
 * Supported built-in locales: en, es, fr, de, pt, ja, zh, ko, ar, hi, ru, it
 *
 * Usage:
 *   var i18n = gifCaptcha.createI18n({ locale: "es" });
 *   i18n.t("instructions");   // "Selecciona la imagen correcta..."
 *   i18n.t("error.timeout");  // "Tiempo agotado. Inténtalo de nuevo."
 *   i18n.t("greeting", { name: "Ana" }); // interpolation
 *   i18n.setLocale("fr");
 *   i18n.addLocale("th", { instructions: "เลือกภาพ..." });
 *
 * @param {Object} [options]
 * @param {string} [options.locale="en"]         Active locale
 * @param {string} [options.fallbackLocale="en"] Fallback when key missing
 * @param {Object} [options.locales]             Extra locale maps to merge
 * @returns {Object} i18n instance
 */
function createI18n(options) {
  options = options || {};
  var fallbackLocale = (typeof options.fallbackLocale === "string") ? options.fallbackLocale : "en";
  var currentLocale = (typeof options.locale === "string") ? options.locale : "en";

  var catalogs = {
    en: {
      "instructions":        "Select the correct image to prove you are human.",
      "instructions.audio":  "Listen to the audio and type what you hear.",
      "submit":              "Submit",
      "retry":               "Try Again",
      "loading":             "Loading challenge…",
      "success":             "Verification successful!",
      "error.generic":       "Something went wrong. Please try again.",
      "error.timeout":       "Time expired. Please try again.",
      "error.wrong":         "Incorrect answer. Please try again.",
      "error.tooMany":       "Too many attempts. Please wait before trying again.",
      "error.blocked":       "Access denied.",
      "accessibility.label": "CAPTCHA verification challenge",
      "accessibility.help":  "Complete this challenge to continue.",
      "timer.remaining":     "Time remaining: {seconds} seconds",
      "attempts.remaining":  "Attempts remaining: {count}",
      "difficulty.easy":     "Easy",
      "difficulty.medium":   "Medium",
      "difficulty.hard":     "Hard"
    },
    es: {
      "instructions":        "Selecciona la imagen correcta para demostrar que eres humano.",
      "instructions.audio":  "Escucha el audio y escribe lo que oyes.",
      "submit":              "Enviar",
      "retry":               "Intentar de nuevo",
      "loading":             "Cargando desafío…",
      "success":             "¡Verificación exitosa!",
      "error.generic":       "Algo salió mal. Inténtalo de nuevo.",
      "error.timeout":       "Tiempo agotado. Inténtalo de nuevo.",
      "error.wrong":         "Respuesta incorrecta. Inténtalo de nuevo.",
      "error.tooMany":       "Demasiados intentos. Espera antes de intentarlo de nuevo.",
      "error.blocked":       "Acceso denegado.",
      "accessibility.label": "Desafío de verificación CAPTCHA",
      "accessibility.help":  "Completa este desafío para continuar.",
      "timer.remaining":     "Tiempo restante: {seconds} segundos",
      "attempts.remaining":  "Intentos restantes: {count}",
      "difficulty.easy":     "Fácil",
      "difficulty.medium":   "Medio",
      "difficulty.hard":     "Difícil"
    },
    fr: {
      "instructions":        "Sélectionnez la bonne image pour prouver que vous êtes humain.",
      "instructions.audio":  "Écoutez l'audio et tapez ce que vous entendez.",
      "submit":              "Soumettre",
      "retry":               "Réessayer",
      "loading":             "Chargement du défi…",
      "success":             "Vérification réussie !",
      "error.generic":       "Une erreur est survenue. Veuillez réessayer.",
      "error.timeout":       "Temps écoulé. Veuillez réessayer.",
      "error.wrong":         "Réponse incorrecte. Veuillez réessayer.",
      "error.tooMany":       "Trop de tentatives. Veuillez patienter.",
      "error.blocked":       "Accès refusé.",
      "accessibility.label": "Défi de vérification CAPTCHA",
      "accessibility.help":  "Complétez ce défi pour continuer.",
      "timer.remaining":     "Temps restant : {seconds} secondes",
      "attempts.remaining":  "Tentatives restantes : {count}",
      "difficulty.easy":     "Facile",
      "difficulty.medium":   "Moyen",
      "difficulty.hard":     "Difficile"
    },
    de: {
      "instructions":        "Wählen Sie das richtige Bild, um zu beweisen, dass Sie ein Mensch sind.",
      "instructions.audio":  "Hören Sie sich das Audio an und geben Sie ein, was Sie hören.",
      "submit":              "Absenden",
      "retry":               "Erneut versuchen",
      "loading":             "Herausforderung wird geladen…",
      "success":             "Verifizierung erfolgreich!",
      "error.generic":       "Etwas ist schiefgelaufen. Bitte versuchen Sie es erneut.",
      "error.timeout":       "Zeit abgelaufen. Bitte versuchen Sie es erneut.",
      "error.wrong":         "Falsche Antwort. Bitte versuchen Sie es erneut.",
      "error.tooMany":       "Zu viele Versuche. Bitte warten Sie.",
      "error.blocked":       "Zugang verweigert.",
      "accessibility.label": "CAPTCHA-Verifizierungsaufgabe",
      "accessibility.help":  "Schließen Sie diese Aufgabe ab, um fortzufahren.",
      "timer.remaining":     "Verbleibende Zeit: {seconds} Sekunden",
      "attempts.remaining":  "Verbleibende Versuche: {count}",
      "difficulty.easy":     "Leicht",
      "difficulty.medium":   "Mittel",
      "difficulty.hard":     "Schwer"
    },
    pt: {
      "instructions":        "Selecione a imagem correta para provar que você é humano.",
      "submit":              "Enviar",
      "retry":               "Tentar novamente",
      "loading":             "Carregando desafio…",
      "success":             "Verificação bem-sucedida!",
      "error.generic":       "Algo deu errado. Tente novamente.",
      "error.timeout":       "Tempo esgotado. Tente novamente.",
      "error.wrong":         "Resposta incorreta. Tente novamente.",
      "error.tooMany":       "Muitas tentativas. Aguarde antes de tentar novamente.",
      "error.blocked":       "Acesso negado.",
      "accessibility.label": "Desafio de verificação CAPTCHA",
      "timer.remaining":     "Tempo restante: {seconds} segundos",
      "attempts.remaining":  "Tentativas restantes: {count}",
      "difficulty.easy":     "Fácil",
      "difficulty.medium":   "Médio",
      "difficulty.hard":     "Difícil"
    },
    ja: {
      "instructions":        "正しい画像を選択して、あなたが人間であることを証明してください。",
      "submit":              "送信",
      "retry":               "もう一度試す",
      "loading":             "チャレンジを読み込み中…",
      "success":             "認証成功！",
      "error.generic":       "エラーが発生しました。もう一度お試しください。",
      "error.timeout":       "時間切れです。もう一度お試しください。",
      "error.wrong":         "不正解です。もう一度お試しください。",
      "error.tooMany":       "試行回数が多すぎます。しばらくお待ちください。",
      "error.blocked":       "アクセスが拒否されました。",
      "accessibility.label": "CAPTCHA認証チャレンジ",
      "timer.remaining":     "残り時間: {seconds}秒",
      "attempts.remaining":  "残り試行回数: {count}",
      "difficulty.easy":     "簡単",
      "difficulty.medium":   "普通",
      "difficulty.hard":     "難しい"
    },
    zh: {
      "instructions":        "请选择正确的图片以证明您是人类。",
      "submit":              "提交",
      "retry":               "重试",
      "loading":             "正在加载验证…",
      "success":             "验证成功！",
      "error.generic":       "出现错误，请重试。",
      "error.timeout":       "已超时，请重试。",
      "error.wrong":         "回答不正确，请重试。",
      "error.tooMany":       "尝试次数过多，请稍后再试。",
      "error.blocked":       "访问被拒绝。",
      "accessibility.label": "CAPTCHA验证挑战",
      "timer.remaining":     "剩余时间：{seconds}秒",
      "attempts.remaining":  "剩余尝试次数：{count}",
      "difficulty.easy":     "简单",
      "difficulty.medium":   "中等",
      "difficulty.hard":     "困难"
    },
    ko: {
      "instructions":        "올바른 이미지를 선택하여 사람임을 증명하세요.",
      "submit":              "제출",
      "retry":               "다시 시도",
      "loading":             "챌린지 로딩 중…",
      "success":             "인증 성공!",
      "error.generic":       "오류가 발생했습니다. 다시 시도해 주세요.",
      "error.timeout":       "시간이 초과되었습니다. 다시 시도해 주세요.",
      "error.wrong":         "오답입니다. 다시 시도해 주세요.",
      "error.tooMany":       "시도 횟수를 초과했습니다. 잠시 후 다시 시도해 주세요.",
      "error.blocked":       "접근이 거부되었습니다.",
      "accessibility.label": "CAPTCHA 인증 챌린지",
      "timer.remaining":     "남은 시간: {seconds}초",
      "attempts.remaining":  "남은 시도 횟수: {count}",
      "difficulty.easy":     "쉬움",
      "difficulty.medium":   "보통",
      "difficulty.hard":     "어려움"
    },
    ar: {
      "instructions":        "اختر الصورة الصحيحة لإثبات أنك إنسان.",
      "submit":              "إرسال",
      "retry":               "حاول مرة أخرى",
      "loading":             "جارٍ تحميل التحدي…",
      "success":             "تم التحقق بنجاح!",
      "error.generic":       "حدث خطأ. يرجى المحاولة مرة أخرى.",
      "error.timeout":       "انتهى الوقت. يرجى المحاولة مرة أخرى.",
      "error.wrong":         "إجابة خاطئة. يرجى المحاولة مرة أخرى.",
      "error.tooMany":       "محاولات كثيرة جداً. يرجى الانتظار.",
      "error.blocked":       "تم رفض الوصول.",
      "accessibility.label": "تحدي التحقق CAPTCHA",
      "timer.remaining":     "الوقت المتبقي: {seconds} ثانية",
      "attempts.remaining":  "المحاولات المتبقية: {count}",
      "difficulty.easy":     "سهل",
      "difficulty.medium":   "متوسط",
      "difficulty.hard":     "صعب"
    },
    hi: {
      "instructions":        "यह साबित करने के लिए कि आप इंसान हैं, सही छवि चुनें।",
      "submit":              "जमा करें",
      "retry":               "पुनः प्रयास करें",
      "loading":             "चुनौती लोड हो रही है…",
      "success":             "सत्यापन सफल!",
      "error.generic":       "कुछ गलत हो गया। कृपया पुनः प्रयास करें।",
      "error.timeout":       "समय समाप्त। कृपया पुनः प्रयास करें।",
      "error.wrong":         "गलत उत्तर। कृपया पुनः प्रयास करें।",
      "error.tooMany":       "बहुत अधिक प्रयास। कृपया प्रतीक्षा करें।",
      "error.blocked":       "पहुँच अस्वीकृत।",
      "accessibility.label": "CAPTCHA सत्यापन चुनौती",
      "timer.remaining":     "शेष समय: {seconds} सेकंड",
      "attempts.remaining":  "शेष प्रयास: {count}",
      "difficulty.easy":     "आसान",
      "difficulty.medium":   "मध्यम",
      "difficulty.hard":     "कठिन"
    },
    ru: {
      "instructions":        "Выберите правильное изображение, чтобы подтвердить, что вы человек.",
      "submit":              "Отправить",
      "retry":               "Попробовать снова",
      "loading":             "Загрузка задания…",
      "success":             "Проверка пройдена!",
      "error.generic":       "Что-то пошло не так. Попробуйте ещё раз.",
      "error.timeout":       "Время истекло. Попробуйте ещё раз.",
      "error.wrong":         "Неправильный ответ. Попробуйте ещё раз.",
      "error.tooMany":       "Слишком много попыток. Подождите немного.",
      "error.blocked":       "Доступ запрещён.",
      "accessibility.label": "Задание проверки CAPTCHA",
      "timer.remaining":     "Осталось времени: {seconds} секунд",
      "attempts.remaining":  "Осталось попыток: {count}",
      "difficulty.easy":     "Легко",
      "difficulty.medium":   "Средне",
      "difficulty.hard":     "Сложно"
    },
    it: {
      "instructions":        "Seleziona l'immagine corretta per dimostrare che sei umano.",
      "submit":              "Invia",
      "retry":               "Riprova",
      "loading":             "Caricamento sfida…",
      "success":             "Verifica riuscita!",
      "error.generic":       "Qualcosa è andato storto. Riprova.",
      "error.timeout":       "Tempo scaduto. Riprova.",
      "error.wrong":         "Risposta errata. Riprova.",
      "error.tooMany":       "Troppi tentativi. Attendi prima di riprovare.",
      "error.blocked":       "Accesso negato.",
      "accessibility.label": "Sfida di verifica CAPTCHA",
      "timer.remaining":     "Tempo rimanente: {seconds} secondi",
      "attempts.remaining":  "Tentativi rimanenti: {count}",
      "difficulty.easy":     "Facile",
      "difficulty.medium":   "Medio",
      "difficulty.hard":     "Difficile"
    }
  };

  if (options.locales && typeof options.locales === "object") {
    var keys = Object.keys(options.locales);
    for (var i = 0; i < keys.length; i++) {
      addLocale(keys[i], options.locales[keys[i]]);
    }
  }

  function t(key, vars) {
    var catalog = catalogs[currentLocale];
    var str = (catalog && catalog[key]) || null;
    if (str === null) {
      var fb = catalogs[fallbackLocale];
      str = (fb && fb[key]) || key;
    }
    if (vars && typeof vars === "object") {
      var vkeys = Object.keys(vars);
      for (var i = 0; i < vkeys.length; i++) {
        str = str.split("{" + vkeys[i] + "}").join(String(vars[vkeys[i]]));
      }
    }
    return str;
  }

  function addLocale(locale, strings) {
    if (typeof locale !== "string" || !strings || typeof strings !== "object") return;
    if (!catalogs[locale]) catalogs[locale] = Object.create(null);
    var keys = Object.keys(strings);
    for (var i = 0; i < keys.length; i++) {
      catalogs[locale][keys[i]] = String(strings[keys[i]]);
    }
  }

  function setLocale(locale) {
    if (typeof locale === "string") currentLocale = locale;
  }

  function getLocale() { return currentLocale; }

  function getAvailableLocales() { return Object.keys(catalogs); }

  function hasKey(key) {
    var catalog = catalogs[currentLocale];
    if (catalog && catalog[key] != null) return true;
    var fb = catalogs[fallbackLocale];
    return !!(fb && fb[key] != null);
  }

  function exportCatalog() {
    var result = Object.create(null);
    var locales = Object.keys(catalogs);
    for (var i = 0; i < locales.length; i++) {
      result[locales[i]] = Object.create(null);
      var keys = Object.keys(catalogs[locales[i]]);
      for (var j = 0; j < keys.length; j++) {
        result[locales[i]][keys[j]] = catalogs[locales[i]][keys[j]];
      }
    }
    return result;
  }

  return {
    t: t,
    addLocale: addLocale,
    setLocale: setLocale,
    getLocale: getLocale,
    getAvailableLocales: getAvailableLocales,
    hasKey: hasKey,
    exportCatalog: exportCatalog
  };
}



module.exports = { createI18n: createI18n };

