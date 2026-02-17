import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type AppLocale = "en" | "fa" | "ru";

type LocaleMeta = {
  label: string;
  direction: "ltr" | "rtl";
  bcp47: string;
};

type TranslateValues = Record<string, string | number>;

type I18nContextValue = {
  locale: AppLocale;
  availableLocales: AppLocale[];
  localeMeta: Record<AppLocale, LocaleMeta>;
  setLocale: (next: AppLocale) => void;
  t: (key: string, values?: TranslateValues) => string;
  tr: (message: string) => string;
  formatNumber: (value: number) => string;
  formatDateTime: (value: number | string | Date) => string;
};

const STORAGE_KEY = "nullid:locale";
const FALLBACK_LOCALE: AppLocale = "en";

const localeMeta: Record<AppLocale, LocaleMeta> = {
  en: { label: "English", direction: "ltr", bcp47: "en-US" },
  fa: { label: "فارسی", direction: "rtl", bcp47: "fa-IR" },
  ru: { label: "Русский", direction: "ltr", bcp47: "ru-RU" },
};

const messages: Record<AppLocale, Record<string, string>> = {
  en: {
    "locale.en": "English",
    "locale.fa": "Persian",
    "locale.ru": "Russian",

    "module.hash.title": "Hash & Verify",
    "module.hash.subtitle": "digests",
    "module.redact.title": "Text Redaction",
    "module.redact.subtitle": "pii scrubbing",
    "module.sanitize.title": "Log Sanitizer",
    "module.sanitize.subtitle": "diff preview",
    "module.meta.title": "Metadata Inspector",
    "module.meta.subtitle": "exif",
    "module.enc.title": "Encrypt / Decrypt",
    "module.enc.subtitle": "envelopes",
    "module.pw.title": "Password & Passphrase",
    "module.pw.subtitle": "generator",
    "module.vault.title": "Secure Notes",
    "module.vault.subtitle": "sealed",
    "module.selftest.title": "Self-test",
    "module.selftest.subtitle": "diagnostics",
    "module.guide.title": "Guide",
    "module.guide.subtitle": "how-to",

    "app.ready": "ready",
    "app.loading": "loading module...",
    "app.themeLabel": "Theme",
    "app.theme.dark": "Dark",
    "app.theme.light": "Light",
    "app.wipeData": "Wipe data",
    "app.commands": "/ Commands",
    "app.actions": "Actions",
    "app.openQuickActions": "Open quick actions",
    "app.language": "Language",
    "app.status": "Status",
    "app.connectionIndicators": "Connection indicators",
    "app.local": "local",
    "app.offline": "offline",
    "app.noNet": "no-net",
    "app.tools": "Tools",
    "app.navigate": "Navigate",
    "app.moduleList": "Module list",
    "app.buildMarker": "Build marker",

    "app.commandPalette": "Command palette",
    "app.searchCommands": "Search commands",
    "app.commandInputPlaceholder": "Type a command or tool…",
    "app.commandsList": "Commands",
    "app.noCommands": "No commands",
    "app.closeCommandPalette": "Close command palette",

    "app.confirm": "confirm",
    "app.cancel": "cancel",

    "onboarding.dialog": "Onboarding tour",
    "onboarding.step": "step {{current}}/{{total}}",
    "onboarding.skip": "skip",
    "onboarding.back": "back",
    "onboarding.next": "next",
    "onboarding.finish": "finish",

    "feedback.panel": "Feedback panel",
    "feedback.title": "Feedback",
    "feedback.close": "close",
    "feedback.stored": "Stored locally only ({{count}} saved). Use export to share.",
    "feedback.category": "Feedback category",
    "feedback.priority": "Feedback priority",
    "feedback.message": "Feedback message",
    "feedback.context": "Context: :{{module}} (what worked, what broke, what should be added)",
    "feedback.save": "save local",
    "feedback.export": "export json",
    "feedback.clear": "clear draft",
    "feedback.open": "Open feedback",
    "feedback.launcher": "feedback",
    "feedback.idea": "idea",
    "feedback.bug": "bug",
    "feedback.ux": "ux",
    "feedback.performance": "performance",
    "feedback.low": "low",
    "feedback.medium": "medium",
    "feedback.high": "high",

    "error.title": "Something went wrong",
    "error.body": "The UI recovered from an error. Please retry your last action.",
    "error.dismiss": "Dismiss",

    "app.command.toolsGroup": "Tools",
    "app.command.systemGroup": "System",
    "app.command.hashGroup": "Hash actions",
    "app.command.toggleTheme": "Toggle theme",
    "app.command.switchTheme": "Switch between light and dark",
    "app.command.wipe": "Wipe local data",
    "app.command.clearPrefs": "Clear preferences and stored content",
    "app.command.exportProfile": "Export profile",
    "app.command.exportProfileDesc": "Download preferences as JSON",
    "app.command.importProfile": "Import profile",
    "app.command.importProfileDesc": "Load preferences from JSON",
    "app.command.runOnboarding": "Run onboarding",
    "app.command.runOnboardingDesc": "Replay quick setup tour",
    "app.command.compareDigest": "Compare digest",
    "app.command.compareDigestDesc": "Validate against provided hash",
    "app.command.clearInputs": "Clear inputs",
    "app.command.clearInputsDesc": "Reset text, file, and verify fields",
    "app.command.copyDigest": "Copy digest",
    "app.command.copyDigestDesc": "Copy computed hash to clipboard",
    "app.command.language.en": "Language: English",
    "app.command.language.fa": "Language: Persian",
    "app.command.language.ru": "Language: Russian",
    "app.command.languageDesc": "Switch UI language",

    "app.onboarding.1.title": "Start with the Guide",
    "app.onboarding.1.body": "Every tool has limits and safe defaults. The guide gives the shortest path to avoid common mistakes.",
    "app.onboarding.1.action": "open guide",
    "app.onboarding.2.title": "Use the Strength Lab",
    "app.onboarding.2.body": "The Password & Passphrase module includes a larger dictionary, hardening toggles, and secret auditing.",
    "app.onboarding.2.action": "open :pw",
    "app.onboarding.3.title": "Sanitize before sharing",
    "app.onboarding.3.body": "Use the Log Sanitizer for policy packs, diff preview, and bundle exports when sharing logs externally.",
    "app.onboarding.3.action": "open :sanitize",
    "app.onboarding.4.title": "Drive the app from commands",
    "app.onboarding.4.body": "Press / or Cmd/Ctrl+K for fast navigation, profile export/import, and system actions.",
    "app.onboarding.4.action": "open commands",
    "app.onboarding.5.title": "Track feedback locally",
    "app.onboarding.5.body": "Use the feedback button at the bottom-left to save issues and ideas locally, then export as JSON.",

    "runtime.theme": "theme :: {{value}}",
    "runtime.module": "module :: {{value}}",
    "runtime.command": "command :: {{value}}",
    "runtime.error": "error :: {{value}}",
    "runtime.languageChanged": "language changed: {{value}}",
    "runtime.localDataWiped": "local data wiped",
    "runtime.dataWiped": "data wiped",
    "runtime.onboarding": "onboarding",
    "runtime.onboardingComplete": "onboarding complete",
    "runtime.onboardingSkipped": "onboarding skipped",
    "runtime.profileExported": "profile exported",
    "runtime.profileImported": "profile imported",
    "runtime.importFailed": "import failed",
    "runtime.runtimeError": "runtime error: {{value}}",
    "runtime.unhandledPromise": "unhandled promise rejection",

    "runtime.dark": "dark",
    "runtime.light": "light",

    "guide.link": "? guide",
  },
  fa: {
    "locale.en": "انگلیسی",
    "locale.fa": "فارسی",
    "locale.ru": "روسی",

    "module.hash.title": "هش و اعتبارسنجی",
    "module.hash.subtitle": "هش‌ها",
    "module.redact.title": "حذف اطلاعات حساس",
    "module.redact.subtitle": "پاک‌سازی PII",
    "module.sanitize.title": "پاک‌ساز لاگ",
    "module.sanitize.subtitle": "پیش‌نمایش تفاوت",
    "module.meta.title": "بازرس فراداده",
    "module.meta.subtitle": "EXIF",
    "module.enc.title": "رمزگذاری / رمزگشایی",
    "module.enc.subtitle": "پاکت‌ها",
    "module.pw.title": "گذرواژه و عبارت عبور",
    "module.pw.subtitle": "تولیدکننده",
    "module.vault.title": "یادداشت امن",
    "module.vault.subtitle": "مهر و موم‌شده",
    "module.selftest.title": "خودآزمون",
    "module.selftest.subtitle": "عیب‌یابی",
    "module.guide.title": "راهنما",
    "module.guide.subtitle": "نحوه استفاده",

    "app.ready": "آماده",
    "app.loading": "در حال بارگذاری ماژول...",
    "app.themeLabel": "پوسته",
    "app.theme.dark": "تیره",
    "app.theme.light": "روشن",
    "app.wipeData": "پاک کردن داده‌ها",
    "app.commands": "/ فرمان‌ها",
    "app.actions": "عملیات",
    "app.openQuickActions": "باز کردن عملیات سریع",
    "app.language": "زبان",
    "app.status": "وضعیت",
    "app.connectionIndicators": "نشانگرهای اتصال",
    "app.local": "محلی",
    "app.offline": "آفلاین",
    "app.noNet": "بدون شبکه",
    "app.tools": "ابزارها",
    "app.navigate": "ناوبری",
    "app.moduleList": "فهرست ماژول‌ها",
    "app.buildMarker": "شناسه بیلد",

    "app.commandPalette": "پالت فرمان",
    "app.searchCommands": "جستجوی فرمان‌ها",
    "app.commandInputPlaceholder": "یک فرمان یا ابزار بنویسید…",
    "app.commandsList": "فرمان‌ها",
    "app.noCommands": "فرمانی یافت نشد",
    "app.closeCommandPalette": "بستن پالت فرمان",

    "app.confirm": "تایید",
    "app.cancel": "لغو",

    "onboarding.dialog": "راهنمای شروع",
    "onboarding.step": "مرحله {{current}}/{{total}}",
    "onboarding.skip": "رد کردن",
    "onboarding.back": "قبلی",
    "onboarding.next": "بعدی",
    "onboarding.finish": "پایان",

    "feedback.panel": "پنل بازخورد",
    "feedback.title": "بازخورد",
    "feedback.close": "بستن",
    "feedback.stored": "فقط به‌صورت محلی ذخیره می‌شود ({{count}} مورد). برای اشتراک‌گذاری خروجی بگیرید.",
    "feedback.category": "دسته‌بندی بازخورد",
    "feedback.priority": "اولویت بازخورد",
    "feedback.message": "متن بازخورد",
    "feedback.context": "زمینه: :{{module}} (چه چیزی خوب بود، چه چیزی شکست، چه باید اضافه شود)",
    "feedback.save": "ذخیره محلی",
    "feedback.export": "خروجی JSON",
    "feedback.clear": "پاک کردن پیش‌نویس",
    "feedback.open": "باز کردن بازخورد",
    "feedback.launcher": "بازخورد",
    "feedback.idea": "ایده",
    "feedback.bug": "باگ",
    "feedback.ux": "تجربه کاربری",
    "feedback.performance": "کارایی",
    "feedback.low": "کم",
    "feedback.medium": "متوسط",
    "feedback.high": "زیاد",

    "error.title": "مشکلی رخ داد",
    "error.body": "رابط کاربری از خطا بازیابی شد. لطفا آخرین عمل را دوباره انجام دهید.",
    "error.dismiss": "بستن",

    "app.command.toolsGroup": "ابزارها",
    "app.command.systemGroup": "سیستم",
    "app.command.hashGroup": "عملیات هش",
    "app.command.toggleTheme": "تغییر پوسته",
    "app.command.switchTheme": "جابجایی بین حالت روشن و تیره",
    "app.command.wipe": "پاک کردن داده‌های محلی",
    "app.command.clearPrefs": "حذف تنظیمات و داده‌های ذخیره‌شده",
    "app.command.exportProfile": "خروجی پروفایل",
    "app.command.exportProfileDesc": "دانلود تنظیمات به‌صورت JSON",
    "app.command.importProfile": "ورودی پروفایل",
    "app.command.importProfileDesc": "بارگذاری تنظیمات از JSON",
    "app.command.runOnboarding": "اجرای راهنمای شروع",
    "app.command.runOnboardingDesc": "نمایش دوباره راه‌اندازی سریع",
    "app.command.compareDigest": "مقایسه هش",
    "app.command.compareDigestDesc": "اعتبارسنجی با هش ارائه‌شده",
    "app.command.clearInputs": "پاک کردن ورودی‌ها",
    "app.command.clearInputsDesc": "بازنشانی متن، فایل و فیلد اعتبارسنجی",
    "app.command.copyDigest": "کپی هش",
    "app.command.copyDigestDesc": "کپی هش محاسبه‌شده در کلیپ‌بورد",
    "app.command.language.en": "زبان: انگلیسی",
    "app.command.language.fa": "زبان: فارسی",
    "app.command.language.ru": "زبان: روسی",
    "app.command.languageDesc": "تغییر زبان رابط",

    "app.onboarding.1.title": "از راهنما شروع کنید",
    "app.onboarding.1.body": "هر ابزار محدودیت‌ها و پیش‌فرض‌های ایمن دارد. راهنما کوتاه‌ترین مسیر برای جلوگیری از اشتباهات رایج است.",
    "app.onboarding.1.action": "باز کردن راهنما",
    "app.onboarding.2.title": "از آزمایشگاه قدرت استفاده کنید",
    "app.onboarding.2.body": "ماژول گذرواژه و عبارت عبور شامل واژه‌نامه بزرگ‌تر، گزینه‌های سخت‌سازی و ممیزی رازها است.",
    "app.onboarding.2.action": "باز کردن :pw",
    "app.onboarding.3.title": "قبل از اشتراک‌گذاری پاک‌سازی کنید",
    "app.onboarding.3.body": "برای بسته‌های سیاست، پیش‌نمایش تفاوت و خروجی بسته‌ها هنگام اشتراک لاگ از پاک‌ساز لاگ استفاده کنید.",
    "app.onboarding.3.action": "باز کردن :sanitize",
    "app.onboarding.4.title": "اپ را با فرمان‌ها کنترل کنید",
    "app.onboarding.4.body": "برای ناوبری سریع، خروجی/ورودی پروفایل و عملیات سیستمی کلید / یا Cmd/Ctrl+K را بزنید.",
    "app.onboarding.4.action": "باز کردن فرمان‌ها",
    "app.onboarding.5.title": "بازخورد را محلی ثبت کنید",
    "app.onboarding.5.body": "از دکمه بازخورد در پایین-چپ برای ذخیره محلی مسائل و ایده‌ها استفاده کنید و سپس خروجی JSON بگیرید.",

    "runtime.theme": "پوسته :: {{value}}",
    "runtime.module": "ماژول :: {{value}}",
    "runtime.command": "فرمان :: {{value}}",
    "runtime.error": "خطا :: {{value}}",
    "runtime.languageChanged": "زبان تغییر کرد: {{value}}",
    "runtime.localDataWiped": "داده‌های محلی پاک شد",
    "runtime.dataWiped": "داده‌ها پاک شدند",
    "runtime.onboarding": "راهنمای شروع",
    "runtime.onboardingComplete": "راهنمای شروع کامل شد",
    "runtime.onboardingSkipped": "راهنمای شروع رد شد",
    "runtime.profileExported": "پروفایل خروجی گرفته شد",
    "runtime.profileImported": "پروفایل وارد شد",
    "runtime.importFailed": "ورود ناموفق",
    "runtime.runtimeError": "خطای زمان اجرا: {{value}}",
    "runtime.unhandledPromise": "وعده مدیریت‌نشده",

    "runtime.dark": "تیره",
    "runtime.light": "روشن",

    "guide.link": "? راهنما",
  },
  ru: {
    "locale.en": "Английский",
    "locale.fa": "Персидский",
    "locale.ru": "Русский",

    "module.hash.title": "Хэш и проверка",
    "module.hash.subtitle": "дайджесты",
    "module.redact.title": "Редактирование текста",
    "module.redact.subtitle": "очистка PII",
    "module.sanitize.title": "Санитайзер логов",
    "module.sanitize.subtitle": "предпросмотр diff",
    "module.meta.title": "Инспектор метаданных",
    "module.meta.subtitle": "exif",
    "module.enc.title": "Шифрование / Дешифрование",
    "module.enc.subtitle": "конверты",
    "module.pw.title": "Пароли и фразы",
    "module.pw.subtitle": "генератор",
    "module.vault.title": "Защищенные заметки",
    "module.vault.subtitle": "запечатано",
    "module.selftest.title": "Самопроверка",
    "module.selftest.subtitle": "диагностика",
    "module.guide.title": "Гайд",
    "module.guide.subtitle": "как использовать",

    "app.ready": "готово",
    "app.loading": "загрузка модуля...",
    "app.themeLabel": "Тема",
    "app.theme.dark": "Темная",
    "app.theme.light": "Светлая",
    "app.wipeData": "Стереть данные",
    "app.commands": "/ Команды",
    "app.actions": "Действия",
    "app.openQuickActions": "Открыть быстрые действия",
    "app.language": "Язык",
    "app.status": "Статус",
    "app.connectionIndicators": "Индикаторы подключения",
    "app.local": "локально",
    "app.offline": "офлайн",
    "app.noNet": "без сети",
    "app.tools": "Инструменты",
    "app.navigate": "Навигация",
    "app.moduleList": "Список модулей",
    "app.buildMarker": "Метка сборки",

    "app.commandPalette": "Палитра команд",
    "app.searchCommands": "Поиск команд",
    "app.commandInputPlaceholder": "Введите команду или инструмент…",
    "app.commandsList": "Команды",
    "app.noCommands": "Команды не найдены",
    "app.closeCommandPalette": "Закрыть палитру команд",

    "app.confirm": "подтвердить",
    "app.cancel": "отмена",

    "onboarding.dialog": "Тур онбординга",
    "onboarding.step": "шаг {{current}}/{{total}}",
    "onboarding.skip": "пропустить",
    "onboarding.back": "назад",
    "onboarding.next": "далее",
    "onboarding.finish": "готово",

    "feedback.panel": "Панель обратной связи",
    "feedback.title": "Обратная связь",
    "feedback.close": "закрыть",
    "feedback.stored": "Хранится только локально ({{count}} записей). Используйте экспорт для отправки.",
    "feedback.category": "Категория",
    "feedback.priority": "Приоритет",
    "feedback.message": "Сообщение",
    "feedback.context": "Контекст: :{{module}} (что сработало, что сломалось, что добавить)",
    "feedback.save": "сохранить локально",
    "feedback.export": "экспорт json",
    "feedback.clear": "очистить черновик",
    "feedback.open": "Открыть обратную связь",
    "feedback.launcher": "фидбек",
    "feedback.idea": "идея",
    "feedback.bug": "ошибка",
    "feedback.ux": "ux",
    "feedback.performance": "производительность",
    "feedback.low": "низкий",
    "feedback.medium": "средний",
    "feedback.high": "высокий",

    "error.title": "Что-то пошло не так",
    "error.body": "Интерфейс восстановился после ошибки. Повторите последнее действие.",
    "error.dismiss": "Закрыть",

    "app.command.toolsGroup": "Инструменты",
    "app.command.systemGroup": "Система",
    "app.command.hashGroup": "Действия хэша",
    "app.command.toggleTheme": "Переключить тему",
    "app.command.switchTheme": "Переключить светлую/темную тему",
    "app.command.wipe": "Стереть локальные данные",
    "app.command.clearPrefs": "Очистить настройки и сохраненный контент",
    "app.command.exportProfile": "Экспорт профиля",
    "app.command.exportProfileDesc": "Скачать настройки в JSON",
    "app.command.importProfile": "Импорт профиля",
    "app.command.importProfileDesc": "Загрузить настройки из JSON",
    "app.command.runOnboarding": "Запустить онбординг",
    "app.command.runOnboardingDesc": "Повторить быстрый тур",
    "app.command.compareDigest": "Сравнить дайджест",
    "app.command.compareDigestDesc": "Проверить с указанным хэшем",
    "app.command.clearInputs": "Очистить поля",
    "app.command.clearInputsDesc": "Сбросить текст, файл и поле проверки",
    "app.command.copyDigest": "Копировать дайджест",
    "app.command.copyDigestDesc": "Скопировать вычисленный хэш",
    "app.command.language.en": "Язык: Английский",
    "app.command.language.fa": "Язык: Персидский",
    "app.command.language.ru": "Язык: Русский",
    "app.command.languageDesc": "Сменить язык интерфейса",

    "app.onboarding.1.title": "Начните с гайда",
    "app.onboarding.1.body": "У каждого инструмента есть ограничения и безопасные значения по умолчанию. Гайд помогает избежать типичных ошибок.",
    "app.onboarding.1.action": "открыть гайд",
    "app.onboarding.2.title": "Используйте Strength Lab",
    "app.onboarding.2.body": "Модуль паролей теперь включает расширенный словарь, настройки усиления и аудит секретов.",
    "app.onboarding.2.action": "открыть :pw",
    "app.onboarding.3.title": "Очищайте перед отправкой",
    "app.onboarding.3.body": "Используйте санитайзер логов для policy packs, diff-предпросмотра и bundle-экспорта при внешней передаче логов.",
    "app.onboarding.3.action": "открыть :sanitize",
    "app.onboarding.4.title": "Управляйте через команды",
    "app.onboarding.4.body": "Нажмите / или Cmd/Ctrl+K для быстрой навигации, импорта/экспорта профиля и системных действий.",
    "app.onboarding.4.action": "открыть команды",
    "app.onboarding.5.title": "Сохраняйте фидбек локально",
    "app.onboarding.5.body": "Используйте кнопку фидбека снизу слева, чтобы хранить идеи и баги локально и экспортировать в JSON.",

    "runtime.theme": "тема :: {{value}}",
    "runtime.module": "модуль :: {{value}}",
    "runtime.command": "команда :: {{value}}",
    "runtime.error": "ошибка :: {{value}}",
    "runtime.languageChanged": "язык изменен: {{value}}",
    "runtime.localDataWiped": "локальные данные стерты",
    "runtime.dataWiped": "данные стерты",
    "runtime.onboarding": "онбординг",
    "runtime.onboardingComplete": "онбординг завершен",
    "runtime.onboardingSkipped": "онбординг пропущен",
    "runtime.profileExported": "профиль экспортирован",
    "runtime.profileImported": "профиль импортирован",
    "runtime.importFailed": "импорт не удался",
    "runtime.runtimeError": "ошибка выполнения: {{value}}",
    "runtime.unhandledPromise": "необработанное promise",

    "runtime.dark": "темная",
    "runtime.light": "светлая",

    "guide.link": "? гайд",
  },
};

const runtimeExactKeys: Record<string, string> = {
  ready: "app.ready",
  guide: "module.guide.title",
  "data wiped": "runtime.dataWiped",
  "profile exported": "runtime.profileExported",
  "profile imported": "runtime.profileImported",
  "onboarding": "runtime.onboarding",
  "onboarding complete": "runtime.onboardingComplete",
  "onboarding skipped": "runtime.onboardingSkipped",
  "local data wiped": "runtime.localDataWiped",
  "unhandled promise rejection": "runtime.unhandledPromise",
};

const I18nContext = createContext<I18nContextValue | null>(null);

function interpolate(template: string, values?: TranslateValues): string {
  if (!values) return template;
  return template.replace(/\{\{(.*?)\}\}/g, (_, rawKey: string) => {
    const key = rawKey.trim();
    const value = values[key];
    return value == null ? "" : String(value);
  });
}

function detectInitialLocale(): AppLocale {
  try {
    const persisted = localStorage.getItem(STORAGE_KEY);
    if (persisted === "en" || persisted === "fa" || persisted === "ru") {
      return persisted;
    }
  } catch {
    // Ignore storage read failures and fall back to browser language.
  }
  const languages = [navigator.language, ...(navigator.languages ?? [])].map((value) => value.toLowerCase());
  if (languages.some((value) => value.startsWith("fa") || value.startsWith("prs"))) return "fa";
  if (languages.some((value) => value.startsWith("ru"))) return "ru";
  return FALLBACK_LOCALE;
}

function translateRuntimeWithKey(locale: AppLocale, key: string, values?: TranslateValues): string {
  const template = messages[locale][key] ?? messages.en[key] ?? key;
  return interpolate(template, values);
}

function translateRuntimeMessage(locale: AppLocale, message: string): string {
  if (locale === "en") return message;
  const trimmed = message.trim();
  const exactKey = runtimeExactKeys[trimmed];
  if (exactKey) {
    return translateRuntimeWithKey(locale, exactKey);
  }

  let match = trimmed.match(/^theme ::\s*(.+)$/i);
  if (match) {
    const themeValue = match[1].toLowerCase() === "dark" ? "runtime.dark" : "runtime.light";
    return translateRuntimeWithKey(locale, "runtime.theme", { value: translateRuntimeWithKey(locale, themeValue) });
  }

  match = trimmed.match(/^module ::\s*(.+)$/i);
  if (match) {
    const moduleKey = match[1].trim();
    const moduleLabel = messages[locale][`module.${moduleKey}.title`] ?? moduleKey;
    return translateRuntimeWithKey(locale, "runtime.module", { value: moduleLabel });
  }

  match = trimmed.match(/^command ::\s*(.+)$/i);
  if (match) {
    return translateRuntimeWithKey(locale, "runtime.command", { value: match[1].trim() });
  }

  match = trimmed.match(/^error ::\s*(.+)$/i);
  if (match) {
    return translateRuntimeWithKey(locale, "runtime.error", { value: match[1].trim() });
  }

  match = trimmed.match(/^runtime error:\s*(.+)$/i);
  if (match) {
    return translateRuntimeWithKey(locale, "runtime.runtimeError", { value: match[1].trim() });
  }

  match = trimmed.match(/^language changed:\s*(.+)$/i);
  if (match) {
    const raw = match[1].trim();
    const normalized = raw.toLowerCase();
    const value =
      normalized === "en" || normalized === "english"
        ? translateRuntimeWithKey(locale, "locale.en")
        : normalized === "fa" || normalized === "persian" || normalized === "farsi" || normalized === "فارسی"
          ? translateRuntimeWithKey(locale, "locale.fa")
          : normalized === "ru" || normalized === "russian" || normalized === "русский"
            ? translateRuntimeWithKey(locale, "locale.ru")
            : raw;
    return translateRuntimeWithKey(locale, "runtime.languageChanged", { value });
  }

  if (/^import failed/i.test(trimmed)) {
    return translateRuntimeWithKey(locale, "runtime.importFailed");
  }

  return message;
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<AppLocale>(detectInitialLocale);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, locale);
    } catch {
      // Ignore storage write failures.
    }
    const meta = localeMeta[locale];
    document.documentElement.lang = meta.bcp47;
    document.documentElement.dir = meta.direction;
    document.body.setAttribute("data-locale", locale);
    document.body.setAttribute("dir", meta.direction);
  }, [locale]);

  const setLocale = useCallback((next: AppLocale) => {
    setLocaleState(next);
  }, []);

  const t = useCallback(
    (key: string, values?: TranslateValues) => {
      const template = messages[locale][key] ?? messages.en[key] ?? key;
      return interpolate(template, values);
    },
    [locale],
  );

  const tr = useCallback(
    (message: string) => {
      return translateRuntimeMessage(locale, message);
    },
    [locale],
  );

  const formatNumber = useCallback(
    (value: number) => {
      return new Intl.NumberFormat(localeMeta[locale].bcp47).format(value);
    },
    [locale],
  );

  const formatDateTime = useCallback(
    (value: number | string | Date) => {
      const date = value instanceof Date ? value : new Date(value);
      return new Intl.DateTimeFormat(localeMeta[locale].bcp47, {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(date);
    },
    [locale],
  );

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      availableLocales: ["en", "fa", "ru"],
      localeMeta,
      setLocale,
      t,
      tr,
      formatNumber,
      formatDateTime,
    }),
    [formatDateTime, formatNumber, locale, setLocale, t, tr],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error("useI18n must be used within I18nProvider");
  }
  return context;
}
