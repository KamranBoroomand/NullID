export const PASSWORD_SYMBOLS = "!@#$%^&*()-_=+[]{}<>?/|~";
const ambiguousChars = new Set(["l", "1", "I", "O", "0", "o"]);
const uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
const digitChars = "0123456789";
const log10Two = Math.log10(2);
const weakFragments = [
    "password",
    "passw0rd",
    "admin",
    "qwerty",
    "letmein",
    "welcome",
    "iloveyou",
    "dragon",
    "baseball",
    "football",
    "monkey",
    "abc123",
    "123456",
    "12345678",
];
const lexicalStarts = [
    "al",
    "an",
    "ar",
    "ba",
    "be",
    "bi",
    "ca",
    "ce",
    "da",
    "de",
    "di",
    "el",
    "fa",
    "fi",
    "ga",
    "ha",
    "ka",
    "la",
    "ma",
    "na",
    "ol",
    "pa",
    "pe",
    "ra",
    "re",
    "sa",
    "se",
    "ta",
    "te",
    "ul",
    "va",
    "za",
];
const lexicalRoots = [
    "bar",
    "bel",
    "cor",
    "dan",
    "dor",
    "fal",
    "gan",
    "hel",
    "jor",
    "kel",
    "lor",
    "mar",
    "nal",
    "nor",
    "pra",
    "quil",
    "ran",
    "sel",
    "tor",
    "ur",
    "val",
    "wen",
    "xer",
    "yor",
    "zen",
    "nix",
    "glen",
    "hart",
    "vex",
    "morn",
    "sil",
    "tren",
];
const lexicalVowels = [
    "a",
    "e",
    "i",
    "o",
    "u",
    "ae",
    "ai",
    "ea",
    "eo",
    "ia",
    "io",
    "oa",
    "oi",
    "ou",
    "ua",
    "ue",
    "y",
    "an",
    "en",
    "in",
    "on",
    "un",
    "ar",
    "er",
    "ir",
    "or",
    "ur",
    "ath",
    "eth",
    "ith",
    "oth",
    "ume",
];
const lexicalConsonants = [
    "b",
    "br",
    "c",
    "cr",
    "d",
    "dr",
    "f",
    "g",
    "gr",
    "k",
    "l",
    "m",
    "n",
    "p",
    "pr",
    "q",
    "r",
    "s",
    "st",
    "t",
    "tr",
    "v",
    "w",
    "x",
    "z",
    "ld",
    "nd",
    "rn",
    "th",
    "sh",
    "sk",
    "vr",
];
const lexicalEndings = ["a", "e", "i", "o", "u", "an", "en", "er", "ia", "ion", "is", "or", "os", "um", "yx", "zen"];
const dictionarySegments = {
    balanced: [lexicalStarts, lexicalRoots, lexicalVowels],
    extended: [lexicalStarts, lexicalRoots, lexicalVowels, lexicalConsonants],
    maximal: [lexicalStarts, lexicalRoots, lexicalVowels, lexicalConsonants, lexicalEndings],
};
const sequentialSources = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiopasdfghjklzxcvbnm",
];
export function generatePassword(settings) {
    const pools = buildPools(settings);
    const selectedPools = pools.length > 0 ? pools : [lowercaseChars, uppercaseChars];
    const alphabet = selectedPools.join("");
    const minUnique = clamp(settings.minUniqueChars, 1, settings.length);
    for (let attempt = 0; attempt < 500; attempt += 1) {
        const characters = [];
        if (settings.enforceMix) {
            selectedPools.forEach((pool) => {
                if (pool.length > 0) {
                    characters.push(pool[randomIndex(pool.length)]);
                }
            });
        }
        while (characters.length < settings.length) {
            characters.push(alphabet[randomIndex(alphabet.length)]);
        }
        const candidate = shuffle(characters).join("");
        if (validatePasswordCandidate(candidate, selectedPools, settings.enforceMix) &&
            hasMinUniqueChars(candidate, minUnique) &&
            (!settings.blockRepeats || !hasRepeatRun(candidate, 3)) &&
            (!settings.blockSequential || !hasSequentialRun(candidate, 3))) {
            return candidate;
        }
    }
    const fallback = shuffle(Array.from({ length: settings.length }, () => alphabet[randomIndex(alphabet.length)])).join("");
    return fallback;
}
export function estimatePasswordEntropy(settings) {
    const pools = buildPools(settings);
    const alphabet = (pools.length > 0 ? pools : [lowercaseChars, uppercaseChars]).join("");
    return Math.round(settings.length * Math.log2(Math.max(1, alphabet.length)));
}
export function generatePassphrase(settings) {
    const dictionary = getPassphraseDictionaryStats(settings.dictionaryProfile);
    const separator = settings.separator === "space" ? " " : settings.separator;
    const words = [];
    const usedWords = settings.ensureUniqueWords ? new Set() : undefined;
    for (let i = 0; i < settings.words; i += 1) {
        const baseWord = pickPassphraseWord(settings.dictionaryProfile, dictionary.size, usedWords);
        if (usedWords)
            usedWords.add(baseWord);
        const word = applyCaseStyle(baseWord, settings.caseStyle);
        words.push(word);
    }
    let phrase = words.join(separator);
    if (settings.numberMode === "append-2") {
        phrase = `${phrase}${separator}${randomDigits(2)}`;
    }
    else if (settings.numberMode === "append-4") {
        phrase = `${phrase}${separator}${randomDigits(4)}`;
    }
    if (settings.symbolMode === "append") {
        phrase = `${phrase}${separator}${PASSWORD_SYMBOLS[randomIndex(PASSWORD_SYMBOLS.length)]}`;
    }
    else if (settings.symbolMode === "wrap") {
        const left = PASSWORD_SYMBOLS[randomIndex(PASSWORD_SYMBOLS.length)];
        const right = PASSWORD_SYMBOLS[randomIndex(PASSWORD_SYMBOLS.length)];
        phrase = `${left}${phrase}${right}`;
    }
    return phrase;
}
export function estimatePassphraseEntropy(settings) {
    const { size } = getPassphraseDictionaryStats(settings.dictionaryProfile);
    let entropy = 0;
    if (settings.ensureUniqueWords) {
        for (let i = 0; i < settings.words; i += 1) {
            entropy += Math.log2(Math.max(1, size - i));
        }
    }
    else {
        entropy += settings.words * Math.log2(size);
    }
    if (settings.caseStyle === "random") {
        entropy += settings.words * Math.log2(3);
    }
    if (settings.numberMode === "append-2") {
        entropy += Math.log2(100);
    }
    else if (settings.numberMode === "append-4") {
        entropy += Math.log2(10_000);
    }
    if (settings.symbolMode === "append") {
        entropy += Math.log2(PASSWORD_SYMBOLS.length);
    }
    else if (settings.symbolMode === "wrap") {
        entropy += Math.log2(PASSWORD_SYMBOLS.length) * 2;
    }
    return Math.round(entropy);
}
export function analyzeSecret(secret, theoreticalEntropyBits) {
    const value = secret.trim();
    if (!value) {
        return {
            grade: "critical",
            entropyBits: 0,
            effectiveEntropyBits: 0,
            warnings: ["empty secret"],
            strengths: [],
            crackTime: { online: "<1 second", offline: "<1 second" },
        };
    }
    const warnings = [];
    const strengths = [];
    const length = value.length;
    const uniqueRatio = new Set(value).size / length;
    const lower = value.toLowerCase();
    if (length < 12)
        warnings.push("length below 12 characters");
    if (length >= 16)
        strengths.push("length 16+");
    if (uniqueRatio < 0.5)
        warnings.push("low character uniqueness");
    if (uniqueRatio > 0.75)
        strengths.push("high unique character ratio");
    const classes = countCharacterClasses(value);
    if (classes <= 1)
        warnings.push("single character class detected");
    if (classes >= 3)
        strengths.push("multiple character classes");
    const repeatRuns = countRepeatRuns(value, 3);
    if (repeatRuns > 0)
        warnings.push("contains repeated character runs");
    const sequentialRuns = countSequentialRuns(value, 3);
    if (sequentialRuns > 0)
        warnings.push("contains keyboard/alphabet/number sequences");
    const weakMatches = weakFragments.filter((fragment) => lower.includes(fragment));
    if (weakMatches.length > 0)
        warnings.push("contains common password fragments");
    if (/\b(19|20)\d{2}\b/.test(value))
        warnings.push("contains a likely year");
    const entropyBits = theoreticalEntropyBits ?? estimateObservedEntropy(value);
    let penalty = 0;
    if (length < 8)
        penalty += 28;
    else if (length < 12)
        penalty += 18;
    else if (length < 16)
        penalty += 8;
    if (classes <= 1)
        penalty += 20;
    else if (classes === 2)
        penalty += 8;
    if (uniqueRatio < 0.5)
        penalty += 10;
    penalty += repeatRuns * 6;
    penalty += sequentialRuns * 7;
    penalty += weakMatches.length * 14;
    if (/^\d+$/.test(value))
        penalty += 18;
    const effective = Math.max(0, Math.round(entropyBits - penalty));
    const grade = mapEntropyToGrade(effective);
    return {
        grade,
        entropyBits: Math.round(entropyBits),
        effectiveEntropyBits: effective,
        warnings,
        strengths,
        crackTime: {
            online: estimateCrackTime(effective, 100),
            offline: estimateCrackTime(effective, 10_000_000_000),
        },
    };
}
export function gradeLabel(grade) {
    if (grade === "critical")
        return "critical";
    if (grade === "weak")
        return "weak";
    if (grade === "fair")
        return "fair";
    if (grade === "strong")
        return "strong";
    return "elite";
}
export function getPassphraseDictionaryStats(profile) {
    const segments = dictionarySegments[profile];
    const size = segments.reduce((total, part) => total * part.length, 1);
    const label = profile === "balanced"
        ? "balanced (32,768 words)"
        : profile === "extended"
            ? "extended (1,048,576 words)"
            : "maximal (16,777,216 words)";
    return {
        profile,
        label,
        size,
        bitsPerWord: Math.log2(size),
    };
}
export function generatePasswordBatch(settings, count) {
    const rows = [];
    for (let i = 0; i < count; i += 1) {
        const value = generatePassword(settings);
        const entropyBits = estimatePasswordEntropy(settings);
        rows.push({ value, entropyBits, assessment: analyzeSecret(value, entropyBits) });
    }
    return rows;
}
export function generatePassphraseBatch(settings, count) {
    const rows = [];
    for (let i = 0; i < count; i += 1) {
        const value = generatePassphrase(settings);
        const entropyBits = estimatePassphraseEntropy(settings);
        rows.push({ value, entropyBits, assessment: analyzeSecret(value, entropyBits) });
    }
    return rows;
}
function buildPools(settings) {
    const pools = [];
    if (settings.upper)
        pools.push(uppercaseChars);
    if (settings.lower)
        pools.push(lowercaseChars);
    if (settings.digits)
        pools.push(digitChars);
    if (settings.symbols)
        pools.push(PASSWORD_SYMBOLS);
    if (!settings.avoidAmbiguity)
        return pools;
    return pools
        .map((pool) => Array.from(pool).filter((char) => !ambiguousChars.has(char)).join(""))
        .filter((pool) => pool.length > 0);
}
function validatePasswordCandidate(candidate, pools, enforceMix) {
    if (!enforceMix)
        return true;
    return pools.every((pool) => Array.from(candidate).some((char) => pool.includes(char)));
}
function hasMinUniqueChars(candidate, minUniqueChars) {
    return new Set(candidate).size >= minUniqueChars;
}
function hasRepeatRun(value, minRun) {
    return countRepeatRuns(value, minRun) > 0;
}
function countRepeatRuns(value, minRun) {
    let runs = 0;
    let streak = 1;
    for (let i = 1; i < value.length; i += 1) {
        if (value[i] === value[i - 1]) {
            streak += 1;
            if (streak === minRun) {
                runs += 1;
            }
        }
        else {
            streak = 1;
        }
    }
    return runs;
}
function hasSequentialRun(value, minRun) {
    return countSequentialRuns(value, minRun) > 0;
}
function countSequentialRuns(value, minRun) {
    const lower = value.toLowerCase();
    let count = 0;
    sequentialSources.forEach((source) => {
        for (let i = 0; i <= source.length - minRun; i += 1) {
            const fragment = source.slice(i, i + minRun);
            if (lower.includes(fragment) || lower.includes(fragment.split("").reverse().join(""))) {
                count += 1;
            }
        }
    });
    return count;
}
function applyCaseStyle(word, style) {
    if (style === "lower")
        return word;
    if (style === "upper")
        return word.toUpperCase();
    if (style === "title")
        return `${word[0].toUpperCase()}${word.slice(1)}`;
    const mode = randomIndex(3);
    if (mode === 0)
        return word.toUpperCase();
    if (mode === 1)
        return `${word[0].toUpperCase()}${word.slice(1)}`;
    return word;
}
function dictionaryWord(profile, index) {
    const segments = dictionarySegments[profile];
    let cursor = index;
    const parts = segments.map((segment) => {
        const pick = cursor % segment.length;
        cursor = Math.floor(cursor / segment.length);
        return segment[pick];
    });
    return parts.join("");
}
function pickPassphraseWord(profile, dictionarySize, usedWords) {
    let sampledIndex = randomIndex(dictionarySize);
    let candidate = dictionaryWord(profile, sampledIndex);
    if (!usedWords || !usedWords.has(candidate))
        return candidate;
    for (let attempts = 0; attempts < 128; attempts += 1) {
        sampledIndex = randomIndex(dictionarySize);
        candidate = dictionaryWord(profile, sampledIndex);
        if (!usedWords.has(candidate))
            return candidate;
    }
    for (let offset = 1; offset < dictionarySize; offset += 1) {
        const index = (sampledIndex + offset) % dictionarySize;
        candidate = dictionaryWord(profile, index);
        if (!usedWords.has(candidate))
            return candidate;
    }
    return candidate;
}
function randomDigits(length) {
    let digits = "";
    for (let i = 0; i < length; i += 1) {
        digits += digitChars[randomIndex(digitChars.length)];
    }
    return digits;
}
function estimateObservedEntropy(value) {
    let alphabet = 0;
    if (/[a-z]/.test(value))
        alphabet += 26;
    if (/[A-Z]/.test(value))
        alphabet += 26;
    if (/[0-9]/.test(value))
        alphabet += 10;
    if (/[^A-Za-z0-9\s]/.test(value))
        alphabet += PASSWORD_SYMBOLS.length;
    if (/\s/.test(value))
        alphabet += 1;
    return Math.round(value.length * Math.log2(Math.max(alphabet, 1)));
}
function countCharacterClasses(value) {
    let classes = 0;
    if (/[a-z]/.test(value))
        classes += 1;
    if (/[A-Z]/.test(value))
        classes += 1;
    if (/[0-9]/.test(value))
        classes += 1;
    if (/[^A-Za-z0-9\s]/.test(value))
        classes += 1;
    return classes;
}
function mapEntropyToGrade(bits) {
    if (bits < 40)
        return "critical";
    if (bits < 60)
        return "weak";
    if (bits < 80)
        return "fair";
    if (bits < 110)
        return "strong";
    return "elite";
}
function estimateCrackTime(bits, guessesPerSecond) {
    if (bits <= 0)
        return "<1 second";
    const log10Seconds = bits * log10Two - Math.log10(guessesPerSecond);
    return formatLogDuration(log10Seconds);
}
function formatLogDuration(log10Seconds) {
    if (!Number.isFinite(log10Seconds) || log10Seconds > 30)
        return "astronomical";
    if (log10Seconds < 0)
        return "<1 second";
    if (log10Seconds < 12) {
        const seconds = 10 ** log10Seconds;
        return formatDuration(seconds);
    }
    const log10Years = log10Seconds - Math.log10(31_557_600);
    if (log10Years > 8) {
        return `~10^${log10Years.toFixed(1)} years`;
    }
    const years = 10 ** log10Years;
    return `~${Math.round(years).toLocaleString()} years`;
}
function formatDuration(seconds) {
    if (seconds < 1)
        return "<1 second";
    if (seconds < 60)
        return `${Math.ceil(seconds)} seconds`;
    const minutes = seconds / 60;
    if (minutes < 60)
        return `${Math.ceil(minutes)} minutes`;
    const hours = minutes / 60;
    if (hours < 24)
        return `${Math.ceil(hours)} hours`;
    const days = hours / 24;
    if (days < 365)
        return `${Math.ceil(days)} days`;
    const years = days / 365;
    return `${Math.round(years).toLocaleString()} years`;
}
function randomIndex(max) {
    if (max <= 0)
        throw new Error("max must be positive");
    const maxUint = 0xffffffff;
    const limit = Math.floor((maxUint + 1) / max) * max;
    let value = 0;
    do {
        value = crypto.getRandomValues(new Uint32Array(1))[0];
    } while (value >= limit);
    return value % max;
}
function shuffle(input) {
    const arr = [...input];
    for (let i = arr.length - 1; i > 0; i -= 1) {
        const j = randomIndex(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}
function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}
