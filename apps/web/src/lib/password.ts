/**
 * Password and passphrase generation in the browser, with crypto.getRandomValues
 * and rejection sampling so every character or word is equally likely.
 * Nothing is sent anywhere.
 */
const LOWER = "abcdefghijkmnopqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const SYMBOLS = "!#$%&*+-=?@^_~";

// Short, common, easy-to-type words (no look-alikes, no offensive words).
export const WORDS = (
  "amber anchor apple arrow aspen atlas autumn badge bamboo banner barley basin beacon berry birch blanket blossom bridge " +
  "bright brook butter cabin cactus camel candle canyon carbon cargo castle cedar chalk cherry cider cinema citrus clever " +
  "cliff cloud clover cobalt comet copper coral cotton cradle crane crystal cumin daisy dawn delta desert dolphin dragon " +
  "drift eagle earth echo ember engine fabric falcon feather fern fiber field flame flint forest fossil fountain fox " +
  "galaxy garden garnet gentle ginger glacier globe golden granite grape gravel harbor harvest hazel helmet hollow honey " +
  "horizon husky indigo island ivory jacket jasmine jungle kettle kiwi lagoon lantern lemon lilac linen lotus lunar " +
  "magnet mango maple marble meadow melon meteor mint mirror mosaic mountain nectar needle noble oasis ocean olive " +
  "orbit orchid otter oyster paddle palm panda paper parrot pebble pepper pine planet plum polar pony prairie pulse " +
  "quartz quiet rabbit radar raven reef ribbon river robin rocket saffron salmon sand sapphire satin scarlet shadow " +
  "silver sky slate snow solar sparrow spice spring spruce stone summit sunset swift tango thistle thunder tiger timber " +
  "topaz tulip tundra turtle valley velvet violet voyage walnut willow window winter yarrow zebra zephyr"
).split(" ");

function randomIndex(max: number): number {
  const limit = Math.floor(0x100000000 / max) * max;
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    if (buffer[0]! < limit) return buffer[0]! % max;
  }
}

export interface PasswordOptions {
  length: number;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
}

export function generatePassword(options: PasswordOptions): string {
  const sets = [LOWER, options.upper && UPPER, options.digits && DIGITS, options.symbols && SYMBOLS].filter(Boolean) as string[];
  const all = sets.join("");
  for (;;) {
    const chars = Array.from({ length: options.length }, () => all[randomIndex(all.length)]!);
    // Make sure every chosen character type appears at least once.
    if (sets.every((set) => chars.some((char) => set.includes(char)))) return chars.join("");
  }
}

export function generatePassphrase(words: number, separator = "-"): string {
  return Array.from({ length: words }, () => WORDS[randomIndex(WORDS.length)]!).join(separator);
}

/** Entropy in bits of a generated secret, from how it was generated. */
export function passwordBits(options: PasswordOptions): number {
  const size = LOWER.length + (options.upper ? UPPER.length : 0) + (options.digits ? DIGITS.length : 0) + (options.symbols ? SYMBOLS.length : 0);
  return Math.floor(options.length * Math.log2(size));
}

export function passphraseBits(words: number): number {
  return Math.floor(words * Math.log2(WORDS.length));
}
