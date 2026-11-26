export function publicKeyHex(privatePem: string): string;
export function buildManifest(dir: string, version: string, daysValid?: number, now?: number): unknown;
export function signManifest(privatePem: string, manifestBytes: Buffer): string;
