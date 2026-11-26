import type { KeyObject } from "node:crypto";

export function encryptedPem(privateKey: KeyObject, passphrase: string): string;
export function loadPrivateKey(pem: string, passphrase: string): KeyObject;
export function publicKeyHex(privateKey: KeyObject): string;
export function buildManifest(dir: string, version: string, daysValid?: number, now?: number): unknown;
export function signManifest(privateKey: KeyObject, manifestBytes: Buffer): string;
export function verifyFolder(publicHex: string, dir: string): { ok: true; version: string; expires: string; files: number } | { ok: false; problem: string };
