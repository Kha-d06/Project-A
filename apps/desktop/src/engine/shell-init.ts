/**
 * Shell integration for terminal protection (bash and zsh), and setting it up.
 *
 * bash: Enter is bound (bind -x) to a check of the whole typed line, in the shell
 *   itself, before anything runs; a declined line is cleared, so nothing runs. (A
 *   DEBUG trap cannot do this reliably: bash runs it separately in each part of a
 *   pipeline.) The checker only starts when a quick pattern matches.
 * zsh: the Enter key's widget (accept-line) is wrapped; a declined command is kept
 *   in history but never runs.
 * Both scan files downloaded with curl or wget after the command finishes.
 */
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { SHELL_PREFILTER } from "./terminal";

const quote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`;

export function bashInit(bin: string): string {
  // Enter runs __qalaa_check_line first (bind -x sees the whole typed line, in this shell,
  // before anything runs); a declined line is cleared so accept-line runs nothing.
  return `# Qalaa terminal protection for bash. Remove with: qalaa terminal off
[[ $- == *i* ]] || return 0 2>/dev/null
__qalaa_bin=${quote(bin)}
__qalaa_pattern=${quote(SHELL_PREFILTER)}
__qalaa_after_line=""
__qalaa_check_line() {
  local line="$READLINE_LINE"
  [[ -z "\${line//[[:space:]]/}" ]] && return 0
  if [[ "$line" =~ $__qalaa_pattern || "$line" == *[^[:print:][:space:]]* ]]; then
    printf '\\n' >/dev/tty
    if ! "$__qalaa_bin" guard -- "$line" </dev/tty; then
      builtin history -s -- "$line"
      READLINE_LINE=""
      READLINE_POINT=0
      return 0
    fi
  fi
  [[ "$line" =~ (curl|wget) ]] && __qalaa_after_line="$line"
  return 0
}
__qalaa_after() {
  if [[ -n "$__qalaa_after_line" ]]; then
    "$__qalaa_bin" after -- "$__qalaa_after_line"
    __qalaa_after_line=""
  fi
}
for __qalaa_map in emacs vi-insert; do
  bind -m "$__qalaa_map" -x '"\\C-x\\C-q": __qalaa_check_line' 2>/dev/null
  bind -m "$__qalaa_map" '"\\C-x\\C-a": accept-line' 2>/dev/null
  bind -m "$__qalaa_map" '"\\C-m": "\\C-x\\C-q\\C-x\\C-a"' 2>/dev/null
  bind -m "$__qalaa_map" '"\\C-j": "\\C-x\\C-q\\C-x\\C-a"' 2>/dev/null
done
unset __qalaa_map
[[ "$PROMPT_COMMAND" == *__qalaa_after* ]] || PROMPT_COMMAND="__qalaa_after\${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
`;
}

export function zshInit(bin: string): string {
  return `# Qalaa terminal protection for zsh. Remove with: qalaa terminal off
[[ -o interactive ]] || return 0
typeset -g __qalaa_bin=${quote(bin)}
typeset -g __qalaa_pattern=${quote(SHELL_PREFILTER)}
typeset -g __qalaa_after_line=""
__qalaa_accept_line() {
  if [[ -n "$BUFFER" && ( "$BUFFER" =~ $__qalaa_pattern || "$BUFFER" == *[^[:print:][:space:]]* ) ]]; then
    zle -I
    if ! "$__qalaa_bin" guard -- "$BUFFER" </dev/tty; then
      print -s -- "$BUFFER"
      BUFFER=""
      zle reset-prompt
      return 0
    fi
  fi
  [[ "$BUFFER" =~ (curl|wget) ]] && __qalaa_after_line="$BUFFER"
  zle .accept-line
}
zle -N accept-line __qalaa_accept_line
__qalaa_after() {
  if [[ -n "$__qalaa_after_line" ]]; then
    "$__qalaa_bin" after -- "$__qalaa_after_line"
    __qalaa_after_line=""
  fi
}
autoload -Uz add-zsh-hook
add-zsh-hook precmd __qalaa_after
`;
}

// --- Setting it up --------------------------------------------------------------------

const BEGIN = "# >>> Qalaa terminal protection >>>";
const END = "# <<< Qalaa terminal protection <<<";

/** The block added to ~/.bashrc or ~/.zshrc (pure). */
export function rcBlock(shell: "bash" | "zsh", initFile: string): string {
  return `${BEGIN}\n[ -r ${quote(initFile)} ] && . ${quote(initFile)}\n${END}\n`;
}

/** Adds or removes the block, leaving everything else in the file as it was (pure). */
export function withRcBlock(text: string, block: string | null): string {
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  let rest = text;
  if (start !== -1 && end > start) rest = text.slice(0, start) + text.slice(end + END.length).replace(/^\n/, "");
  if (!block) return rest;
  return `${rest}${rest && !rest.endsWith("\n") ? "\n" : ""}${block}`;
}

export interface TerminalSetup {
  /** The `qalaa` command. */
  command: string;
  shells: { shell: "bash" | "zsh"; rc: string; enabled: boolean }[];
}

export interface TerminalPaths {
  home: string;
  /** Where the wrapper and init scripts go (~/.local/share/qalaa). */
  share: string;
  /** Where the `qalaa` command goes (~/.local/bin). */
  bin: string;
}

export function terminalPaths(home = homedir()): TerminalPaths {
  return { home, share: join(home, ".local", "share", "qalaa"), bin: join(home, ".local", "bin") };
}

/**
 * The `qalaa` launcher: Qalaa Desktop's own runtime in Node mode running the bundled
 * CLI. For an AppImage the inner path changes on every start, so it is found from the
 * runtime's location at run time.
 */
export function launcher(runtime: string, cliScript: string | null, dataDir?: string): string {
  const env = `ELECTRON_RUN_AS_NODE=1${dataDir ? ` QALAA_DATA_DIR=${quote(dataDir)}` : ""}`;
  const script = cliScript
    ? `exec env ${env} ${quote(runtime)} ${quote(cliScript)} "$@"`
    : `exec env ${env} ${quote(runtime)} -e 'require(require("path").join(require("path").dirname(process.execPath),"resources","app.asar.unpacked","dist","cli.js"))' qalaa "$@"`;
  return `#!/bin/sh\n# Qalaa terminal protection (installed by Qalaa Desktop)\n${script}\n`;
}

async function readText(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
}

export async function terminalStatus(paths = terminalPaths()): Promise<TerminalSetup> {
  const command = join(paths.bin, "qalaa");
  const shells: TerminalSetup["shells"] = [];
  for (const shell of ["bash", "zsh"] as const) {
    const rc = join(paths.home, shell === "bash" ? ".bashrc" : ".zshrc");
    const text = await readText(rc);
    shells.push({ shell, rc, enabled: Boolean(text?.includes(BEGIN)) });
  }
  return { command, shells };
}

/** Installs the command and hooks bash (always) and zsh (when ~/.zshrc exists or zsh is the login shell). */
export async function enableTerminal(runtime: string, cliScript: string | null, paths = terminalPaths(), loginShell = process.env.SHELL ?? "", dataDir?: string): Promise<{ changed: string[]; setup: TerminalSetup }> {
  await mkdir(paths.share, { recursive: true, mode: 0o700 });
  await mkdir(paths.bin, { recursive: true });
  const command = join(paths.bin, "qalaa");
  await writeFile(command, launcher(runtime, cliScript, dataDir));
  await chmod(command, 0o755);
  await writeFile(join(paths.share, "init.bash"), bashInit(command));
  await writeFile(join(paths.share, "init.zsh"), zshInit(command));
  const changed: string[] = [];
  for (const shell of ["bash", "zsh"] as const) {
    const rc = join(paths.home, shell === "bash" ? ".bashrc" : ".zshrc");
    const text = await readText(rc);
    if (shell === "zsh" && text === null && !loginShell.endsWith("zsh")) continue;
    const next = withRcBlock(text ?? "", rcBlock(shell, join(paths.share, `init.${shell}`)));
    if (next !== text) {
      await writeFile(rc, next);
      changed.push(rc);
    }
  }
  return { changed, setup: await terminalStatus(paths) };
}

export async function disableTerminal(paths = terminalPaths()): Promise<{ changed: string[]; setup: TerminalSetup }> {
  const changed: string[] = [];
  for (const shell of ["bash", "zsh"] as const) {
    const rc = join(paths.home, shell === "bash" ? ".bashrc" : ".zshrc");
    const text = await readText(rc);
    if (text === null || !text.includes(BEGIN)) continue;
    await writeFile(rc, withRcBlock(text, null));
    changed.push(rc);
  }
  await rm(join(paths.share, "init.bash"), { force: true });
  await rm(join(paths.share, "init.zsh"), { force: true });
  await rm(join(paths.bin, "qalaa"), { force: true });
  return { changed, setup: await terminalStatus(paths) };
}
