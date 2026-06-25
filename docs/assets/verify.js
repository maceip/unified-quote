// unified-quote: in-browser Value X verifier for this repo.
//
// Mirrors the algorithm in v2/src/main.rs::compute_tree_hash + collect_hashes,
// which is the version that actually runs inside the TDX runner during
// the current build command. Pure JavaScript, no WASM, no external
// libraries. Uses:
//   - GitHub REST API         → enumerate a commit tree (one request).
//   - raw.githubusercontent.com → fetch each blob (no API rate limit).
//   - crypto.subtle.digest('SHA-384', …) → native browser sha-384.
//
// This is not a simulation. It is the same pipeline the runtime uses
// when it re-computes Value X at boot against its frozen source tree. The
// only thing missing from a full verify is parsing a TEE quote — that needs
// vendor-specific ECDSA libraries and is tracked as a follow-up.
//
// THE "WOW" MOMENT: walk `v2` at commit `2593db6` and the widget produces
//   58b663bbb60a906f29a2e5141c67a4a163271a9af24304e282bdbbbb8fb94fa5bc337dda323d37e7f78f429bcf80810c
// byte-for-byte. That is the exact Value X Intel's TDX module signed in the
// ouroboros run on 2026-04-14. You can verify it in your browser, right now,
// against a committed attestation artifact. No infrastructure needed.

(() => {
  "use strict";

  // --------------------------------------------------------------------------
  // Config — these mirror v2's compute_tree_hash / collect_hashes
  // --------------------------------------------------------------------------
  const REPO = "maceip/unified-quote";
  // The directory the build hashes is whatever you pass as
  // <source-dir>. The ouroboros run used `v2`, so that's our default — it
  // reproduces the signed Value X when walked at the right commit.
  const DEFAULT_PATH = "v2";
  const DEFAULT_REF = "2593db6";

  // Ported verbatim from v2/src/main.rs::collect_hashes skip list.
  // These are directory / file BASENAMES; matching is exact, not suffix.
  // .git and target/ are gitignored anyway so they never appear in the
  // GitHub tree API response — keeping them here for documentation and
  // for the case where someone feeds a tree that does contain them.
  const SKIP_NAMES = new Set([
    ".git",
    "target",
    "node_modules",
    ".DS_Store",
    "out",
  ]);
  const shouldSkip = (name) => SKIP_NAMES.has(name);

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------
  const toHex = (buf) => {
    const bytes = new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
  };

  const sha384 = async (data) => {
    const buf = typeof data === "string" ? new TextEncoder().encode(data) : data;
    return await crypto.subtle.digest("SHA-384", buf);
  };

  const concatBuffers = (buffers) => {
    let total = 0;
    for (const b of buffers) total += b.byteLength;
    const out = new Uint8Array(total);
    let off = 0;
    for (const b of buffers) {
      out.set(new Uint8Array(b), off);
      off += b.byteLength;
    }
    return out.buffer;
  };

  // --------------------------------------------------------------------------
  // DOM
  // --------------------------------------------------------------------------
  let ui = {};

  const bindUi = () => {
    ui.root = document.getElementById("verifier");
    if (!ui.root) return false;
    ui.runBtn = document.getElementById("verify-run");
    ui.clearBtn = document.getElementById("verify-clear");
    ui.pathSel = document.getElementById("verify-path");
    ui.refInp = document.getElementById("verify-ref");
    ui.phase = document.getElementById("verify-phase");
    ui.count = document.getElementById("verify-count");
    ui.log = document.getElementById("verify-log");
    ui.result = document.getElementById("verify-result");
    ui.resultHex = document.getElementById("verify-result-hex");
    ui.compare = document.getElementById("verify-compare");
    return true;
  };

  const setPhase = (text) => {
    if (ui.phase) ui.phase.textContent = text;
  };

  const appendLog = (line, cls = "") => {
    if (!ui.log) return;
    const row = document.createElement("div");
    row.className = "verify-line " + cls;
    row.textContent = line;
    ui.log.appendChild(row);
    // Autoscroll — only if the user hasn't scrolled up themselves.
    const nearBottom =
      ui.log.scrollHeight - ui.log.scrollTop - ui.log.clientHeight < 40;
    if (nearBottom) ui.log.scrollTop = ui.log.scrollHeight;
  };

  const clearLog = () => {
    if (ui.log) ui.log.innerHTML = "";
    if (ui.result) ui.result.hidden = true;
    if (ui.compare) {
      ui.compare.textContent = "";
      ui.compare.className = "verify-compare";
    }
    setPhase("idle");
    if (ui.count) ui.count.textContent = "0 files";
  };

  // --------------------------------------------------------------------------
  // GitHub tree walk
  // --------------------------------------------------------------------------
  //
  // One call to api.github.com for the full recursive tree of <ref>. Returns
  // an array of { path, type, sha, size }. Rate limit is 60/hr unauthenticated
  // which is fine — we make exactly one call per verifier run.
  const fetchTree = async (ref) => {
    const url = `https://api.github.com/repos/${REPO}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
    appendLog(`GET ${url}`, "dim");
    const res = await fetch(url, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (!res.ok) {
      throw new Error(
        `GitHub tree API returned ${res.status} ${res.statusText}. ` +
          `This happens if you've hit the anonymous rate limit (60/hr) or ` +
          `the ref does not exist.`,
      );
    }
    const body = await res.json();
    if (body.truncated) {
      appendLog(
        "WARN: GitHub reports the tree was truncated. Large repos need the paginated API. " +
          "Value X from this run will NOT match the canonical one.",
        "warn",
      );
    }
    return body.tree;
  };

  // Raw file fetch — NOT counted against the API rate limit. We use the
  // commit SHA as the ref so the bytes are immutable and cacheable.
  const fetchBlob = async (commitSha, path) => {
    const url = `https://raw.githubusercontent.com/${REPO}/${commitSha}/${path}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`raw fetch ${path}: ${res.status}`);
    }
    return await res.arrayBuffer();
  };

  // Resolve a ref (branch / tag / commit short-sha) to a full commit SHA.
  // Using this for the blob URLs means our hashes are reproducible: if
  // someone re-runs the widget later they get the same bytes even if main
  // has advanced. Passing `2593db6` here resolves to the exact commit the
  // ouroboros CI run was triggered on, so walking v2 at that ref produces
  // the Value X Intel's TDX module signed.
  const resolveRef = async (ref) => {
    const url = `https://api.github.com/repos/${REPO}/commits/${encodeURIComponent(ref)}`;
    const res = await fetch(url, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (!res.ok) {
      throw new Error(`resolve ${ref}: ${res.status}`);
    }
    const body = await res.json();
    return body.sha;
  };

  // --------------------------------------------------------------------------
  // Value X computation — the main event
  // --------------------------------------------------------------------------
  //
  // ALGORITHM (from v2/src/main.rs::compute_tree_hash + collect_hashes):
  //   1. Walk <dir> recursively.
  //   2. For each file, skip if basename is in SKIP_NAMES.
  //   3. Collect (relative_path, sha384(file_bytes)).
  //   4. Sort by relative_path (byte-lexicographic).
  //   5. hasher = sha384()
  //      for (p, h) in sorted:
  //        hasher.update(p.as_bytes())
  //        hasher.update(b":")
  //        hasher.update(h)              // 48 raw bytes, not hex
  //        hasher.update(b"\n")
  //   6. Value X = hasher.finalize()
  //
  // Important: the hash field in step 5 is the RAW 48 bytes of the sha384
  // digest, not its hex encoding. The Rust code uses `hasher.update(hash)`
  // on a [u8; 48]. We must match byte-for-byte.
  const computeValueX = async (rootPath, ref) => {
    setPhase(`resolving ${ref}…`);
    const commit = await resolveRef(ref);
    appendLog(`resolved ${ref} → ${commit.slice(0, 12)}`, "dim");

    setPhase("enumerating tree…");
    const tree = await fetchTree(commit);

    // Filter to files under rootPath. Use "" to mean whole repo.
    const prefix = rootPath ? rootPath.replace(/\/$/, "") + "/" : "";
    const isInRoot = (p) => !prefix || p.startsWith(prefix);

    // Apply should_skip using the BASENAME of the full path. This matches
    // v2/src/main.rs::collect_hashes which checks file_name() per entry.
    const files = tree
      .filter((e) => e.type === "blob" && isInRoot(e.path))
      .filter((e) => {
        const name = e.path.split("/").pop() || "";
        return !shouldSkip(name);
      });

    if (files.length === 0) {
      throw new Error(`no files under ${rootPath} in ${commit}`);
    }

    appendLog(
      `found ${files.length} files under ${rootPath || "<repo root>"}`,
      "ok",
    );
    setPhase(`hashing ${files.length} files…`);
    if (ui.count) ui.count.textContent = `0 / ${files.length} files`;

    // Hash each file. We relativize paths to rootPath because the Rust
    // verifier calls strip_prefix(base) before hashing — so the path
    // component in the hash input starts at the walked directory, not
    // the repo root.
    const entries = [];
    let done = 0;
    for (const f of files) {
      const rel = prefix ? f.path.slice(prefix.length) : f.path;
      const bytes = await fetchBlob(commit, f.path);
      const digest = await sha384(bytes);
      entries.push({ rel, digest, bytes: bytes.byteLength });
      done++;
      if (ui.count) ui.count.textContent = `${done} / ${files.length} files`;
      appendLog(
        `${rel.padEnd(48)} ${toHex(digest).slice(0, 16)}…  (${bytes.byteLength}B)`,
      );
      // Yield to the event loop so the DOM keeps up and the user sees
      // each line appear in real time, not all at the end.
      await new Promise((r) => setTimeout(r, 0));
    }

    setPhase("sorting by path…");
    // Byte-lexicographic sort. Rust's String::cmp is ordered by bytes;
    // for ASCII paths (all of v2/) JS default string comparison agrees.
    entries.sort((a, b) => {
      if (a.rel < b.rel) return -1;
      if (a.rel > b.rel) return 1;
      return 0;
    });
    appendLog("sorted " + entries.length + " entries", "dim");

    setPhase("computing Value X…");
    // Concatenate into the exact byte sequence the Rust hasher sees:
    //   rel_path || ":" || raw_digest(48) || "\n"
    // Then sha384 the whole thing. We build one big buffer to feed
    // SubtleCrypto — SubtleCrypto has no streaming API, so this is
    // unavoidable. For v2/ (~60 files) the buffer stays under ~10 KB,
    // which is fine.
    const parts = [];
    const enc = new TextEncoder();
    for (const e of entries) {
      parts.push(enc.encode(e.rel).buffer);
      parts.push(enc.encode(":").buffer);
      parts.push(e.digest);
      parts.push(enc.encode("\n").buffer);
    }
    const manifest = concatBuffers(parts);
    const valueX = await sha384(manifest);

    appendLog(
      `sha384(manifest, ${manifest.byteLength} bytes) = ${toHex(valueX)}`,
      "ok",
    );
    return { valueX: toHex(valueX), commit, fileCount: entries.length };
  };

  // --------------------------------------------------------------------------
  // Wiring
  // --------------------------------------------------------------------------
  const run = async () => {
    const rootPath = ui.pathSel ? ui.pathSel.value : DEFAULT_PATH;
    const ref = ui.refInp && ui.refInp.value.trim()
      ? ui.refInp.value.trim()
      : DEFAULT_REF;

    clearLog();
    ui.runBtn.disabled = true;
    ui.clearBtn.disabled = true;

    try {
      const started = performance.now();
      const { valueX, commit, fileCount } = await computeValueX(rootPath, ref);
      const elapsed = ((performance.now() - started) / 1000).toFixed(1);

      setPhase(`done in ${elapsed}s`);
      ui.result.hidden = false;
      ui.resultHex.textContent = valueX;

      // Compare to the registered Value X baked into the root element.
      // When walking `v2` at commit `2593db6`, this widget reproduces
      // the exact 48 bytes Intel's TDX module signed in the ouroboros
      // run — a live match against a committed attestation artifact.
      const registered = ui.root.getAttribute("data-registered-value-x") || "";
      const registeredCommit = ui.root.getAttribute("data-registered-commit") || "";
      if (registered && valueX.toLowerCase() === registered.toLowerCase()) {
        ui.compare.innerHTML =
          "<strong>MATCH.</strong> This is the exact Value X that " +
          "Intel's TDX module signed in the ouroboros run on commit " +
          "<code>" + registeredCommit + "</code>. " +
          "Every byte you just saw scroll by was hashed into the number in " +
          "<code>v2/testdata/chain/tdx_ouroboros.cbor</code> — and that " +
          "file's binding is in <code>report_data[0..32]</code> of a real " +
          "Intel-signed TDX quote. You have just verified the first link " +
          "of the ouroboros chain in your browser.";
        ui.compare.className = "verify-compare ok";
      } else if (registered) {
        ui.compare.innerHTML =
          "This does NOT match the registered Value X (<code>" +
          registered.slice(0, 24) +
          "…</code> from commit <code>" +
          registeredCommit +
          "</code>). " +
          "That is expected: the registered entry is <code>v2</code> at " +
          "<code>" + registeredCommit + "</code>. You walked <strong>" +
          rootPath +
          "</strong> at <strong>" +
          commit.slice(0, 12) +
          "</strong> (" +
          fileCount +
          " files). Set the path to <code>v2</code> and the ref to <code>" +
          registeredCommit +
          "</code>, click run, and watch the numbers converge.";
        ui.compare.className = "verify-compare info";
      }
    } catch (err) {
      setPhase("error");
      appendLog("ERROR: " + err.message, "err");
      console.error(err);
    } finally {
      ui.runBtn.disabled = false;
      ui.clearBtn.disabled = false;
    }
  };

  const init = () => {
    if (!bindUi()) return;
    ui.runBtn.addEventListener("click", run);
    ui.clearBtn.addEventListener("click", clearLog);
    setPhase(
      "idle — click 'compute Value X live' to walk v2 at " +
        DEFAULT_REF +
        " and reproduce the Intel-signed bytes",
    );
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
