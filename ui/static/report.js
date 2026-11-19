import { el, withBars, fmtMs, fmtPct, fmtNum, GATES, ISSUE_VI } from "./common.js";

const $ = (id) => document.getElementById(id);

// Cột trong sổ: 4 lớp + điểm đến. Layer trong audit → cột mà đường kẻ dừng lại.
const COLS = [...GATES.map((g) => g.name), "Người dùng"];
const REACH = { rate_limiter: 0, input_guardrail: 1, error: 2, output_guardrail: 3 };
const LAYER_VI = Object.fromEntries(GATES.map((g) => [g.key, g.long]));

// Kết quả CP4 (layer trong attack_results.json) → nhãn + kiểu con dấu
const ATTACK_OUTCOME = {
  leaked: ["Lộ secret", "is-breach"],
  model_refuse: ["Model từ chối", "is-pass"],
  input_injection: ["Chặn ở L1: injection", ""],
  input_topic: ["Chặn ở L1: chủ đề", ""],
  nemo_input_rail: ["Chặn ở L2: NeMo đầu vào", ""],
  output_filter: ["Chặn ở L3: lọc đầu ra", ""],
  nemo_output_rail: ["Chặn ở L4: NeMo đầu ra", ""],
  nemo_error: ["NeMo lỗi, chặn an toàn", "is-error"],
  error: ["Lỗi khi chạy", "is-error"],
};

const statusOf = (r) => (r.layer === "error" ? "error" : r.blocked ? "stop" : "pass");

function verdictText(r) {
  const s = statusOf(r);
  if (s === "stop") return `bị chặn ở ${LAYER_VI[r.layer] ?? r.layer}`;
  if (s === "error") return "model trả lỗi";
  return "đã tới người dùng";
}

function tally(rows) {
  const n = { stop: 0, pass: 0, error: 0 };
  rows.forEach((r) => n[statusOf(r)]++);
  return [
    n.stop && `${n.stop} bị chặn`,
    n.pass && `${n.pass} được trả lời`,
    n.error && `${n.error} lỗi model`,
  ].filter(Boolean).join(", ");
}

function secHead(id, title, lede) {
  return [el("h2", { id }, title), lede ? el("p", { class: "sec-lede" }, lede) : null];
}

/** Hiện ký tự vô hình (vd U+200B trong ca injection Unicode). */
function showInvisible(text) {
  const parts = String(text).split("​");
  return parts.flatMap((p, i) =>
    i < parts.length - 1 ? [p, el("span", { class: "zw", title: "Ký tự ẩn U+200B" }, "U+200B")] : [p],
  );
}

// ------------------------------------------------------------
// Đầu trang
// ------------------------------------------------------------

function renderMasthead(d) {
  const cp3 = d.cp3;
  if (cp3) {
    const total = cp3.rows.length;
    const blocked = cp3.rows.filter((r) => r.blocked).length;
    $("headline").textContent =
      `${total} yêu cầu đi qua pipeline của Blue. ${blocked} yêu cầu bị chặn trước khi tới người dùng.`;
    $("lede").textContent =
      "Mỗi dòng trong sổ dưới đây là một yêu cầu của bộ test Checkpoint 3, đúng thứ tự trong " +
      "outputs/audit_log.json. Đường kẻ dừng ở lớp nào thì lớp đó đã chặn; đường chạy tới cột " +
      "cuối là câu trả lời đã tới người dùng. Chọn một dòng để xem nội dung.";
  } else {
    $("headline").textContent = "Chưa có kết quả Checkpoint 3";
    $("lede").textContent =
      "Không tìm thấy outputs/results.json. Chạy python src/main.py --part 3 rồi tải lại trang.";
  }

  const pluginVi = d.blue.plugins.map((p) => {
    if (p.name === "rate_limiter") return `giới hạn tần suất (${p.max_requests} yêu cầu / ${p.window_seconds} giây)`;
    return LAYER_VI[p.name] ?? p.name;
  });
  const red = d.cp4 ? { model: d.cp4.model, provider: d.cp4.provider } : d.red;
  const facts = [
    ["Sinh viên", d.student.name && `${d.student.name}, ${d.student.id}`],
    ["Blue", `${d.blue.model} qua OpenRouter`],
    ["Red và Red Advance", `${red.model} qua ${red.provider}`],
    ["Thứ tự plugin", pluginVi.join(", rồi ")],
  ];
  $("facts").append(
    ...facts.filter(([, v]) => v).map(([k, v]) => el("div", {}, el("dt", {}, k), el("dd", {}, v))),
  );
}

// ------------------------------------------------------------
// Sổ kiểm soát (hero)
// ------------------------------------------------------------

function renderLedger(d) {
  const wrap = $("ledger-wrap");
  const cp3 = d.cp3;
  if (!cp3) return wrap.remove();

  const rl = d.blue.plugins.find((p) => p.name === "rate_limiter");
  const subs = [
    rl ? `${rl.max_requests} trong ${rl.window_seconds} giây` : "",
    "injection, chủ đề",
    d.blue.model.split("/").pop().replace(":free", ""),
    "che PII, ẩn secret",
    "nhận câu trả lời",
  ];

  const cols = el(
    "div",
    { class: "ledger-cols", "aria-hidden": "true" },
    el("div", { class: "lc lc-label" }, "Yêu cầu"),
    COLS.map((name, i) =>
      el("div", { class: "lc" }, el("span", { class: "lc-name" }, name), el("span", { class: "lc-sub" }, subs[i])),
    ),
  );

  const body = el("div", { class: "ledger-body" });
  body.append(el("div", { class: "rails", "aria-hidden": "true" }, COLS.map(() => el("span"))));

  const detail = el("aside", { class: "detail", "aria-live": "polite", "aria-label": "Chi tiết yêu cầu" });
  const buttons = [];
  let i = 0;

  // Màn hẹp: chi tiết mở ngay dưới dòng được chọn thay vì ở cột phải.
  const narrow = window.matchMedia("(max-width: 1080px)");
  let current = null;
  const place = () => {
    if (!current) return;
    if (narrow.matches) current.after(detail);
    else if (detail.parentElement !== wrap) wrap.append(detail);
    detail.classList.toggle("is-inline", narrow.matches);
  };
  narrow.addEventListener("change", place);

  const select = (btn, r, g) => {
    buttons.forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
    current = btn;
    renderDetail(detail, r, g);
    place();
  };

  for (const g of cp3.groups) {
    const rows = cp3.rows.filter((r) => r.group === g.key);
    if (!rows.length) continue;
    body.append(
      el("div", { class: "lgroup" }, el("h3", {}, g.label), el("span", { class: "lgroup-tally" }, tally(rows))),
    );
    if (g.key === "rate") {
      body.append(el("p", { class: "lgroup-note" }, "Cùng một câu gửi liên tiếp: ", el("span", { class: "verbatim" }, rows[0].input)));
    }
    for (const r of rows) {
      const status = statusOf(r);
      const label = g.key === "rate" ? `Lần ${r.n}` : r.input || "(chuỗi rỗng)";
      const btn = el(
        "button",
        {
          type: "button",
          class: `lrow is-${status}`,
          style: `--reach:${REACH[r.layer] ?? 4};--i:${i++}`,
          "aria-pressed": "false",
          "aria-label": `${g.label}, dòng ${r.n}: ${verdictText(r)}`,
        },
        el("span", { class: `lrow-text${g.key === "rate" ? "" : " verbatim"}` }, label.slice(0, 160)),
        el("span", { class: "lrow-track" }, el("span", { class: "lrow-line" })),
      );
      btn.addEventListener("click", () => select(btn, r, g));
      buttons.push(btn);
      body.append(btn);
    }
  }

  // Mũi tên lên/xuống để đi qua từng dòng
  body.addEventListener("keydown", (e) => {
    const idx = buttons.indexOf(document.activeElement);
    if (idx < 0) return;
    const to = { ArrowDown: idx + 1, ArrowUp: idx - 1, Home: 0, End: buttons.length - 1 }[e.key];
    if (to == null || !buttons[to]) return;
    e.preventDefault();
    buttons[to].focus();
    buttons[to].click();
  });

  const legend = el(
    "p",
    { class: "legend" },
    el("span", { class: "lg lg-stop" }, "bị chặn tại lớp đó"),
    el("span", { class: "lg lg-pass" }, "tới người dùng"),
    el("span", { class: "lg lg-error" }, "model trả lỗi"),
  );

  wrap.append(el("div", { class: "ledger" }, cols, body, legend));

  const first = buttons.find((b) => b.classList.contains("is-stop")) || buttons[0];
  if (first) first.click();
}

function renderDetail(detail, r, g) {
  const s = statusOf(r);
  const stamp =
    s === "stop"
      ? el("span", { class: "stamp" }, `Đã chặn ở ${LAYER_VI[r.layer] ?? r.layer}`)
      : s === "error"
        ? el("span", { class: "stamp is-error" }, "Model trả lỗi, không phải chặn")
        : el("span", { class: "stamp is-pass" }, "Đã tới người dùng");

  detail.replaceChildren(...[
    el("p", { class: "detail-where" }, `${g.label}, dòng ${r.n}`),
    stamp,
    el(
      "dl",
      { class: "detail-facts" },
      el("div", {}, el("dt", {}, "Thời gian xử lý"), el("dd", { class: "num" }, fmtMs(r.latency_ms))),
      el("div", {}, el("dt", {}, "Lớp ghi trong audit"), el("dd", { class: "verbatim" }, r.layer ?? "null")),
    ),
    el("h4", {}, "Đầu vào"),
    el("div", { class: "detail-block verbatim" }, r.input ? showInvisible(r.input) : "(chuỗi rỗng)"),
    r.input_len > r.input.length
      ? el("p", { class: "detail-note" }, `Dài ${fmtNum(r.input_len)} ký tự, đang hiện ${fmtNum(r.input.length)} ký tự đầu.`)
      : null,
    el("h4", {}, "Phản hồi"),
    el("div", { class: "detail-block" }, r.preview ? withBars(r.preview) : "(trống)"),
  ].filter(Boolean));
}

// ------------------------------------------------------------
// Checkpoint 2
// ------------------------------------------------------------

const verdictWord = (v, muted = false) =>
  el("span", { class: `vw ${v === "BLOCK" ? "is-stop" : "is-pass"}${muted ? " is-muted" : ""}` }, v === "BLOCK" ? "Chặn" : "Cho qua");

function verdictTable(title, fn, rows) {
  const ok = rows.filter((r) => r.ok).length;
  return el(
    "div",
    { class: "bench" },
    el("h3", {}, title, " ", el("code", { class: "fn" }, fn)),
    el("p", { class: "tally" }, `${ok}/${rows.length} ca đúng`),
    el(
      "div",
      { class: "table-scroll" },
      el(
        "table",
        { class: "vt" },
        el("thead", {}, el("tr", {}, ["Câu kiểm tra", "Mong đợi", "Kết quả"].map((h) => el("th", { scope: "col" }, h)))),
        el(
          "tbody",
          {},
          rows.map((r) =>
            el(
              "tr",
              { class: r.ok ? "" : "is-wrong" },
              el("td", {}, el("span", { class: "verbatim" }, showInvisible(r.text)), el("span", { class: "src" }, r.source)),
              el("td", {}, verdictWord(r.expected, true)),
              el("td", {}, verdictWord(r.actual), r.ok ? null : el("span", { class: "wrong" }, "sai")),
            ),
          ),
        ),
      ),
    ),
  );
}

function renderCP2(cp2) {
  const sec = $("cp2");
  const all = [...cp2.injection, ...cp2.topic, ...cp2.output];
  const ok = all.filter((r) => r.ok).length;
  const out = cp2.output;
  const outOk = out.filter((r) => r.ok).length;

  const ACTION = {
    keep: ["Giữ nguyên", "stamp is-pass"],
    redact: ["Che", "stamp is-redact"],
    withhold: ["Ẩn cả câu", "stamp"],
  };

  sec.append(
    ...secHead(
      "cp2-title",
      "Checkpoint 2: bộ lọc đầu vào và đầu ra",
      `${ok} trên ${all.length} ca cho đúng kết quả mong đợi. Các ca được chạy lại trên code trong src/guardrails mỗi lần mở trang, không gọi model.`,
    ),
    el(
      "div",
      { class: "sec-grid" },
      verdictTable("Phát hiện prompt injection", "detect_injection()", cp2.injection),
      verdictTable("Lọc chủ đề", "topic_filter()", cp2.topic),
    ),
    el(
      "div",
      { class: "bench" },
      el("h3", {}, "Lọc đầu ra ", el("code", { class: "fn" }, "content_filter()")),
      el("p", { class: "tally" }, `${outOk}/${out.length} ca đúng`),
      el(
        "p",
        { class: "bench-lede" },
        "Mười câu trả lời mẫu trong data/pii_hallucination_samples.json và một ca từ test public. " +
          "Dữ liệu cá nhân của khách hàng bị che, phần còn lại của câu vẫn giữ. Nếu có secret nội bộ, " +
          "OutputGuardrailPlugin ẩn cả câu vì model đã bị lừa và phần còn lại không còn đáng tin.",
      ),
      el(
        "ul",
        { class: "pii-list" },
        out.map((r) => {
          const [label, cls] = ACTION[r.action];
          const kinds = r.found.length ? r.found.map((k) => ISSUE_VI[k] ?? k).join(", ") : "không có dữ liệu nhạy cảm";
          return el(
            "li",
            { class: `pii${r.ok ? "" : " is-wrong"}` },
            el(
              "div",
              { class: "pii-head" },
              el("span", { class: "pii-kind" }, kinds),
              el("span", { class: cls }, label),
              r.ok ? null : el("span", { class: "wrong" }, "sai"),
            ),
            el(
              "div",
              { class: "pii-pair" },
              el("div", {}, el("span", { class: "pii-label" }, "Model trả lời"), el("p", { class: "verbatim pii-before" }, r.text)),
              el(
                "div",
                {},
                el("span", { class: "pii-label" }, "Người dùng nhận"),
                r.action === "withhold"
                  ? el("p", { class: "pii-after is-withheld" }, "Thông báo an toàn thay cho cả câu. Bản đã che: ", el("span", { class: "verbatim" }, withBars(r.redacted)))
                  : el("p", { class: "verbatim pii-after" }, withBars(r.redacted)),
              ),
            ),
          );
        }),
      ),
    ),
  );
}

// ------------------------------------------------------------
// Checkpoint 3
// ------------------------------------------------------------

function meter(label, value, threshold, fmt, max, note) {
  const over = value > threshold;
  const pct = (v) => `${Math.min(100, (v / max) * 100)}%`;
  return el(
    "div",
    { class: `meter${over ? " is-over" : ""}` },
    el(
      "div",
      { class: "meter-row" },
      el("span", { class: "meter-label" }, label),
      el("span", { class: "meter-value num" }, fmt(value), el("span", { class: "meter-th" }, `ngưỡng ${fmt(threshold)}`)),
    ),
    el(
      "div",
      { class: "meter-track", role: "img", "aria-label": `${label}: ${fmt(value)}, ngưỡng ${fmt(threshold)}` },
      el("span", { class: "meter-fill", style: `width:${pct(value)}` }),
      el("span", { class: "meter-tick", style: `left:${pct(threshold)}` }),
    ),
    note ? el("p", { class: "meter-note" }, note) : null,
  );
}

function renderCP3(cp3, egress) {
  const sec = $("cp3");
  if (!cp3) {
    sec.append(
      ...secHead("cp3-title", "Checkpoint 3: pipeline, giới hạn tần suất và giám sát",
        "Chưa có outputs/results.json. Chạy python src/main.py --part 3 rồi tải lại trang."),
    );
    return;
  }
  const m = cp3.metrics || {};
  const t = cp3.thresholds;
  const rl = cp3.rate_limit || {};
  const rateRows = cp3.rows.filter((r) => r.group === "rate");
  const rateErrors = rateRows.filter((r) => statusOf(r) === "error").length;

  const equalAtThreshold = [
    m.block_rate === t.block_rate && "tỉ lệ chặn",
    m.rate_limit_hits === t.rate_limit_hits && `số lần chạm giới hạn (${m.rate_limit_hits})`,
  ].filter(Boolean);
  const alerts = m.alerts || [];
  const alertText = alerts.length
    ? `${alerts.length} cảnh báo: ${alerts.map((a) => a.message).join("; ")}.`
    : "Không có cảnh báo: cảnh báo chỉ bật khi một chỉ số vượt hẳn ngưỡng." +
      (equalAtThreshold.length ? ` Hiện ${equalAtThreshold.join(" và ")} đang bằng đúng ngưỡng nên chưa bật.` : "");

  const egressOk = egress.filter((r) => r.ok).length;

  sec.append(
    ...secHead(
      "cp3-title",
      "Checkpoint 3: pipeline, giới hạn tần suất và giám sát",
      `Đọc từ outputs/results.json, metrics.json và audit_log.json (framework ${cp3.framework ?? "không ghi"}).`,
    ),
    el(
      "div",
      { class: "sec-grid" },
      el(
        "div",
        { class: "bench" },
        el("h3", {}, "Giới hạn tần suất"),
        el(
          "ol",
          { class: "slots", "aria-label": "Từng yêu cầu trong lượt gửi dồn dập" },
          rateRows.map((r) => el("li", { class: `slot is-${statusOf(r)}`, title: `Lần ${r.n}: ${verdictText(r)}` }, el("span", { class: "visually-hidden" }, `Lần ${r.n}: ${verdictText(r)}`))),
        ),
        el(
          "p",
          { class: "bench-lede" },
          `Gửi ${rl.sent} yêu cầu liên tiếp với giới hạn ${rl.max_requests} yêu cầu trong ${rl.window_seconds} giây: ${rl.passed} qua, ${rl.blocked} bị chặn.` +
            (rateErrors ? ` ${rateErrors === 1 ? "Một" : rateErrors} yêu cầu qua được giới hạn nhưng model trả lỗi, nên không tính là bị chặn.` : ""),
        ),
      ),
      el(
        "div",
        { class: "bench" },
        el("h3", {}, "Thời gian xử lý"),
        el(
          "div",
          { class: "lat" },
          el("div", {}, el("span", { class: "lat-num num" }, fmtMs(cp3.latency.blocked_median)), el("span", { class: "lat-label" }, "trung vị khi bị chặn trước model")),
          el("div", {}, el("span", { class: "lat-num num" }, fmtMs(cp3.latency.model_median)), el("span", { class: "lat-label" }, "trung vị khi đi tới model")),
        ),
        el("p", { class: "bench-lede" }, "Yêu cầu bị chặn ở plugin không tốn lượt gọi model, nên gần như không mất thời gian."),
      ),
    ),
    el(
      "div",
      { class: "bench" },
      el("h3", {}, "Giám sát"),
      el(
        "div",
        { class: "meters" },
        meter("Tỉ lệ chặn", m.block_rate ?? 0, t.block_rate, fmtPct, 1),
        meter("Số lần chạm giới hạn tần suất", m.rate_limit_hits ?? 0, t.rate_limit_hits, fmtNum, Math.max(t.rate_limit_hits * 2, m.rate_limit_hits ?? 0)),
        meter("Tỉ lệ judge đánh trượt", m.judge_fail_rate ?? 0, t.judge_fail_rate, fmtPct, 1,
          m.judge_checks ? null : "LLM-as-Judge không bật, chưa có lượt kiểm tra nào."),
      ),
      el("p", { class: "bench-lede" }, alertText),
    ),
    el(
      "div",
      { class: "bench" },
      el("h3", {}, "Kiểm soát dữ liệu gửi ra ngoài ", el("code", { class: "fn" }, "is_egress_allowed()")),
      el("p", { class: "tally" }, `${egressOk}/${egress.length} ca đúng`),
      el(
        "div",
        { class: "table-scroll" },
        el(
          "table",
          { class: "vt" },
          el("thead", {}, el("tr", {}, ["Đích", "Dữ liệu", "Mong đợi", "Kết quả"].map((h) => el("th", { scope: "col" }, h)))),
          el(
            "tbody",
            {},
            egress.map((r) =>
              el(
                "tr",
                { class: r.ok ? "" : "is-wrong" },
                el("td", {}, el("span", { class: "verbatim" }, r.destination), el("span", { class: "src" }, r.source)),
                el("td", {}, el("span", { class: "verbatim" }, r.payload)),
                el("td", {}, verdictWord(r.expected ? "ALLOW" : "BLOCK", true)),
                el("td", {}, verdictWord(r.actual ? "ALLOW" : "BLOCK"), r.ok ? null : el("span", { class: "wrong" }, "sai")),
              ),
            ),
          ),
        ),
      ),
    ),
  );
}

// ------------------------------------------------------------
// Checkpoint 4
// ------------------------------------------------------------

function outcome(r) {
  if (!r) return el("span", { class: "muted" }, "không có");
  const [label, cls] = ATTACK_OUTCOME[r.layer] ?? ["Trả lời, không lộ", null];
  if (cls === null) return el("span", { class: "plain-outcome" }, label);
  return el("span", { class: `stamp ${cls}` }, label, r.leaked && !r.evidence_in_preview ? el("sup", {}, "*") : null);
}

function renderCP4(cp4) {
  const sec = $("cp4");
  if (!cp4) {
    sec.append(
      ...secHead("cp4-title", "Checkpoint 4: tấn công Red và Red Advance",
        "Chưa có outputs/attack_results.json. Chạy python src/main.py --part 4 rồi tải lại trang."),
    );
    return;
  }
  const { red, advance } = cp4;
  const leaks = red.filter((r) => r.leaked).length;
  const advLeaks = advance.filter((r) => r.leaked).length;
  const advL1 = advance.filter((r) => r.layer === "input_injection" || r.layer === "input_topic").length;
  const advText = advLeaks
    ? `Red Advance lộ secret ở ${advLeaks} trên ${advance.length} prompt.`
    : advL1 === advance.length
      ? `Red Advance chặn cả ${advance.length} prompt ngay ở lớp regex đầu vào (L1), nên chưa prompt nào tới NeMo hay model.`
      : "Red Advance không lộ secret ở prompt nào.";
  const missingEvidence = red.some((r) => r.leaked && !r.evidence_in_preview);

  const byId = new Map(advance.map((r) => [r.id, r]));
  const pairs = red.map((r, i) => [r, byId.get(r.id) ?? advance[i]]);

  sec.append(
    ...secHead(
      "cp4-title",
      "Checkpoint 4: tấn công Red và Red Advance",
      `Model tấn công ${cp4.model} qua ${cp4.provider}, ${cp4.harder_model ? "model khó (tuỳ chọn)" : "model mặc định của lab"}. Đọc từ outputs/attack_results.json.`,
    ),
    el("p", { class: "cp4-summary" }, `Red lộ secret ở ${leaks} trên ${red.length} prompt. ${advText}`),
    el(
      "div",
      { class: "atk-table" },
      el(
        "div",
        { class: "atk-head", "aria-hidden": "true" },
        ["Nhóm prompt", "Red, không có guardrail", "Red Advance, 4 lớp"].map((h) => el("span", {}, h)),
      ),
      pairs.map(([r, a]) => {
        const body = el(
          "div",
          { class: "atk-body" },
          el("h4", {}, "Prompt"),
          el("div", { class: "detail-block verbatim" }, r.input),
          a && a.input !== r.input ? [el("h4", {}, "Prompt gửi Red Advance"), el("div", { class: "detail-block verbatim" }, a.input)] : null,
          el(
            "div",
            { class: "atk-replies" },
            el(
              "div",
              {},
              el("h4", {}, "Red trả lời"),
              el("div", { class: "detail-block" }, r.preview ? withBars(r.preview) : "(trống)"),
              r.leaked && !r.evidence_in_preview
                ? el("p", { class: "detail-note" }, "Bản xem trước 300 ký tự không chứa giá trị secret; leak được phát hiện trên câu trả lời đầy đủ lúc chạy.")
                : null,
            ),
            a
              ? el("div", {}, el("h4", {}, "Red Advance trả lời"), el("div", { class: "detail-block" }, a.preview ? withBars(a.preview) : "(trống)"))
              : null,
          ),
        );
        return el(
          "details",
          { class: "atk-row" },
          el(
            "summary",
            {},
            el("span", { class: "atk-cat" }, r.category),
            el("span", { "data-label": "Red" }, el("span", { class: "visually-hidden" }, "Red: "), outcome(r)),
            el("span", { "data-label": "Red Advance" }, el("span", { class: "visually-hidden" }, "Red Advance: "), outcome(a)),
            el("span", { class: "atk-more", "aria-hidden": "true" }, "Chi tiết"),
          ),
          body,
        );
      }),
    ),
    missingEvidence
      ? el("p", { class: "footnote" }, "* Bản xem trước 300 ký tự lưu trong JSON không chứa giá trị secret. Leak được phát hiện trên câu trả lời đầy đủ, nên người chấm cần replay để thấy bằng chứng.")
      : null,
  );
}

function renderFoot(d) {
  const when = new Date(d.generated_at).toLocaleString("vi-VN");
  $("foot").append(
    el("p", {}, `Số liệu đọc từ outputs/ lúc ${when}. Sau khi chạy lại python src/main.py --part 3 hoặc --part 4, tải lại trang để cập nhật.`),
    el("p", {}, el("a", { href: "/chat" }, "Hỏi Blue trực tiếp"), " để xem từng lớp xử lý một câu hỏi mới."),
  );
}

async function main() {
  let data;
  try {
    const res = await fetch("/api/report");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();
  } catch (err) {
    $("headline").textContent = "Không đọc được dữ liệu báo cáo";
    $("lede").textContent = `Máy chủ trả lỗi (${err.message}). Kiểm tra terminal đang chạy ui/server.py rồi tải lại trang.`;
    return;
  }
  renderMasthead(data);
  renderLedger(data);
  renderCP2(data.cp2);
  renderCP3(data.cp3, data.egress);
  renderCP4(data.cp4);
  renderFoot(data);
}

main();
