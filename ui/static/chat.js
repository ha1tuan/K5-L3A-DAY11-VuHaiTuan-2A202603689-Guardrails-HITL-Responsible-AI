import { el, withBars, fmtMs, fmtPct, fmtNum, GATES } from "./common.js";

const $ = (id) => document.getElementById(id);

const ui = {
  messages: $("messages"),
  log: $("log"),
  intro: $("intro"),
  form: $("composer"),
  q: $("q"),
  send: $("send"),
};

let busy = false;
let rate = null; // { used, max, window_seconds, reset_in }
let rateAt = 0; // performance.now() lúc nhận rate
let refetching = false;

const JOURNAL_STATUS = {
  null: ["Trả lời", "is-pass"],
  rate_limiter: ["Chặn ở giới hạn tần suất", "is-stop"],
  input_guardrail: ["Chặn ở lọc đầu vào", "is-stop"],
  output_guardrail: ["Ẩn ở lọc đầu ra", "is-stop"],
  error: ["Model trả lỗi", "is-error"],
};

// ------------------------------------------------------------
// Hiển thị câu trả lời: markdown tối thiểu, an toàn (chỉ textContent)
// ------------------------------------------------------------

function inline(text) {
  const frag = document.createDocumentFragment();
  text.split(/(\*\*[^*]+\*\*)/g).forEach((part) => {
    if (/^\*\*[^*]+\*\*$/.test(part)) frag.append(el("strong", {}, withBars(part.slice(2, -2))));
    else if (part) frag.append(withBars(part));
  });
  return frag;
}

const LIST_RE = /^\s*([-*•]|\d+[.)])\s+/;

function renderRich(text) {
  const frag = document.createDocumentFragment();
  for (const block of text.replace(/\r/g, "").split(/\n{2,}/)) {
    let para = null;
    let list = null;
    for (const line of block.split("\n")) {
      if (!line.trim()) continue;
      if (LIST_RE.test(line)) {
        const ordered = /^\s*\d/.test(line);
        if (!list || (list.tagName === "OL") !== ordered) {
          list = el(ordered ? "ol" : "ul");
          frag.append(list);
        }
        list.append(el("li", {}, inline(line.replace(LIST_RE, ""))));
        para = null;
      } else {
        const heading = /^#{1,4}\s+/.test(line);
        const content = inline(line.replace(/^#{1,4}\s+/, ""));
        if (heading) {
          frag.append(el("p", { class: "answer-h" }, content));
          para = null;
        } else if (para) {
          para.append(el("br"), content);
        } else {
          para = el("p", {}, content);
          frag.append(para);
        }
        list = null;
      }
    }
  }
  return frag;
}

// ------------------------------------------------------------
// Một lượt hỏi đáp
// ------------------------------------------------------------

function waitingTrace() {
  return el(
    "ol",
    { class: "trace is-waiting", "aria-label": "Các lớp đang xử lý" },
    GATES.map((g, k) =>
      el("li", { style: `--k:${k}` }, el("span", { class: "gate-name" }, g.name), el("span", { class: "gate-note" }, "…")),
    ),
  );
}

function gateNote(step, data) {
  if (step.status === "skip") return "Không chạy";
  if (step.note && step.status !== "pass") {
    return step.issues?.length ? `${step.note}: ${step.issues.join(", ")}` : step.note;
  }
  switch (step.gate) {
    case "rate_limiter":
      return `Lượt ${data.session.rate.used}/${data.session.rate.max}`;
    case "input_guardrail":
      return "Cho qua";
    case "model":
      return `Trả lời sau ${fmtMs(data.latency_ms)}`;
    case "output_guardrail":
      return "Không có gì phải che";
    default:
      return "Cho qua";
  }
}

function settleTrace(trace, data) {
  const names = Object.fromEntries(GATES.map((g) => [g.key, g.name]));
  trace.classList.remove("is-waiting");
  trace.setAttribute("aria-label", "Kết quả từng lớp");
  trace.replaceChildren(
    ...data.trace.map((step, i) =>
      el(
        "li",
        { style: `--d:${i * 110}ms` },
        el("span", { class: "gate-name" }, names[step.gate] ?? step.gate),
        el("span", { class: "gate-note" }, gateNote(step, data)),
      ),
    ),
  );
  // Khung hình kế tiếp mới gắn trạng thái → màu lan lần lượt qua từng lớp
  requestAnimationFrame(() =>
    requestAnimationFrame(() =>
      [...trace.children].forEach((li, i) => li.classList.add(`is-${data.trace[i].status}`)),
    ),
  );
}

function failTrace(trace) {
  trace.classList.remove("is-waiting");
  [...trace.children].forEach((li) => {
    li.classList.add("is-skip");
    li.querySelector(".gate-note").textContent = "Không chạy";
  });
}

async function send(text) {
  const message = text.trim();
  if (busy || !message) return;
  busy = true;
  ui.send.disabled = true;
  ui.intro.hidden = true;

  const trace = waitingTrace();
  const answer = el("div", { class: "answer-body is-waiting" }, "Đang chờ Blue…");
  const turn = el(
    "article",
    { class: "turn" },
    el("p", { class: "who" }, "Bạn hỏi"),
    el("p", { class: "ask-text" }, message),
    trace,
    el("p", { class: "who" }, "Blue trả lời"),
    answer,
  );
  ui.log.append(turn);
  turn.scrollIntoView({ block: "end" });

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = typeof data.detail === "string" ? data.detail : `Server trả lỗi ${res.status}.`;
      throw new Error(detail);
    }
    settleTrace(trace, data);
    answer.classList.remove("is-waiting");
    if (data.error) {
      answer.className = "answer-body is-error";
      answer.replaceChildren(el("p", {}, data.error.message));
    } else {
      answer.classList.toggle("is-blocked", data.blocked);
      answer.replaceChildren(renderRich(data.reply || "(model trả về câu rỗng)"));
    }
    updateSession(data.session);
  } catch (err) {
    failTrace(trace);
    answer.className = "answer-body is-error";
    const msg =
      err instanceof TypeError
        ? "Không gửi được tới server. Kiểm tra terminal đang chạy ui/server.py rồi gửi lại."
        : err.message;
    answer.replaceChildren(el("p", {}, msg));
  } finally {
    busy = false;
    ui.send.disabled = !ui.q.value.trim();
    turn.scrollIntoView({ block: "end", behavior: "smooth" });
    ui.q.focus();
  }
}

// ------------------------------------------------------------
// Phiên: giới hạn tần suất, số liệu, nhật ký
// ------------------------------------------------------------

function renderRate() {
  if (!rate) return;
  const elapsed = (performance.now() - rateAt) / 1000;
  const remaining = Math.max(0, rate.reset_in - elapsed);
  const used = rate.used;

  $("rate-count").textContent = `${used}/${rate.max}`;
  const slots = $("rate-slots");
  if (slots.children.length !== rate.max) {
    slots.replaceChildren(...Array.from({ length: rate.max }, () => el("li")));
  }
  [...slots.children].forEach((li, i) => li.classList.toggle("is-used", i < used));
  slots.classList.toggle("is-full", used >= rate.max);

  const note = $("rate-note");
  if (!used) note.textContent = `Mỗi ${rate.window_seconds} giây được ${rate.max} lượt.`;
  else if (used >= rate.max) note.textContent = `Hết lượt. Lượt tiếp theo mở sau ${Math.ceil(remaining)} giây.`;
  else note.textContent = `Lượt cũ nhất hết hạn sau ${Math.ceil(remaining)} giây.`;

  // Lượt cũ nhất vừa hết hạn → hỏi lại server số lượt còn trong cửa sổ
  if (used && remaining <= 0 && !refetching && !busy) {
    refetching = true;
    fetch("/api/console")
      .then((r) => r.json())
      .then((d) => updateSession(d.session))
      .catch(() => {})
      .finally(() => { refetching = false; });
  }
}

function updateSession(s) {
  rate = s.rate;
  rateAt = performance.now();
  renderRate();

  const m = s.metrics;
  const over = m.block_rate > s.thresholds.block_rate;
  $("st-total").textContent = fmtNum(m.total_requests);
  $("st-blocked").textContent = fmtNum(m.blocked_requests);
  const rateEl = $("st-rate");
  rateEl.textContent = fmtPct(m.block_rate);
  rateEl.classList.toggle("is-over", over);
  rateEl.title = `Ngưỡng cảnh báo ${fmtPct(s.thresholds.block_rate)}`;

  const alerts = $("alerts");
  alerts.classList.toggle("has-alert", m.alerts.length > 0);
  alerts.textContent = m.alerts.length
    ? m.alerts.map((a) => a.message).join(". ") + "."
    : `Chưa có cảnh báo. Cảnh báo bật khi tỉ lệ chặn vượt ${fmtPct(s.thresholds.block_rate)}.`;

  $("side-brief").textContent = `${rate.used}/${rate.max} lượt, ${fmtNum(m.blocked_requests)} bị chặn`;

  const list = $("journal-list");
  list.replaceChildren(
    ...s.log.map((e) => {
      const [label, cls] = JOURNAL_STATUS[e.layer] ?? [e.layer, ""];
      const time = e.ts ? new Date(e.ts).toLocaleTimeString("vi-VN") : "";
      return el(
        "li",
        {},
        el("span", { class: "j-time num" }, time),
        el("span", { class: "j-text", title: e.input }, e.input || "(rỗng)"),
        el("span", { class: `j-status ${cls}` }, label, el("span", { class: "j-lat num" }, fmtMs(e.latency_ms))),
      );
    }),
  );
  $("journal-count").textContent = s.log.length ? `(${s.log.length})` : "";
  $("journal-empty").hidden = s.log.length > 0;
}

// ------------------------------------------------------------
// Khởi tạo
// ------------------------------------------------------------

function renderSamples(samples) {
  const group = (title, items, probe) =>
    el(
      "div",
      { class: "sample-group" },
      el("h2", {}, title),
      el(
        "div",
        { class: "chips" },
        items.map((t) =>
          el("button", { type: "button", class: `chip${probe ? " is-probe" : ""}`, onclick: () => send(t) }, t),
        ),
      ),
    );
  $("samples").replaceChildren(
    group("Câu hỏi ngân hàng", samples.banking),
    group("Thử các lớp chắn", samples.guards, true),
  );
}

function autosize() {
  ui.q.style.height = "auto";
  ui.q.style.height = `${Math.min(ui.q.scrollHeight, 200)}px`;
  ui.send.disabled = busy || !ui.q.value.trim();
}

ui.q.addEventListener("input", autosize);
ui.q.addEventListener("keydown", (e) => {
  // isComposing: bộ gõ tiếng Việt (Telex/VNI) đang ghép dấu → không gửi
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
    e.preventDefault();
    ui.form.requestSubmit();
  }
});
ui.form.addEventListener("submit", (e) => {
  e.preventDefault();
  const text = ui.q.value;
  if (!text.trim() || busy) return;
  ui.q.value = "";
  autosize();
  send(text);
});

$("reset").addEventListener("click", async () => {
  if (busy) return;
  const res = await fetch("/api/console/reset", { method: "POST" }).catch(() => null);
  if (!res?.ok) return;
  const data = await res.json();
  ui.log.querySelectorAll(".turn").forEach((t) => t.remove());
  ui.intro.hidden = false;
  updateSession(data.session);
  ui.q.focus();
});

// Màn rộng: khung phiên luôn mở. Màn hẹp: thu gọn, bấm để mở.
const narrow = window.matchMedia("(max-width: 900px)");
const sideDetails = $("side-details");
const syncSide = () => { sideDetails.open = !narrow.matches; };
narrow.addEventListener("change", syncSide);
syncSide();
sideDetails.querySelector(".side-summary").addEventListener("click", (e) => {
  if (!narrow.matches) e.preventDefault();
});

setInterval(renderRate, 1000);

(async () => {
  autosize();
  try {
    const res = await fetch("/api/console");
    const data = await res.json();
    $("model-name").textContent = data.blue.model;
    $("key-warning").hidden = data.blue.has_key;
    renderSamples(data.samples);
    updateSession(data.session);
  } catch {
    $("samples").replaceChildren(
      el("p", { class: "intro-warning" }, "Không đọc được trạng thái server. Kiểm tra terminal đang chạy ui/server.py rồi tải lại trang."),
    );
  }
  ui.q.focus();
})();
