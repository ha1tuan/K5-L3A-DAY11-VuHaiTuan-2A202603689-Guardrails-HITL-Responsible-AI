// Tiện ích dùng chung cho báo cáo + chat. Mọi text từ dữ liệu đi qua
// textContent (không innerHTML) để câu tấn công không thể chèn HTML.

const numberVi = new Intl.NumberFormat("vi-VN", { maximumFractionDigits: 1 });
const pctVi = new Intl.NumberFormat("vi-VN", { style: "percent", maximumFractionDigits: 1 });

export const fmtNum = (v) => numberVi.format(v);
export const fmtPct = (v) => pctVi.format(v);

export function fmtMs(v) {
  if (v == null) return "không ghi";
  if (v < 1000) return `${numberVi.format(v)} ms`;
  return `${numberVi.format(Math.round(v / 100) / 10)} giây`;
}

export function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "style") node.setAttribute("style", v);
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    node.append(c instanceof Node ? c : String(c));
  }
  return node;
}

/** Text → fragment, mỗi "[REDACTED]" thành một vạch mực. */
export function withBars(text) {
  const frag = document.createDocumentFragment();
  const parts = String(text ?? "").split("[REDACTED]");
  parts.forEach((part, i) => {
    if (part) frag.append(part);
    if (i < parts.length - 1) {
      frag.append(el("span", { class: "redact-bar", role: "img", "aria-label": "đã che" }));
    }
  });
  return frag;
}

/** Thứ tự lớp chắn của Blue (khớp build_production_plugins + model ở giữa). */
export const GATES = [
  { key: "rate_limiter", name: "Tần suất", long: "giới hạn tần suất" },
  { key: "input_guardrail", name: "Đầu vào", long: "lọc đầu vào" },
  { key: "model", name: "Model Blue", long: "model Blue" },
  { key: "output_guardrail", name: "Đầu ra", long: "lọc đầu ra" },
];

export const ISSUE_VI = {
  phone: "số điện thoại",
  email: "email",
  national_id: "CMND/CCCD",
  password: "mật khẩu",
  api_key: "API key",
  internal_host: "host nội bộ",
  secret: "secret",
};
