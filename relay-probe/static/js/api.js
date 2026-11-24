let access = "";
export function setAccess(value) { access = value; }

async function local(path, options = {}) {
  if (!/^\/api\/[A-Za-z0-9/_-]+$/.test(path)) throw new Error("需要同源 API 路径");
  const headers = { ...(options.headers || {}) };
  if (access) headers.Authorization = `Bearer ${access}`;
  const res = await fetch(path, { ...options, headers, credentials: "omit", cache: "no-store", redirect: "error" });
  if (!res.ok) {
    const info = await res.json().catch(() => ({}));
    const err = new Error([info.detail || `HTTP ${res.status}`, info.fields?.join("、"), info.snippet].filter(Boolean).join(" · "));
    err.status = res.status;
    err.code = info.code;
    throw err;
  }
  return res;
}

export async function api(path, body, method = body === undefined ? "GET" : "POST") {
  return (await local(path, { method, headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) })).json();
}

export async function streamRun(id, onEvent) {
  let cursor = 0;
  let attempts = 0;
  while (true) {
    try {
      const response = await local(`/api/runs/${id}/stream`, { headers: { "Last-Event-ID": String(cursor) } });
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          buffer += part.value.replace(/\r/g, "");
          let end;
          while ((end = buffer.indexOf("\n\n")) >= 0) {
            const frame = buffer.slice(0, end);
            buffer = buffer.slice(end + 2);
            const lines = frame.split("\n");
            const field = name => lines.find(x => x.startsWith(name + ":"))?.slice(name.length + 1).trim();
            if (!field("data")) continue;
            const type = field("event");
            const seq = Number(field("id"));
            if (seq <= cursor) continue;
            onEvent(type, JSON.parse(field("data")));
            cursor = seq;
            attempts = 0;
            if (type === "report") return;
          }
        }
      } finally { reader.releaseLock(); }
      throw new Error("事件流提前关闭");
    } catch (err) {
      if (err.status || ++attempts > 5) throw err;
      onEvent("reconnect", { message: `连接中断，从事件 ${cursor} 续读（${attempts}/5）` });
      await new Promise(resolve => setTimeout(resolve, 600 * attempts));
    }
  }
}
