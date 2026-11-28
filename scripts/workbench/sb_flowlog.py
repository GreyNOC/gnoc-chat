"""sb_flowlog - mitmdump addon for the workbench sandbox.

Appends one JSON line per HTTP flow to flowlog_out:
  {"ts", "method", "url", "host", "port", "scheme", "status", "in_scope", "loopback", "blocked",
   "req_headers", "req_body_b64"?, "resp_headers", "resp_len", "resp_body_head", "error"?}
in_scope is decided by the program's SCOPE.txt and NOSCOPE.txt through bbtools.lib_scope, the
same matcher the Bash scope hook mirrors. flowlog_block_oos=true answers every out-of-scope,
non-loopback request with a synthetic 451 so the app under test never reaches it.
Raw flows are also written by mitmdump itself (-w flows.mitm) for byte-faithful replay.
"""
import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sb_common  # noqa: E402

from mitmproxy import ctx, http  # noqa: E402

BODY_HEAD = 2048


class FlowLog:
    def load(self, loader):
        loader.add_option("flowlog_out", str, "", "JSONL output path")
        loader.add_option("flowlog_program", str, "", "program handle for the scope check")
        loader.add_option("flowlog_block_oos", bool, False, "451 every out-of-scope request")

    def _scope(self, host):
        prog = ctx.options.flowlog_program
        return bool(prog) and sb_common.host_in_scope(host, prog)

    def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        flow.metadata["sb_in_scope"] = self._scope(host)
        if ctx.options.flowlog_block_oos and not flow.metadata["sb_in_scope"]:
            flow.metadata["sb_blocked"] = True
            flow.response = http.Response.make(451, b"blocked by sandbox: out of scope\n",
                                               {"content-type": "text/plain"})

    def _write(self, flow, error=None):
        out = ctx.options.flowlog_out
        if not out:
            return
        req, resp = flow.request, flow.response
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(req.timestamp_start or time.time())),
            "method": req.method, "url": req.pretty_url, "host": req.pretty_host, "port": req.port,
            "scheme": req.scheme, "http_version": req.http_version,
            "in_scope": bool(flow.metadata.get("sb_in_scope")),
            "loopback": sb_common.LOOPBACK(req.pretty_host),
            "blocked": bool(flow.metadata.get("sb_blocked")),
            "req_headers": [[k, v] for k, v in req.headers.items(multi=True)],
            "req_body_len": len(req.raw_content or b""),
        }
        if req.raw_content:
            rec["req_body_b64"] = base64.b64encode(req.raw_content[:BODY_HEAD]).decode()
        if resp is not None:
            body = resp.raw_content or b""
            rec.update({
                "status": resp.status_code,
                "resp_headers": [[k, v] for k, v in resp.headers.items(multi=True)],
                "resp_len": len(body),
                "resp_body_head": body[:BODY_HEAD].decode("utf-8", "replace"),
            })
        if error:
            rec["error"] = str(error)
        with open(out, "a") as fh:
            fh.write(json.dumps(rec) + "\n")

    def response(self, flow):
        self._write(flow)

    def error(self, flow):
        self._write(flow, flow.error.msg if flow.error else "error")

    def websocket_message(self, flow):
        out = ctx.options.flowlog_out
        if not out or not flow.websocket or not flow.websocket.messages:
            return
        m = flow.websocket.messages[-1]
        with open(out, "a") as fh:
            fh.write(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(m.timestamp)),
                "ws": True, "url": flow.request.pretty_url, "host": flow.request.pretty_host,
                "from_client": m.from_client, "in_scope": bool(flow.metadata.get("sb_in_scope")),
                "len": len(m.content), "head": m.content[:BODY_HEAD].decode("utf-8", "replace"),
            }) + "\n")


addons = [FlowLog()]
