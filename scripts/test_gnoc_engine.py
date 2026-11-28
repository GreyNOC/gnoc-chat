"""gnoc_engine: the model store, the downloads, and the Ollama-shaped HTTP API, against a stand-in llama-server
(a small script that speaks llama-server's /health and streaming /v1/chat/completions), so no model is needed."""
import contextlib
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import threading
import types
import unittest
import unittest.mock
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_engine as E  # noqa: E402

FAKE_SERVER = r'''#!/usr/bin/env python3
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
a = sys.argv
port, ctx = int(a[a.index("--port") + 1]), int(a[a.index("-c") + 1])
print("load_tensors: offloaded 3/4 layers to GPU", flush=True)
class H(BaseHTTPRequestHandler):
    def log_message(self, *x): pass
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.loads(raw)
        with open(os.environ["FAKE_LOG"], "a") as f:
            f.write(json.dumps({"path": self.path, "ctx": ctx, "argv": a[1:], "body": body}) + "\n")
        text = json.dumps(body.get("messages"))
        if "OVERFLOW" in text:
            err = json.dumps({"error": {"code": 400, "type": "exceed_context_size_error", "n_prompt_tokens": 20378,
                                        "n_ctx": ctx, "message": "request (20378 tokens) exceeds the available context size"}}).encode()
            self.send_response(400); self.send_header("Content-Length", str(len(err))); self.end_headers()
            return self.wfile.write(err)
        if self.path.endswith("/embeddings"):
            if "--embeddings" not in a:
                err = json.dumps({"error": {"code": 501, "message": "This server does not support embeddings"}}).encode()
                self.send_response(501); self.send_header("Content-Length", str(len(err))); self.end_headers()
                return self.wfile.write(err)
            texts = body["input"] if isinstance(body["input"], list) else [body["input"]]
            # out of order on purpose: the engine must put them back by index
            data = [{"index": i, "embedding": [float(i), float(len(t)), 0.5]} for i, t in enumerate(texts)][::-1]
            out = json.dumps({"data": data, "usage": {"prompt_tokens": 7}}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out))); self.end_headers()
            return self.wfile.write(out)
        if not self.path.endswith("/chat/completions") or not body.get("stream"):
            out = json.dumps({"choices": [{"message": {"role": "assistant", "content": "plain"}}]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out))); self.end_headers()
            return self.wfile.write(out)
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        def ev(delta, finish=None, **extra):
            d = dict({"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}, **extra)
            self.wfile.write(b"data: " + json.dumps(d).encode() + b"\n\n"); self.wfile.flush()
        ev({"reasoning_content": "let me think"})
        if body.get("tools"):
            ev({"tool_calls": [{"index": 0, "id": "c1", "type": "function", "function": {"name": "read_file", "arguments": "{\"pa"}}]})
            ev({"tool_calls": [{"index": 0, "function": {"arguments": "th\": \"/etc/hostname\"}"}}]})
            ev({}, "tool_calls")
        else:
            ev({"content": "hel"}); ev({"content": "lo"}); ev({}, "stop")
        self.wfile.write(b"data: " + json.dumps({"choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 3},
                         "timings": {"prompt_ms": 5.0, "predicted_ms": 7.0}}).encode() + b"\n\ndata: [DONE]\n\n")
HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


def gguf_bytes(arch="qwen3", template="{% if tools %}<tool_call>{% endif %}{{ enable_thinking }}", ctx=32768,
               file_type=15, size_label="8B", pad=64, pooling=None):
    def s(x):
        b = x.encode()
        return struct.pack("<Q", len(b)) + b

    kvs = [("general.architecture", 8, s(arch)), ("general.size_label", 8, s(size_label)),
           ("general.file_type", 4, struct.pack("<I", file_type)),
           # an array of strings (the vocabulary) and one of numbers: both must be stepped over
           ("tokenizer.ggml.tokens", 9, struct.pack("<IQ", 8, 3) + s("a") + s("bb") + s("ccc")),
           ("tokenizer.ggml.scores", 9, struct.pack("<IQ", 6, 3) + struct.pack("<3f", 1, 2, 3)),
           (arch + ".context_length", 4, struct.pack("<I", ctx))]
    if template:
        kvs.append(("tokenizer.chat_template", 8, s(template)))
    if pooling is not None:
        kvs.append((arch + ".pooling_type", 4, struct.pack("<I", pooling)))
    out = b"GGUF" + struct.pack("<IQQ", 3, 0, len(kvs))
    for k, t, v in kvs:
        out += s(k) + struct.pack("<I", t) + v
    return out + os.urandom(pad)


class Store(unittest.TestCase):
    """A scratch engine home and model store for every test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-engine-test-")
        home, mdl = os.path.join(self.tmp, "home"), os.path.join(self.tmp, "models")
        self.patches = [mock.patch.object(E, "HOME", home), mock.patch.object(E, "MODELS", mdl),
                        mock.patch.object(E, "BLOBS", os.path.join(mdl, "blobs")),
                        mock.patch.object(E, "MANIFESTS", os.path.join(mdl, "manifests")),
                        mock.patch.object(E, "PIDFILE", os.path.join(home, "engine.pid")),
                        mock.patch.object(E, "POOL", E.Pool())]
        for p in self.patches:
            p.start()
        self.addCleanup(self._clean)

    def _clean(self):
        E.POOL.close()
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def gguf(self, name="m.gguf", **kw):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(gguf_bytes(**kw))
        return p


class ReadingAGguf(Store):
    def test_metadata_and_capabilities_come_from_the_file(self):
        d = E.describe(self.gguf())
        self.assertEqual((d["family"], d["parameter_size"], d["quantization_level"], d["context_length"]),
                         ("qwen3", "8B", "Q4_K_M", 32768))
        self.assertEqual(d["capabilities"], ["completion", "tools", "thinking"])

    def test_a_projector_means_vision_and_no_template_means_no_tools(self):
        d = E.describe(self.gguf(template=""), mmproj="blobs/x")
        self.assertEqual(d["capabilities"], ["completion", "vision"])
        self.assertFalse(d["has_template"])

    def test_a_file_that_is_not_gguf_is_refused_by_pull(self):
        p = os.path.join(self.tmp, "x.gguf")
        with open(p, "wb") as f:
            f.write(b"<html>not a model</html>")
        with self.assertRaises(E.EngineError) as c:
            E.pull(p)
        self.assertIn("not a GGUF file", str(c.exception))
        self.assertEqual(E.models(), [])


class TheStore(Store):
    def test_names(self):
        self.assertEqual(E.canon("qwen3-oc:latest"), "qwen3-oc")
        self.assertEqual(E.canon("https://huggingface.co/a/b:Q4_K_M"), "hf.co/a/b:Q4_K_M")
        self.assertEqual((E.shown("qwen3-oc"), E.shown("qwen3:8b"), E.shown("hf.co/a/b:Q4_K_M")),
                         ("qwen3-oc:latest", "qwen3:8b", "hf.co/a/b:Q4_K_M"))

    def test_a_file_on_disk_is_stored_by_its_checksum_without_a_second_copy(self):
        src = self.gguf("My-Model.Q4_K_M.gguf")
        m = E.pull(src)
        sha = hashlib.sha256(open(src, "rb").read()).hexdigest()
        self.assertEqual((m["name"], m["model"]), ("my-model.q4_k_m", os.path.join("blobs", "sha256-" + sha)))
        self.assertTrue(os.path.samefile(src, E.blob_path(m["model"])))     # a hard link
        self.assertEqual([x["name"] for x in E.tags()["models"]], ["my-model.q4_k_m:latest"])

    def test_a_path_is_not_pulled_for_a_caller_on_another_machine(self):
        with self.assertRaises(E.EngineError) as c:
            E.pull(self.gguf(), local_ok=False)
        self.assertEqual(c.exception.status, 403)

    def test_an_alias_has_its_own_parameters_and_digest_and_shares_the_weights(self):
        base = E.pull(self.gguf(), name="hf.co/o/r:Q4_K_M")
        alias = E.create("r-oc", "hf.co/o/r:Q4_K_M", {"num_ctx": 16384, "temperature": 0.2})
        self.assertEqual(alias["model"], base["model"])
        self.assertNotEqual(alias["digest"], base["digest"])
        mf = E.show("r-oc:latest")["modelfile"]
        # llm_endpoints._from_blob reads the weights' identity out of this line
        self.assertTrue(re.search(r"^FROM\s+\S*?(sha256[-:][0-9a-f]{12,})", mf, re.M))
        self.assertIn("PARAMETER num_ctx 16384", mf)

    def test_weights_are_deleted_only_with_the_last_name_that_uses_them(self):
        base = E.pull(self.gguf(), name="base")
        E.create("alias", "base")
        blob = E.blob_path(base["model"])
        E.delete("base")
        self.assertTrue(os.path.exists(blob))
        E.delete("alias:latest")
        self.assertFalse(os.path.exists(blob))
        with self.assertRaises(E.EngineError) as c:
            E.delete("alias")
        self.assertEqual(c.exception.status, 404)

    def test_ollamas_downloads_are_adopted_by_hard_link(self):
        store = os.path.join(self.tmp, "ollama")
        blob = gguf_bytes()
        sha = hashlib.sha256(blob).hexdigest()
        par = json.dumps({"num_ctx": 8192, "stop": ["<|im_end|>"], "junk": 1}).encode()
        psha = hashlib.sha256(par).hexdigest()
        os.makedirs(os.path.join(store, "blobs"))
        for h, data in ((sha, blob), (psha, par)):
            with open(os.path.join(store, "blobs", "sha256-" + h), "wb") as f:
                f.write(data)
        # an alias Ollama 0.40 made itself lives in a second directory, under another host name
        for rel in ("manifests/registry.ollama.ai/library/qwen3/8b", "manifests/hf.co/o/r-GGUF/Q4_K_M",
                    "manifests-v2/ollama.com/library/r-oc/latest", "manifests-v2/hf.co/o/r-GGUF/Q4_K_M"):
            os.makedirs(os.path.dirname(os.path.join(store, rel)))
            with open(os.path.join(store, rel), "w") as f:
                json.dump({"layers": [{"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:" + sha},
                                      {"mediaType": "application/vnd.ollama.image.params",
                                       "digest": "sha256:" + psha}]}, f)
        with mock.patch.object(E, "OLLAMA_STORES", [store]):
            made = E.import_ollama()
        self.assertEqual(sorted(m["name"] for m in made), ["hf.co/o/r-GGUF:Q4_K_M", "qwen3:8b", "r-oc"])
        self.assertEqual(E.need("qwen3:8b")["params"], {"num_ctx": 8192, "stop": ["<|im_end|>"]})
        self.assertTrue(os.path.samefile(os.path.join(store, "blobs", "sha256-" + sha),
                                         E.blob_path(E.need("qwen3:8b")["model"])))


class WhatFitsThisComputer(unittest.TestCase):
    BY = {"Q4_K_M": ("Q4_K_M", 9e9), "Q3_K_M": ("Q3_K_M", 7e9), "Q8_0": ("Q8_0", 16e9), "Q2_K": ("Q2_K", 5e9)}

    def test_q4_k_m_when_it_fits_and_nothing_is_said(self):
        self.assertEqual(E.pick_quant(self.BY, (10e9, 20e9, "the 8 GB GPU")), ("Q4_K_M", ""))

    def test_a_smaller_one_when_it_does_not_and_the_reason_is_given(self):
        pick, note = E.pick_quant(self.BY, (8e9, 20e9, "the 6 GB GPU"))
        self.assertEqual(pick, "Q3_K_M")
        self.assertIn("Q4_K_M (9.0 GB) is too big for the 6 GB GPU", note)

    def test_nothing_fits_the_gpu_takes_the_usual_one_that_runs_split(self):
        pick, note = E.pick_quant(self.BY, (2e9, 12e9, "the 2 GB GPU"))
        self.assertEqual(pick, "Q4_K_M")
        self.assertIn("partly on the CPU", note)

    def test_nothing_fits_at_all_takes_the_smallest_and_warns(self):
        pick, note = E.pick_quant(self.BY, (1e9, 2e9, "2 GB of memory"))
        self.assertEqual(pick, "Q2_K")
        self.assertIn("very slow", note)

    def test_fit_words(self):
        b = (8e9, 20e9, "the 6 GB GPU")
        self.assertEqual([E.fit_word(x, b) for x in (7e9, 15e9, 30e9)],
                         ["fits", "runs partly on the CPU (slower)", "too big for the 6 GB GPU"])

    def test_memory_that_cannot_be_read_limits_nothing(self):
        with mock.patch.object(E, "gpu", return_value=("", 0)), mock.patch("os.sysconf", side_effect=ValueError):
            self.assertEqual(E.fit_budget(), (float("inf"), float("inf"), ""))
        with mock.patch.object(E, "gpu", return_value=("amd", 8 * 2 ** 30)), \
                mock.patch("os.sysconf", side_effect=lambda k: {"SC_PAGE_SIZE": 4096, "SC_PHYS_PAGES": 2 ** 23}[k]):
            well, at_all, what = E.fit_budget()
        self.assertEqual((well, at_all, what), (10 * 2 ** 30, 24 * 2 ** 30, "the 8 GB GPU"))


class FromHuggingFace(Store):
    TREE = [{"type": "file", "path": "m.Q4_K_M.gguf", "size": 10, "lfs": {"oid": "a" * 64}},
            {"type": "file", "path": "m.Q8_0.gguf", "size": 20, "lfs": {"oid": "b" * 64}},
            {"type": "file", "path": "big.Q6_K-00001-of-00002.gguf", "size": 5, "lfs": {"oid": "c" * 64}},
            {"type": "file", "path": "big.Q6_K-00002-of-00002.gguf", "size": 6, "lfs": {"oid": "d" * 64}},
            {"type": "file", "path": "mmproj-m-f16.gguf", "size": 3, "lfs": {"oid": "e" * 64}},
            {"type": "file", "path": "README.md", "size": 1}]

    def pull(self, spec, tree=None, **kw):
        got = []

        def fetch(url, dest, size=0, sha256=None, progress=None, label=""):
            got.append(url.rsplit("/", 1)[-1])
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(gguf_bytes())
            return sha256
        with mock.patch.object(E, "_json", return_value=tree or self.TREE), mock.patch.object(E, "fetch", fetch):
            return E.pull(spec, **kw), got

    def test_specs(self):
        self.assertEqual(E.parse_hf("https://huggingface.co/o/r-GGUF/tree/main:q5_k_m"), ("o/r-GGUF", "Q5_K_M", None))
        self.assertEqual(E.parse_hf("hf.co/o/r"), ("o/r", None, None))
        self.assertEqual(E.parse_hf("https://huggingface.co/o/r/resolve/main/sub/x.gguf?download=true"),
                         ("o/r", None, "sub/x.gguf"))
        with self.assertRaises(E.EngineError):
            E.parse_hf("hf.co/just-one-part")

    def test_the_asked_quant_is_fetched_with_the_projector_and_named_like_ollama_names_it(self):
        m, got = self.pull("https://huggingface.co/o/r:Q8_0")
        self.assertEqual(got, ["m.Q8_0.gguf", "mmproj-m-f16.gguf"])
        self.assertEqual((m["name"], m["model"], m["mmproj"]),
                         ("hf.co/o/r:Q8_0", os.path.join("blobs", "sha256-" + "b" * 64),
                          os.path.join("blobs", "sha256-" + "e" * 64)))
        self.assertIn("vision", m["info"]["capabilities"])

    def test_no_quant_asked_takes_q4_k_m_and_a_bare_owner_repo_is_hugging_face(self):
        m, got = self.pull("o/r")
        self.assertEqual((got[0], m["name"]), ("m.Q4_K_M.gguf", "hf.co/o/r:Q4_K_M"))

    def test_no_quant_asked_on_a_small_computer_takes_one_that_fits_and_says_so(self):
        said = []
        tree = [dict(r, size=r["size"] * 10 ** 9) for r in self.TREE[:2]]    # Q4_K_M 10 GB, Q8_0 20 GB
        tree.append({"type": "file", "path": "m.Q3_K_M.gguf", "size": 7 * 10 ** 9, "lfs": {"oid": "f" * 64}})
        with mock.patch.object(E, "fit_budget", return_value=(8e9, 9e9, "the 6 GB GPU")):
            m, got = self.pull("o/r", tree=tree, progress=said.append)
        self.assertEqual((got, m["name"]), (["m.Q3_K_M.gguf"], "hf.co/o/r:Q3_K_M"))
        self.assertTrue(any("too big for the 6 GB GPU" in str(r.get("status")) for r in said))

    def test_a_missing_quant_names_the_ones_there_are(self):
        with self.assertRaises(E.EngineError) as c:
            self.pull("o/r:Q2_K")
        self.assertIn("Q4_K_M, Q6_K, Q8_0", str(c.exception))

    def test_a_split_model_keeps_every_part_together_under_its_own_names(self):
        m, got = self.pull("o/r:Q6_K", tree=[r for r in self.TREE if "mmproj" not in r["path"]])
        self.assertEqual(got, ["big.Q6_K-00001-of-00002.gguf", "big.Q6_K-00002-of-00002.gguf"])
        d = os.path.dirname(E.blob_path(m["model"]))
        self.assertEqual(sorted(os.listdir(d)), got)
        self.assertEqual(m["size"], 2 * len(gguf_bytes()))
        E.delete(m["name"])
        self.assertFalse(os.path.exists(d))

    def test_weights_already_in_the_store_are_not_downloaded_again(self):
        tree = [dict(self.TREE[0], size=len(gguf_bytes()))]
        self.pull("o/r:Q4_K_M", tree=tree)
        _m, got = self.pull("o/r:Q4_K_M", tree=tree, name="again")
        self.assertEqual(got, [])

    def test_a_stored_copy_of_the_wrong_size_is_fetched_again_not_trusted(self):
        os.makedirs(E.BLOBS)
        blob = os.path.join(E.BLOBS, "sha256-" + "a" * 64)
        with open(blob, "wb") as f:
            f.write(b"cut short")
        whole = gguf_bytes()
        tree = [dict(self.TREE[0], size=len(whole))]
        m, got = self.pull("o/r:Q4_K_M", tree=tree)
        self.assertEqual(got, ["m.Q4_K_M.gguf"])                       # it was downloaded again
        self.assertEqual(os.path.getsize(blob), len(whole))
        self.assertIn("thinking", m["info"]["capabilities"])           # and read from the whole file
        _m, got = self.pull("o/r:Q4_K_M", tree=tree, name="again")
        self.assertEqual(got, [])                                      # the whole copy is trusted

    def test_a_finished_download_left_beside_a_stored_file_is_cleared_away(self):
        os.makedirs(E.BLOBS)
        for name in ("sha256-" + "e" * 64, "incoming-mm-" + "e" * 24):
            with open(os.path.join(E.BLOBS, name), "wb") as f:
                f.write(b"mm!")
        self.pull("o/r:Q8_0")
        self.assertEqual([f for f in os.listdir(E.BLOBS) if f.startswith("incoming")], [])

    def test_a_registry_entry_with_no_checksum_is_an_error_in_words_not_a_crash(self):
        man = {"layers": [{"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:", "size": 5}]}
        with mock.patch.object(E, "_json", return_value=man), \
                mock.patch.object(E, "fetch", side_effect=E.EngineError("download failed: HTTP 404 for x", 502)):
            with self.assertRaises(E.EngineError) as c:
                E.pull("somemodel:1b")
        self.assertEqual(c.exception.status, 502)

    def test_a_library_name_comes_from_the_publishers_gguf_repo_under_the_name_asked_for(self):
        urls = []
        with mock.patch.object(E, "_json", side_effect=lambda u, *a, **k: urls.append(u) or self.TREE[:1]), \
                mock.patch.object(E, "fetch", side_effect=lambda url, dest, *a, **k: (
                    os.makedirs(os.path.dirname(dest), exist_ok=True), open(dest, "wb").write(gguf_bytes()),
                    "a" * 64)[-1]):
            m = E.pull("qwen3:8b")
        self.assertEqual(m["name"], "qwen3:8b")
        self.assertIn("huggingface.co/api/models/Qwen/Qwen3-8B-GGUF/", urls[0])


class _Files(http.server.BaseHTTPRequestHandler):
    data, ranges, ignore_range = b"", [], False

    def log_message(self, *a):
        pass

    def do_GET(self):
        rng = self.headers.get("Range")
        type(self).ranges.append(rng)
        start = int(rng.split("=")[1].rstrip("-")) if rng and not self.ignore_range else 0
        body = self.data[start:]
        self.send_response(206 if start else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Downloading(Store):
    def setUp(self):
        super().setUp()
        _Files.data, _Files.ranges, _Files.ignore_range = os.urandom(300000), [], False
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Files)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/f.gguf"
        self.sha = hashlib.sha256(_Files.data).hexdigest()

    def test_a_partial_file_is_resumed_and_the_whole_is_verified(self):
        dest = os.path.join(self.tmp, "f")
        with open(dest + ".part", "wb") as f:
            f.write(_Files.data[:100000])
        self.assertEqual(E.fetch(self.url, dest, len(_Files.data), self.sha), self.sha)
        self.assertEqual(_Files.ranges, ["bytes=100000-"])
        self.assertEqual(open(dest, "rb").read(), _Files.data)

    def test_a_server_that_ignores_the_range_starts_over_instead_of_corrupting_the_file(self):
        _Files.ignore_range = True
        dest = os.path.join(self.tmp, "f")
        with open(dest + ".part", "wb") as f:
            f.write(b"x" * 1000)
        E.fetch(self.url, dest, len(_Files.data), self.sha)
        self.assertEqual(open(dest, "rb").read(), _Files.data)

    def test_a_wrong_checksum_is_refused_and_nothing_is_kept(self):
        dest = os.path.join(self.tmp, "f")
        with self.assertRaises(E.EngineError) as c:
            E.fetch(self.url, dest, len(_Files.data), "0" * 64)
        self.assertIn("checksum mismatch", str(c.exception))
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith("f")], [])

    def test_a_download_the_disk_cannot_hold_is_refused_before_it_starts(self):
        usage = shutil._ntuple_diskusage(100 << 30, 99 << 30, 1 << 29)      # half a GB free
        with mock.patch("shutil.disk_usage", return_value=usage):
            with self.assertRaises(E.EngineError) as c:
                E.fetch(self.url, os.path.join(self.tmp, "f"), 5 << 30, None, label="big.gguf")
        self.assertEqual(c.exception.status, 507)
        self.assertIn("not enough disk space for big.gguf", str(c.exception))
        self.assertEqual(_Files.ranges, [])                                 # nothing was asked of the server

    def test_two_downloads_never_write_one_file_and_a_finished_one_frees_it(self):
        dest = os.path.join(self.tmp, "f")
        with E._one_download(dest + ".part"):
            with self.assertRaises(E.EngineError) as c:
                E.fetch(self.url, dest, len(_Files.data), self.sha)
            self.assertEqual(c.exception.status, 409)
            self.assertIn("f is already being downloaded", str(c.exception))
            # the refused one must not have unlocked the file for a third
            with self.assertRaises(E.EngineError):
                E.fetch(self.url, dest, len(_Files.data), self.sha)
        self.assertEqual(E.fetch(self.url, dest, len(_Files.data), self.sha), self.sha)
        self.assertFalse(os.path.exists(dest + ".part.lock"))

    def test_a_caller_that_went_away_stops_the_download_and_the_partial_file_stays_for_next_time(self):
        _Files.data = os.urandom(3 << 20)
        dest, calls = os.path.join(self.tmp, "f"), []

        def progress(row):
            calls.append(row)
            raise E.Cancelled("the caller went away", 499)
        with self.assertRaises(E.Cancelled):
            E.fetch(self.url, dest, len(_Files.data), None, progress)
        self.assertEqual(len(calls), 1)
        self.assertFalse(os.path.exists(dest))
        self.assertTrue(0 < os.path.getsize(dest + ".part") < len(_Files.data))
        self.assertEqual(E.fetch(self.url, dest, len(_Files.data), hashlib.sha256(_Files.data).hexdigest()),
                         hashlib.sha256(_Files.data).hexdigest())           # and the next pull resumes it

    def test_a_gguf_url_is_pulled(self):
        _Files.data = gguf_bytes()
        m = E.pull(self.url)
        self.assertEqual(m["name"], "f")
        self.assertEqual(m["blob"], hashlib.sha256(_Files.data).hexdigest())

    def test_the_token_never_follows_a_redirect_to_another_host(self):
        req = urllib.request.Request("https://huggingface.co/o/r/resolve/main/x.gguf",
                                     headers={"Authorization": "Bearer hf_secret", "User-Agent": "t"})
        r = E._Redirect()
        away = r.redirect_request(req, None, 302, "Found", {}, "https://cdn.example.net/x?sig=1")
        same = r.redirect_request(req, None, 302, "Found", {}, "https://huggingface.co/other")
        self.assertNotIn("authorization", {k.lower() for k in away.headers})
        self.assertIn("authorization", {k.lower() for k in same.headers})

    def test_only_hugging_face_is_sent_the_token(self):
        with mock.patch.object(E, "hf_token", return_value="hf_secret"):
            self.assertIn("Authorization", E._headers("https://huggingface.co/api/models/o/r"))
            self.assertNotIn("Authorization", E._headers("https://example.com/x.gguf"))
            self.assertNotIn("Authorization", E._headers("https://registry.ollama.ai/v2/library/x/manifests/y"))


class InstallingLlamaCpp(Store):
    def release(self, members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            for name, data in members:
                ti = tarfile.TarInfo(name)
                ti.size, ti.mode = len(data), 0o755
                t.addfile(ti, io.BytesIO(data))
        return buf.getvalue()

    def install(self, members, **kw):
        arc = self.release(members)
        rel = [{"tag_name": "b9", "assets": [
            {"name": "llama-b9-bin-ubuntu-x64.tar.gz", "browser_download_url": "https://x/cpu", "size": 1},
            {"name": "llama-b9-bin-ubuntu-vulkan-x64.tar.gz", "browser_download_url": "https://x/vk",
             "size": len(arc), "digest": "sha256:" + hashlib.sha256(arc).hexdigest()}]}]
        seen = {}

        def fetch(url, dest, size=0, sha256=None, progress=None, label=""):
            seen.update(url=url, sha=sha256)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(arc)
        with mock.patch.object(E, "_json", return_value=rel), mock.patch.object(E, "fetch", fetch), \
                mock.patch.object(E, "pick_variant", return_value="ubuntu-vulkan-x64"), \
                mock.patch.object(E, "_exe", return_value="llama-server"), mock.patch.dict(os.environ):
            os.environ.pop("GNOC_LLAMA_SERVER", None)
            return E.install(**kw), seen

    def test_the_build_for_this_machine_is_fetched_with_its_published_checksum(self):
        got, seen = self.install([("llama-b9/llama-server", b"#!/bin/sh\n"), ("llama-b9/libllama.so", b"x")])
        self.assertEqual(seen["url"], "https://x/vk")
        self.assertEqual(len(seen["sha"]), 64)
        self.assertEqual((got["tag"], got["variant"]), ("b9", "ubuntu-vulkan-x64"))
        self.assertTrue(os.access(got["server"], os.X_OK))
        with mock.patch.dict(os.environ):
            os.environ.pop("GNOC_LLAMA_SERVER", None)
            self.assertEqual(E.server_path(), got["server"])

    def test_update_installs_a_newer_build_removes_the_old_one_and_is_quiet_when_current(self):
        got, _seen = self.install([("llama-b9/llama-server", b"#!/bin/sh\n")])
        old = os.path.dirname(os.path.dirname(got["server"]))
        newer = [{"tag_name": "b10", "assets": [{"name": "llama-b10-bin-ubuntu-vulkan-x64.tar.gz"}]},
                 {"tag_name": "b9", "assets": [{"name": "llama-b9-bin-ubuntu-vulkan-x64.tar.gz"}]}]

        def install(variant, tag, progress=None):
            d = os.path.join(E.HOME, "llama.cpp", f"{tag}-{variant}", f"llama-{tag}")
            os.makedirs(d)
            E._write_json(os.path.join(E.HOME, "current.json"), {"server": os.path.join(d, "llama-server"),
                                                                "tag": tag, "variant": variant})
            open(os.path.join(d, "llama-server"), "w").close()
            return {"server": os.path.join(d, "llama-server"), "tag": tag, "variant": variant}
        with mock.patch.object(E, "_json", return_value=newer), mock.patch.object(E, "install", install), \
                mock.patch.dict(os.environ):
            os.environ.pop("GNOC_LLAMA_SERVER", None)
            self.assertEqual(E.update(), {"tag": "b10", "was": "b9", "changed": True})
            self.assertFalse(os.path.exists(old))
            self.assertEqual(os.listdir(os.path.join(E.HOME, "llama.cpp")), ["b10-ubuntu-vulkan-x64"])
            self.assertEqual(E.update(), {"tag": "b10", "was": "b10", "changed": False})

    def test_an_unknown_variant_lists_the_real_ones(self):
        with self.assertRaises(E.EngineError) as c:
            self.install([("llama-server", b"")], variant="ubuntu-quantum-x64")
        self.assertIn("ubuntu-vulkan-x64", str(c.exception))

    def test_an_archive_that_writes_outside_its_directory_is_refused(self):
        with self.assertRaises(Exception):
            self.install([("../../escaped", b"x"), ("llama-server", b"")])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "home", "escaped")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escaped")))


class Translating(unittest.TestCase):
    def test_an_ollama_chat_becomes_a_llama_server_chat(self):
        body = {"messages": [
            {"role": "user", "content": "look", "images": ["QUJD"]},
            {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "f", "arguments": {"a": 1}}}]},
            {"role": "tool", "tool_name": "f", "content": "done"}],
            "options": {"num_ctx": 4096, "temperature": 0.3, "num_predict": 64, "top_k": 20},
            "format": {"type": "object"}, "think": False, "tools": [{"type": "function"}], "keep_alive": "30m"}
        r = E.to_openai(body, {"params": {"temperature": 0.9, "repeat_penalty": 1.1}})
        self.assertEqual(r["messages"][0]["content"][1]["image_url"]["url"], "data:image/jpeg;base64,QUJD")
        call = r["messages"][1]["tool_calls"][0]
        self.assertEqual((call["type"], call["function"]["arguments"]), ("function", '{"a": 1}'))
        self.assertEqual(r["messages"][2]["tool_call_id"], call["id"])       # the answer names the call it answers
        self.assertEqual((r["temperature"], r["repeat_penalty"], r["max_tokens"], r["top_k"]), (0.3, 1.1, 64, 20))
        self.assertEqual(r["response_format"]["json_schema"]["schema"], {"type": "object"})
        self.assertEqual(r["chat_template_kwargs"], {"enable_thinking": False})
        self.assertNotIn("num_ctx", r)

    def test_json_format_and_a_reasoning_depth(self):
        r = E.to_openai({"messages": [], "format": "json", "think": "high"}, {})
        self.assertEqual(r["response_format"], {"type": "json_object"})
        self.assertEqual(r["chat_template_kwargs"]["reasoning_effort"], "high")

    def test_an_embedding_model_is_told_from_a_chat_model_by_its_file(self):
        tmp = tempfile.mkdtemp(prefix="gnoc-engine-test-")
        self.addCleanup(shutil.rmtree, tmp, True)
        p = os.path.join(tmp, "e.gguf")
        with open(p, "wb") as f:
            f.write(gguf_bytes(arch="nomic-bert", template="", pooling=1))
        self.assertEqual(E.describe(p)["capabilities"], ["embedding"])
        with open(p, "wb") as f:      # a chat model that also names a pooling type is still a chat model
            f.write(gguf_bytes(pooling=1))
        self.assertIn("completion", E.describe(p)["capabilities"])

    def test_keep_alive(self):
        self.assertEqual([E.keep_alive_secs(v) for v in ("30m", "1h30m", 0, "0", -1, "45s", 12.5)],
                         [1800, 5400, 0, 0, -1, 45, 12.5])


class ApiCase(Store):
    """The engine's HTTP server over a stand-in llama-server, with two stored models."""

    def setUp(self):
        super().setUp()
        fake = os.path.join(self.tmp, "llama-server")
        with open(fake, "w") as f:
            f.write(FAKE_SERVER)
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
        self.log = os.path.join(self.tmp, "fake.log")
        env = mock.patch.dict(os.environ, {"GNOC_LLAMA_SERVER": fake, "FAKE_LOG": self.log, "GNOC_ENGINE_ARGS": ""})
        env.start()
        self.addCleanup(env.stop)
        E.pull(self.gguf(), name="base", params={"num_ctx": 8192})
        E.create("other", "base", {"num_ctx": 2048})
        self.srv = E._Server(("127.0.0.1", 0), E.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.at = f"127.0.0.1:{self.srv.server_address[1]}"

    def call(self, path, body=None, method=None, headers=None):
        req = urllib.request.Request(f"http://{self.at}{path}", json.dumps(body).encode() if body is not None else None,
                                     dict({"Content-Type": "application/json"}, **(headers or {})), method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, [json.loads(ln) for ln in r.read().splitlines() if ln.strip()]
        except urllib.error.HTTPError as e:
            with e:
                return e.code, [json.loads(e.read() or b"{}")]

    def sent(self):
        with open(self.log) as f:
            return [json.loads(ln) for ln in f]

    def chat(self, **kw):
        return self.call("/api/chat", dict({"model": "base", "messages": [{"role": "user", "content": "hi"}]}, **kw))


@unittest.skipIf(os.name == "nt", "the stand-in llama-server is a #! script")
class TheApi(ApiCase):
    def test_a_streamed_chat_has_ollamas_shape(self):
        st, rows = self.chat(options={"num_ctx": 4096})
        self.assertEqual(st, 200)
        self.assertEqual("".join(r["message"].get("thinking", "") for r in rows), "let me think")
        self.assertEqual("".join(r["message"]["content"] for r in rows), "hello")
        end = rows[-1]
        self.assertEqual((end["done"], end["done_reason"], end["prompt_eval_count"], end["eval_count"],
                          end["eval_duration"], end["model"]), (True, "stop", 11, 3, 7000000, "base:latest"))
        self.assertTrue(all(r["done"] is False for r in rows[:-1]))

    def test_think_false_keeps_reasoning_out_and_turns_it_off_in_the_template(self):
        _st, rows = self.chat(think=False)
        self.assertFalse(any(r["message"].get("thinking") for r in rows))
        self.assertEqual(self.sent()[-1]["body"]["chat_template_kwargs"], {"enable_thinking": False})

    def test_tool_call_fragments_arrive_as_one_call_with_parsed_arguments(self):
        st, rows = self.chat(stream=False, tools=[{"type": "function", "function": {"name": "read_file"}}])
        self.assertEqual((st, len(rows)), (200, 1))
        call = rows[0]["message"]["tool_calls"][0]
        self.assertEqual((call["function"]["name"], call["function"]["arguments"], call["id"]),
                         ("read_file", {"path": "/etc/hostname"}, "c1"))
        self.assertEqual(rows[0]["message"]["thinking"], "let me think")

    def test_a_prompt_over_the_window_is_a_400_carrying_what_gnoc_reads(self):
        st, rows = self.call("/api/chat", {"model": "base", "messages": [{"role": "user", "content": "OVERFLOW"}]})
        self.assertEqual(st, 400)
        self.assertIn("exceed_context_size", rows[0]["error"])
        self.assertEqual(re.search(r"n_prompt_tokens[^0-9]*(\d+)", rows[0]["error"]).group(1), "20378")

    def test_an_unknown_model_is_a_404(self):
        st, rows = self.call("/api/chat", {"model": "nope", "messages": [{"role": "user", "content": "x"}]})
        self.assertEqual((st, rows[0]["error"]), (404, "model 'nope' not found"))

    def test_the_window_is_the_requests_then_the_models_and_a_different_one_reloads(self):
        self.chat()
        self.assertEqual(self.sent()[-1]["ctx"], 8192)                # the model's own num_ctx
        self.chat()
        self.assertEqual(len({tuple(s["argv"]) for s in self.sent()}), 1)   # same runner, not reloaded
        self.chat(options={"num_ctx": 16384})
        self.assertEqual(self.sent()[-1]["ctx"], 16384)
        self.chat()                                                   # no window asked: the loaded one is kept
        self.assertEqual(self.sent()[-1]["ctx"], 16384)
        _st, ps = self.call("/api/ps")
        m = ps[0]["models"][0]
        self.assertEqual((m["name"], m["context_length"]), ("base:latest", 16384))
        self.assertEqual(m["size_vram"], int(m["size"] * 3 / 4))      # from the layer split the runner logged

    def test_a_window_is_never_asked_beyond_what_the_model_was_trained_for(self):
        self.chat(options={"num_ctx": 999999})
        self.assertEqual(self.sent()[-1]["ctx"], 32768)

    def test_one_model_is_loaded_at_a_time_and_the_idle_one_makes_room(self):
        self.chat()
        self.call("/api/chat", {"model": "other", "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(self.sent()[-1]["ctx"], 2048)
        _st, ps = self.call("/api/ps")
        self.assertEqual([m["name"] for m in ps[0]["models"]], ["other:latest"])

    def test_keep_alive_zero_with_no_prompt_unloads_and_an_empty_prompt_loads(self):
        st, rows = self.call("/api/generate", {"model": "base", "prompt": "", "keep_alive": "30m"})
        self.assertEqual((st, rows[0]["done_reason"]), (200, "load"))
        self.assertEqual(len(self.call("/api/ps")[1][0]["models"]), 1)
        st, rows = self.call("/api/generate", {"model": "base", "keep_alive": 0})
        self.assertEqual((st, rows[0]["done_reason"]), (200, "unload"))
        self.assertEqual(self.call("/api/ps")[1][0]["models"], [])

    def test_a_chat_with_keep_alive_zero_answers_and_then_unloads(self):
        _st, rows = self.chat(keep_alive=0)
        self.assertEqual("".join(r["message"]["content"] for r in rows), "hello")
        self.assertEqual(self.call("/api/ps")[1][0]["models"], [])

    def test_generate_with_an_image_answers_in_response(self):
        st, rows = self.call("/api/generate", {"model": "base", "prompt": "what is this", "images": ["QUJD"],
                                               "stream": False})
        self.assertEqual((st, rows[0]["response"], rows[0]["done"]), (200, "hello", True))
        self.assertEqual(self.sent()[-1]["body"]["messages"][-1]["content"][1]["type"], "image_url")

    def test_create_show_tags_delete_over_http(self):
        st, rows = self.call("/api/create", {"model": "third", "from": "base", "parameters": {"num_ctx": 4096}})
        self.assertEqual((st, rows[-1]), (200, {"status": "success"}))
        self.assertEqual(self.call("/api/show", {"model": "third"})[1][0]["capabilities"],
                         ["completion", "tools", "thinking"])
        self.assertIn("third:latest", [m["name"] for m in self.call("/api/tags")[1][0]["models"]])
        self.assertEqual(self.call("/api/delete", {"model": "third"}, method="DELETE")[0], 200)
        self.assertEqual(self.call("/api/delete", {"model": "third"}, method="DELETE")[0], 404)
        self.assertEqual(E.who(self.at), "gnoc")

    def test_pull_over_http_reports_progress_then_success_or_the_error(self):
        st, rows = self.call("/api/pull", {"model": self.gguf("second.gguf")})
        self.assertEqual((st, rows[-1]), (200, {"status": "success"}))
        self.assertIsNotNone(E.get("second"))
        st, rows = self.call("/api/pull", {"model": os.path.join(self.tmp, "missing.gguf")})
        self.assertIn("no such file", rows[-1]["error"])
        with self.assertRaises(E.EngineError) as c:
            E.remote_pull(self.at, os.path.join(self.tmp, "missing.gguf"), show=False)
        self.assertIn("no such file", str(c.exception))

    def test_the_openai_endpoints_pass_through_to_the_runner(self):
        st, rows = self.call("/v1/chat/completions", {"model": "base", "messages": [{"role": "user", "content": "x"}]})
        self.assertEqual((st, rows[0]["choices"][0]["message"]["content"]), (200, "plain"))
        self.assertEqual(self.sent()[-1]["path"], "/v1/chat/completions")
        self.assertEqual(self.call("/v1/models")[1][0]["data"][0]["id"], "base:latest")

    def test_a_web_page_cannot_drive_the_engine(self):
        st, _ = self.call("/api/delete", {"model": "base"}, method="DELETE", headers={"Origin": "https://evil.example"})
        self.assertEqual(st, 403)
        st, _ = self.call("/api/tags", headers={"Host": "rebound.evil.example:11434"})
        self.assertEqual(st, 403)
        self.assertIsNotNone(E.get("base"))
        self.assertEqual(self.call("/api/tags", headers={"Origin": "http://localhost:3000"})[0], 200)

    def test_an_embedding_model_gives_vectors_in_the_order_asked_and_does_not_chat(self):
        E.pull(self.gguf("emb.gguf", arch="nomic-bert", template="", pooling=1), name="emb")
        st, rows = self.call("/api/embed", {"model": "emb", "input": ["a", "bbb"]})
        self.assertEqual((st, rows[0]["embeddings"], rows[0]["prompt_eval_count"], rows[0]["model"]),
                         (200, [[0.0, 1.0, 0.5], [1.0, 3.0, 0.5]], 7, "emb:latest"))
        argv = self.sent()[-1]["argv"]
        self.assertIn("--embeddings", argv)
        self.assertNotIn("--pooling", argv)                # it carries its own
        self.assertEqual(self.call("/api/embed", {"model": "emb", "input": "one"})[1][0]["embeddings"],
                         [[0.0, 3.0, 0.5]])
        self.assertEqual(self.call("/api/embeddings", {"model": "emb", "prompt": "hey"})[1][0],
                         {"embedding": [0.0, 3.0, 0.5]})
        self.assertEqual(self.call("/v1/embeddings", {"model": "emb", "input": "hey"})[1][0]["usage"],
                         {"prompt_tokens": 7})
        for path, body in (("/api/chat", {"messages": [{"role": "user", "content": "hi"}]}),
                           ("/api/generate", {"prompt": "hi"}), ("/v1/chat/completions", {"messages": []})):
            st, rows = self.call(path, dict(body, model="emb"))
            self.assertEqual(st, 400, path)
            self.assertIn("is an embedding model", rows[0]["error"])
        self.assertEqual(self.call("/api/embed", {"model": "emb", "input": [1, 2]})[0], 400)

    def test_a_chat_model_reloads_once_to_give_vectors_and_then_does_both(self):
        self.chat()
        self.assertNotIn("--embeddings", self.sent()[-1]["argv"])
        st, rows = self.call("/api/embed", {"model": "base", "input": ["x"]})
        self.assertEqual((st, len(rows[0]["embeddings"])), (200, 1))
        argv = self.sent()[-1]["argv"]
        self.assertEqual(argv[argv.index("--embeddings"):argv.index("--embeddings") + 3],
                         ["--embeddings", "--pooling", "mean"])
        _st, rows = self.chat()                            # the same runner still chats: no reload back
        self.assertEqual("".join(r["message"]["content"] for r in rows), "hello")
        self.assertEqual(self.sent()[-1]["argv"], argv)

    def test_with_a_key_set_another_computer_must_send_it_and_this_one_need_not(self):
        with mock.patch.dict(os.environ, {"GNOC_ENGINE_KEY": "s3cret"}):
            self.assertEqual(self.call("/api/tags")[0], 200)                       # this computer: no key needed
            with mock.patch.object(E, "_is_local", return_value=False):            # as if from another computer
                st, rows = self.call("/api/tags")
                self.assertEqual(st, 401)
                self.assertIn("Authorization: Bearer", rows[0]["error"])
                self.assertEqual(self.call("/api/tags", headers={"Authorization": "Bearer wrong"})[0], 401)
                self.assertEqual(self.call("/api/tags", headers={"Authorization": "Bearer s3cret"})[0], 200)
                self.assertEqual(E.who(self.at), "gnoc")                           # the client helpers send it
        with mock.patch.object(E, "_is_local", return_value=False):
            self.assertEqual(self.call("/api/tags")[0], 200)                       # no key set: as before

    def test_a_pull_whose_caller_hangs_up_is_stopped(self):
        started, stopped = threading.Event(), threading.Event()

        def slow_pull(src, name, params, progress, local_ok):
            started.set()
            try:
                while True:
                    progress({"status": "pulling x", "total": 10, "completed": 1})
                    threading.Event().wait(0.05)
            except E.Cancelled:
                stopped.set()
                raise
        with mock.patch.object(E, "pull", slow_pull):
            host, port = self.at.split(":")
            import socket
            sk = socket.create_connection((host, int(port)))
            body = json.dumps({"model": "o/r"}).encode()
            sk.sendall(b"POST /api/pull HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                       + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
            self.assertTrue(started.wait(5))
            sk.recv(200)
            sk.close()                                      # the caller pressed Ctrl-C
            self.assertTrue(stopped.wait(10), "the pull kept running after its caller left")

    def test_a_llama_server_that_drops_the_connection_is_an_error_the_caller_can_read(self):
        self.chat()                                         # the model is loaded

        class Gone:
            def request(self, *a, **k):
                raise ConnectionResetError("reset by peer")

            def close(self):
                pass
        with mock.patch.object(E.Runner, "conn", lambda self, timeout=None: Gone()):
            for path, body in (("/api/chat", {"messages": [{"role": "user", "content": "hi"}], "stream": False}),
                               ("/api/embed", {"input": "x"}), ("/v1/chat/completions", {"messages": []})):
                if path == "/api/embed":
                    continue                                # it would reload first; covered by the two others
                st, rows = self.call(path, dict(body, model="base"))
                self.assertEqual(st, 502, path)
                self.assertIn("llama-server stopped answering for base:latest (ConnectionResetError)",
                              rows[0]["error"])
            st, rows = self.chat()                          # streamed: the error arrives as the stream's line
            self.assertIn("stopped answering", rows[-1]["error"])

    def test_a_llama_server_that_has_exited_is_not_started_even_if_its_port_answers(self):
        man = E.need("base")
        r = E.Runner(man, 4096)
        real = E.subprocess.Popen

        def exited(*a, **k):                # the process is gone before the first look at it
            proc = real(*a, **k)
            proc.wait()
            return proc
        with mock.patch.object(E.Runner, "_command", lambda self, exe: [sys.executable, "-c", "pass"]), \
                mock.patch.object(E.subprocess, "Popen", exited), \
                mock.patch.object(E.Runner, "_healthy", lambda self: True):     # something else answers its port
            with self.assertRaises(E.EngineError) as c:
                r.start()
        self.assertIn("llama-server exited while loading base", str(c.exception))

    def test_no_llama_cpp_is_said_in_words(self):
        with mock.patch.object(E, "server_path", return_value=None):
            st, rows = self.chat()
        self.assertEqual(st, 503)
        self.assertIn("gnoc engine install", rows[0]["error"])


@unittest.skipIf(os.name == "nt", "the stand-in llama-server is a #! script")
class TalkingInTheTerminal(ApiCase):
    def run_chat(self, *a, lines=()):
        out, feed = io.StringIO(), iter(lines)

        def ask(prompt):
            out.write(prompt)
            return next(feed)       # StopIteration never reaches here: the script ends with /bye
        host, port = self.at.split(":")
        with mock.patch.object(E, "start", return_value=("running", self.at)), \
                mock.patch.object(E, "addr", return_value=(host, int(port))):
            rc = E.run_chat(*a, ask=ask, out=out)
        return rc, out.getvalue()

    def test_one_question_prints_the_answer_without_the_reasoning(self):
        rc, text = self.run_chat("base", "hi")
        self.assertEqual(rc, 0)
        self.assertTrue(text.rstrip().endswith("hello"))
        self.assertNotIn("let me think", text)

    def test_a_conversation_carries_its_history_and_clear_drops_it(self):
        rc, _text = self.run_chat("base", lines=["one", "two", "/clear", "three", "/bye"])
        self.assertEqual(rc, 0)
        sent = [[m["content"] for m in s["body"]["messages"]] for s in self.sent()]
        self.assertEqual(sent, [["one"], ["one", "hello", "two"], ["three"]])

    def test_an_unknown_model_is_said_before_anything_is_started(self):
        with mock.patch.object(E, "start", side_effect=AssertionError("must not start")):
            with self.assertRaises(E.EngineError) as c:
                E.run_chat("nope", "hi")
        self.assertEqual(c.exception.status, 404)

    def test_a_model_in_ollamas_own_format_says_what_to_do(self):
        man = dict(E.need("base"), source="ollama:qwen2.5vl:7b", name="vl")
        self.assertIn("pull a GGUF build", E.Runner(man, 4096)._format_hint())
        self.assertEqual(E.Runner(dict(man, source="hf.co/o/r:Q4_K_M"), 4096)._format_hint(), "")


class TheStandaloneDownload(Store):
    def test_a_hint_is_respelled_once_however_many_layers_it_passes(self):
        for prog in ("gnoc-engine", "python3 -m gnoc engine"):
            with mock.patch.object(E, "PROG", prog):
                once = E._say("not installed yet: gnoc engine install")
                self.assertEqual(once, f"not installed yet: {prog} install")
                self.assertEqual(E._say(E._say(once)), once)

    def test_a_reply_that_is_not_json_is_the_servers_fault_and_the_callers_own_errors_stay_theirs(self):
        class Lines(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch("urllib.request.urlopen", return_value=Lines(b'{"message": {"content": "hi"}}\n{not json\n')):
            with self.assertRaises(E.EngineError) as c:
                E._ask("127.0.0.1:1", "m", [], io.StringIO())
            self.assertEqual(c.exception.status, 502)
            self.assertIn("stopped answering", str(c.exception))
        closed = io.StringIO()
        closed.close()
        with mock.patch("urllib.request.urlopen", return_value=Lines(b'{"message": {"content": "hi"}}\n')):
            with self.assertRaises(ValueError):          # a closed terminal is not "the engine stopped answering"
                E._ask("127.0.0.1:1", "m", [], closed)

    def test_help_and_hints_name_the_command_the_user_types(self):
        with mock.patch.object(E, "PROG", "gnoc-engine"):
            self.assertIn("gnoc-engine pull <source>", E._say(E.__doc__))
            self.assertNotIn("gnoc engine install", E._say("llama.cpp is not installed yet: gnoc engine install"))
        self.assertIn("gnoc engine pull <source>", E._say(E.__doc__))

    def test_the_package_is_the_engine_its_readme_and_an_installer_stamped_with_the_version(self):
        try:
            import gnoc_release as R
        except ImportError:
            self.skipTest("the release builder is not part of a shipped copy")
        rel = os.path.join(self.tmp, "rel")
        os.makedirs(os.path.join(rel, "scripts"))
        for name, body in (("scripts/gnoc_engine.py", "print('engine')\n"), ("scripts/gnoc_update.py", "# signed\n"),
                           ("LICENSE", "MIT\n")):
            with open(os.path.join(rel, name), "w") as f:
                f.write(body)
        dist = os.path.join(self.tmp, "dist")
        os.makedirs(dist)
        with mock.patch.object(R, "REL", rel), mock.patch.object(R, "VERSION", "9.9.9"):
            built = R._engine_packages(dist)
        self.assertEqual(built, {"engine": "gnoc-engine-9.9.9.tar.gz", "engine_zip": "gnoc-engine-9.9.9.zip"})
        with tarfile.open(os.path.join(dist, built["engine"])) as t:
            names = sorted(t.getnames())
            self.assertEqual(names, ["gnoc-engine-9.9.9/" + n for n in
                                     ("LICENSE", "README.md", "VERSION", "gnoc_engine.py", "gnoc_update.py",
                                      "install.sh")])   # gnoc_update.py: the release key's checks, for self-update
            self.assertTrue(t.getmember("gnoc-engine-9.9.9/install.sh").mode & 0o100)
            readme = t.extractfile("gnoc-engine-9.9.9/README.md").read().decode()
        self.assertIn("Version 9.9.9.", readme)
        self.assertNotIn("@VERSION@", readme)
        import zipfile
        with zipfile.ZipFile(os.path.join(dist, built["engine_zip"])) as z:
            self.assertIn("gnoc-engine-9.9.9/gnoc-engine.cmd", z.namelist())
            self.assertNotIn("gnoc-engine-9.9.9/install.sh", z.namelist())
            self.assertIn(b">nul", z.read("gnoc-engine-9.9.9/gnoc-engine.cmd"))


class NvidiaRunsOnCuda(unittest.TestCase):
    """2026-11-23: an RTX 5060 under WSL got the Vulkan build, which ran on llvmpipe (the CPU): "hello" stalled."""

    def setUp(self):
        import gnoc_engine
        self.E = gnoc_engine
        self.tmp = tempfile.mkdtemp(prefix="gnoc-engine-cuda-")
        self.saved = self.E.HOME
        self.E.HOME = self.tmp

    def tearDown(self):
        self.E.HOME = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_an_nvidia_card_on_linux_gets_the_cuda_build_and_its_runtime(self):
        E = self.E
        with unittest.mock.patch.object(E, "gpu", return_value=("nvidia", 16 << 30)), \
                unittest.mock.patch.object(E.sys, "platform", "linux"), \
                unittest.mock.patch.object(E.os, "name", "posix"), \
                unittest.mock.patch("platform.machine", return_value="x86_64"), \
                unittest.mock.patch.object(E, "on_android", return_value=False):
            self.assertEqual(E.pick_variant(), "ubuntu-cuda-12.8-x64")
        rel = {"tag_name": "b1", "assets": [
            {"name": "llama-b1-bin-ubuntu-cuda-12.8-x64.tar.gz", "browser_download_url": "u1", "size": 1},
            {"name": "cudart-llama-b1-bin-ubuntu-cuda-12.8-x64.tar.gz", "browser_download_url": "u2", "size": 1}]}
        fetched = []

        def unpack(arc, dest, label):
            os.makedirs(dest, exist_ok=True)
            if "cudart" in label:
                os.makedirs(os.path.join(dest, "rt"), exist_ok=True)
                open(os.path.join(dest, "rt", "libcudart.so.12"), "w").close()
            else:
                os.makedirs(os.path.join(dest, "llama-b1"), exist_ok=True)
                open(os.path.join(dest, "llama-b1", "llama-server"), "w").close()

        def fetch(url, arc, size, sha, progress, label):
            fetched.append(url)
            os.makedirs(os.path.dirname(arc), exist_ok=True)
            open(arc, "w").close()
        with unittest.mock.patch.object(E, "_releases", return_value=[rel]), \
                unittest.mock.patch.object(E, "fetch", side_effect=fetch), \
                unittest.mock.patch.object(E, "_unpack", side_effect=unpack):
            got = E.install("cuda-12.8")
        self.assertEqual(got["variant"], "ubuntu-cuda-12.8-x64")
        self.assertEqual(fetched, ["u1", "u2"])
        dirs = E._lib_dirs(got["server"])
        self.assertTrue(any(d.endswith(os.path.join("cudart", "rt")) for d in dirs), dirs)

    def _variant_on_windows(self, kind):
        E = self.E
        with unittest.mock.patch.object(E, "gpu", return_value=(kind, 16 << 30)), \
                unittest.mock.patch.object(E.sys, "platform", "win32"), \
                unittest.mock.patch.object(E.os, "name", "nt"), \
                unittest.mock.patch("platform.machine", return_value="AMD64"), \
                unittest.mock.patch.object(E, "on_android", return_value=False):
            return E.pick_variant()

    def test_an_nvidia_card_on_native_windows_gets_the_windows_cuda_build(self):
        self.assertEqual(self._variant_on_windows("nvidia"), "win-cuda-13.5-x64")
        self.assertEqual(self._variant_on_windows("nvidia"), self.E.WIN_CUDA_VARIANT)

    def test_amd_or_no_card_on_native_windows_keeps_vulkan(self):
        self.assertEqual(self._variant_on_windows("amd"), "win-vulkan-x64")
        self.assertEqual(self._variant_on_windows(""), "win-vulkan-x64")

    def test_the_cuda_runtime_archive_matches_both_real_name_shapes(self):
        # the real asset names in llama.cpp release b12728: Windows' runtime zip carries no tag, Linux's does
        E = self.E
        self.assertTrue(E._cudart_re("b12728", "win-cuda-13.5-x64").match("cudart-llama-bin-win-cuda-13.5-x64.zip"))
        self.assertTrue(E._cudart_re("b12728", "ubuntu-cuda-12.8-x64").match(
            "cudart-llama-b12728-bin-ubuntu-cuda-12.8-x64.tar.gz"))
        self.assertFalse(E._cudart_re("b12728", "win-cuda-13.5-x64").match("cudart-llama-bin-win-cuda-12.4-x64.zip"))
        self.assertFalse(E._cudart_re("b12728", "win-cuda-13.5-x64").match(
            "cudart-llama-bin-win-cuda-13.5-arm64.zip"))

    def test_the_windows_cuda_runtime_dlls_land_beside_llama_server(self):
        E = self.E
        rel = {"tag_name": "b1", "assets": [
            {"name": "llama-b1-bin-win-cuda-13.5-x64.zip", "browser_download_url": "u1", "size": 1},
            {"name": "cudart-llama-bin-win-cuda-12.4-x64.zip", "browser_download_url": "u0", "size": 1},
            {"name": "cudart-llama-bin-win-cuda-13.5-x64.zip", "browser_download_url": "u2", "size": 1}]}
        fetched = []

        def unpack(arc, dest, label):
            os.makedirs(dest, exist_ok=True)
            names = ["cudart64_13.dll", "cublas64_13.dll", "cublasLt64_13.dll"] if "cudart" in label \
                else [E._exe(), "ggml-cuda.dll"]
            for n in names:
                open(os.path.join(dest, n), "w").close()

        def fetch(url, arc, size, sha, progress, label):
            fetched.append(url)
            os.makedirs(os.path.dirname(arc), exist_ok=True)
            open(arc, "w").close()
        with unittest.mock.patch.object(E, "_releases", return_value=[rel]), \
                unittest.mock.patch.object(E, "fetch", side_effect=fetch), \
                unittest.mock.patch.object(E, "_unpack", side_effect=unpack):
            got = E.install("win-cuda-13.5-x64")
        self.assertEqual(got["variant"], "win-cuda-13.5-x64")
        self.assertEqual(fetched, ["u1", "u2"])
        here = os.listdir(os.path.dirname(got["server"]))
        for n in ("cudart64_13.dll", "cublas64_13.dll", "cublasLt64_13.dll"):
            self.assertIn(n, here)

    def test_vulkan_on_llvmpipe_is_named(self):
        E = self.E
        os.makedirs(os.path.join(self.tmp, "runners"))
        with open(os.path.join(self.tmp, "runners", "qwen3_14b.log"), "w") as f:
            f.write("ggml_vulkan: Found 1 Vulkan devices:\nggml_vulkan: 0 = llvmpipe (LLVM 19.1.7, 256 bits)\n")
        self.assertTrue(E.software_vulkan())
        with open(os.path.join(self.tmp, "runners", "qwen3_14b.log"), "w") as f:
            f.write("ggml_vulkan: 0 = NVIDIA GeForce RTX 5060 (NVIDIA) | uma: 0\n")
        self.assertFalse(E.software_vulkan())


class SharedWithAnotherComputer(unittest.TestCase):
    """2026-11-23: a second computer runs only the engine, shared behind a key, kept current (no Ollama)."""

    def setUp(self):
        import gnoc_engine
        self.E = gnoc_engine
        self.tmp = tempfile.mkdtemp(prefix="gnoc-engine-share-")
        self.saved = self.E.HOME
        self.E.HOME = self.tmp

    def tearDown(self):
        self.E.HOME = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_share_on_makes_a_private_key_listens_everywhere_and_off_undoes_it(self):
        E = self.E
        with unittest.mock.patch.dict(os.environ, {"GNOC_ENGINE_ADDR": "", "GNOC_ENGINE_KEY": ""}):
            conf = E.share(True, 11471)
            self.assertEqual(conf["addr"], "0.0.0.0:11471")
            self.assertGreaterEqual(len(conf["key"]), 24)
            self.assertEqual(os.stat(os.path.join(self.tmp, "share.json")).st_mode & 0o777, 0o600)
            self.assertEqual(E.addr(), ("0.0.0.0", 11471))
            self.assertEqual(E.engine_key(), conf["key"])
            self.assertEqual(E.share(True)["key"], conf["key"], "a second share on keeps the paired key")
            with unittest.mock.patch.object(E, "boot_autostart", return_value=(True, "x")) as boot:
                E.share(False)
            boot.assert_called_once_with(False)
            self.assertEqual(E.engine_key(), "")

    def test_a_remote_update_needs_the_key_and_a_gnoc_chat_install_updates_the_whole_app(self):
        E = self.E
        h = types.SimpleNamespace(client_address=("192.168.1.30", 5000), sent=[])
        h._send = lambda obj, status=200: h.sent.append(obj)
        with unittest.mock.patch.object(E, "engine_key", return_value=""):
            with self.assertRaises(E.EngineError):
                E.Handler.h_gnoc_update(h)
        fake_u = types.SimpleNamespace(latest_release=lambda: {"version": "2026.12.1.1", "files": {}},
                                       newer=lambda a, b: a > b)
        with unittest.mock.patch.object(E, "engine_key", return_value="k"), \
                unittest.mock.patch.dict(sys.modules, {"gnoc_update": fake_u}), \
                unittest.mock.patch.object(E, "_release_version", return_value="2026.11.23.2"), \
                unittest.mock.patch.object(E, "standalone", return_value=False), \
                unittest.mock.patch.object(E, "_update_whole_app", return_value={"updating": True, "note": "n"}) as w:
            E.Handler.h_gnoc_update(h)
        w.assert_called_once()   # part of gnoc chat: the whole app updates there (2026-11-23), not only a report
        self.assertTrue(h.sent[-1]["updating"])
        self.assertIn(("POST", "/api/gnoc/update"), E.ROUTES)


if __name__ == "__main__":
    unittest.main()


class WslShare20261123(unittest.TestCase):
    """the user 2026-11-23: "it should be able to set up the desktop using the engine". In WSL's default NAT mode
    share on printed a 172.x pairing address no other computer reaches."""

    def test_nat_wsl_prints_the_windows_steps_not_a_dead_pairing_line(self):
        import io, contextlib
        from unittest import mock
        import gnoc_engine as E
        out = io.StringIO()
        with mock.patch.object(E, "share_conf", return_value={"port": 11434, "key": "k123"}), \
                mock.patch.object(E, "wsl_networking", return_value="nat"), contextlib.redirect_stdout(out):
            E._cmd_share(["show"], lambda o: None)
        text = out.getvalue()
        self.assertIn("networkingMode=mirrored", text)
        self.assertIn("New-NetFirewallHyperVRule", text)
        self.assertIn("-LocalPorts 11434", text)
        self.assertNotIn("gnoc pair", text)

    def test_mirrored_wsl_and_plain_linux_print_the_pairing_line(self):
        import io, contextlib
        from unittest import mock
        import gnoc_engine as E
        for mode in ("mirrored", ""):
            out = io.StringIO()
            with mock.patch.object(E, "share_conf", return_value={"port": 11434, "key": "k123"}), \
                    mock.patch.object(E, "wsl_networking", return_value=mode), \
                    mock.patch.object(E, "lan_addresses", return_value=["10.0.0.7"]), contextlib.redirect_stdout(out):
                E._cmd_share(["show"], lambda o: None)
            self.assertIn("gnoc pair 10.0.0.7:11434 k123", out.getvalue(), mode)

    def test_nat_is_read_from_a_172_address_when_wslinfo_is_missing(self):
        from unittest import mock
        import gnoc_engine as E
        with mock.patch.object(E, "on_wsl", return_value=True), \
                mock.patch.object(E.subprocess, "run", side_effect=FileNotFoundError), \
                mock.patch.object(E, "lan_addresses", return_value=["172.24.80.5"]):
            self.assertEqual(E.wsl_networking(), "nat")
        with mock.patch.object(E, "on_wsl", return_value=False):
            self.assertEqual(E.wsl_networking(), "")


class PairedAppUpdate20261123(unittest.TestCase):
    """A paired computer's `gnoc update` reaches an engine that is part of gnoc chat here: the whole app installs in
    the background and the engine restarts on the NEW folder's copy, never while a chat is open here."""

    def _go(self, chat_open, installed):
        import types
        from unittest import mock
        import gnoc_engine as E
        dest = tempfile.mkdtemp()
        os.makedirs(os.path.join(dest, "scripts"))
        open(os.path.join(dest, "scripts", "gnoc_engine.py"), "w").close()
        U = types.ModuleType("gnoc_update")
        U._LAST_INSTALLED = [None]
        U.APP = os.path.dirname(os.path.dirname(os.path.abspath(E.__file__)))
        seen = {}

        def upd(args, quiet=False, paired=True, restart=True):
            seen.update(paired=paired, restart=restart)
            U._LAST_INSTALLED[0] = dest if installed else None
            return 0
        U.update = upd
        U._chat_open_besides_me = lambda: chat_open
        restarted = []
        with mock.patch.dict(sys.modules, {"gnoc_update": U}), \
                mock.patch.object(E, "_restart_soon", side_effect=lambda delay=2.0, path=None: restarted.append(path)):
            E._APP_UPDATE["running"] = False
            res = E._update_whole_app()
            for th in [x for x in __import__("threading").enumerate() if x.name == "gnoc-app-update"]:
                th.join(5)
        shutil.rmtree(dest, ignore_errors=True)
        return res, seen, restarted, dest

    def test_installs_then_restarts_on_the_new_folder(self):
        res, seen, restarted, dest = self._go(chat_open=False, installed=True)
        self.assertTrue(res["updating"])
        self.assertEqual(seen, {"paired": False, "restart": False})   # no ping-pong, and it restarts itself
        self.assertEqual(restarted, [os.path.join(dest, "scripts", "gnoc_engine.py")])

    def test_no_restart_while_a_chat_is_open_there(self):
        res, seen, restarted, _ = self._go(chat_open=True, installed=True)
        self.assertTrue(res["updating"])
        self.assertEqual(restarted, [])


class ThinkOffPrefill20261123(unittest.TestCase):
    """The Claude-4.6-Opus distills of Qwen3.5 have no enable_thinking switch and always open <think>: "think": false
    still thought 100-200 tokens and a short reply came back empty. A closed think block starts the reply instead."""
    FORCED = ("{%- if add_generation_prompt %}{{- '<|im_start|>assistant\\n<think>\\n' }}{%- endif %}")
    SWITCH = ("{%- if add_generation_prompt %}{%- if enable_thinking is defined and enable_thinking is false %}"
              "{{- '<think>\\n\\n</think>\\n\\n' }}{%- endif %}{%- endif %}")

    def _man(self, tpl):
        from unittest import mock
        import gnoc_engine as E
        name = "m-%d" % len(E._FORCED_THINK)
        E._FORCED_THINK.pop(E.blob_path(name), None)
        with mock.patch.object(E, "gguf_meta", return_value={"tokenizer.chat_template": tpl}):
            E.forced_think({"model": name})
        return {"model": name, "name": name}

    def test_only_a_template_without_the_switch_gets_the_prefill(self):
        import gnoc_engine as E
        forced, switch = self._man(self.FORCED), self._man(self.SWITCH)
        body = {"messages": [{"role": "user", "content": "hi"}], "think": False}
        self.assertEqual(E.think_prefill(body, forced), E.THINK_OFF_PREFILL)
        self.assertEqual(E.think_prefill(body, switch), "")
        self.assertEqual(E.think_prefill(dict(body, think=True), forced), "")
        self.assertEqual(E.think_prefill(dict(body, think=None), forced), "")
        req = E.to_openai(body, forced)
        self.assertEqual(req["messages"][-1], {"role": "assistant", "content": E.THINK_OFF_PREFILL})
        self.assertEqual(E.to_openai(body, switch)["messages"][-1]["role"], "user")

    def test_the_prefill_is_cut_from_the_reply_even_split_across_chunks(self):
        import gnoc_engine as E
        man = self._man(self.FORCED)
        pieces = ["<think>\n", "\n</thi", "nk>\n\nlaptop", " ok"]
        lines = [("data: " + json.dumps({"choices": [{"delta": {"content": p}}]})).encode() for p in pieces]
        lines += [b"data: " + json.dumps({"choices": [{"delta": {}, "finish_reason": "stop"}]}).encode(), b"data: [DONE]"]

        class Resp:
            status = 200

            def __iter__(self):
                return iter(lines)

        class Conn:
            def request(self, *a, **k):
                pass

            def getresponse(self):
                return Resp()

            def close(self):
                pass
        r = types.SimpleNamespace(conn=lambda timeout=0: Conn(), loaded_in=0.0)
        body = {"messages": [{"role": "user", "content": "x"}], "think": False}
        out = "".join(c["message"].get("content", "") for c in E.chat_stream(r, body, man))
        self.assertEqual(out, "laptop ok")


class LocalImages20261123(unittest.TestCase):
    """the user 2026-11-23: "for a clean install ... even the image gen should work". gnoc's engine draws with
    stable-diffusion.cpp: SDXL on a GPU with 10 GB or more, Stable Diffusion 1.5 otherwise (permissive licences)."""

    def test_the_build_is_the_newest_one_this_glibc_runs(self):
        import gnoc_engine as E
        from unittest import mock
        rels = [{"tag_name": "new", "assets": [{"name": "sd-new-bin-Linux-Ubuntu-26.04-x86_64-vulkan.zip"}]},
                {"tag_name": "old", "assets": [{"name": "sd-old-bin-Linux-Ubuntu-24.04-x86_64-vulkan.zip"}]}]
        with mock.patch.object(E.sys, "platform", "linux"), mock.patch.object(E, "_glibc", return_value=(2, 41)):
            rel, _a = E._sd_find(rels, r"Linux-Ubuntu-(\d+\.\d+)-x86_64-vulkan")
            self.assertEqual(rel["tag_name"], "old")
        with mock.patch.object(E.sys, "platform", "linux"), mock.patch.object(E, "_glibc", return_value=(2, 43)):
            self.assertEqual(E._sd_find(rels, r"Linux-Ubuntu-(\d+\.\d+)-x86_64-vulkan")[0]["tag_name"], "new")
        with mock.patch.object(E.sys, "platform", "linux"), mock.patch.object(E, "_glibc", return_value=(2, 35)):
            self.assertEqual(E._sd_find(rels, r"Linux-Ubuntu-(\d+\.\d+)-x86_64-vulkan"), (None, None))

    def test_the_model_is_sized_to_the_card(self):
        import gnoc_engine as E
        from unittest import mock
        G = 1 << 30
        with mock.patch.dict(os.environ, {"GNOC_IMAGE_MODEL": ""}), mock.patch.object(E.sys, "platform", "linux"), \
                mock.patch.object(E, "on_wsl", return_value=False):
            with mock.patch.object(E, "gpu", return_value=("nvidia", 16 * G)):
                self.assertEqual(E.pick_image_model(), "sdxl")
            with mock.patch.object(E, "gpu", return_value=("amd", 8 * G)):
                self.assertEqual(E.pick_image_model(), "sd15")
            with mock.patch.object(E, "gpu", return_value=("", 0)):
                self.assertEqual(E.pick_image_model(), "sd15")
        with mock.patch.object(E, "gpu", return_value=("nvidia", 16 * G)), mock.patch.object(E, "on_wsl", return_value=True), \
                mock.patch.object(E.sys, "platform", "linux"), mock.patch.dict(os.environ, {"GNOC_IMAGE_MODEL": ""}):
            self.assertEqual(E.pick_image_model(), "sd15")   # WSL runs the CPU build

    def test_make_image_runs_sd_cli_and_retries_with_offload(self):
        import gnoc_engine as E
        from unittest import mock
        tmp = tempfile.mkdtemp()
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            out = argv[argv.index("-o") + 1]
            if "--offload-to-cpu" in argv:
                with open(out, "wb") as f:
                    f.write(b"\x89PNG fake")
                return mock.Mock(returncode=0, stdout="", stderr="")
            return mock.Mock(returncode=1, stdout="", stderr="ErrorOutOfDeviceMemory")
        with mock.patch.object(E, "SD_HOME", tmp), mock.patch.object(E, "sd_path", return_value="/x/sd-cli"), \
                mock.patch.object(E, "image_files", return_value={"model": __file__}), \
                mock.patch.object(E, "pick_image_model", return_value="sd15"), \
                mock.patch.object(E.subprocess, "run", side_effect=fake_run):
            png, info = E.make_image("a red triangle", width=1024, height=1536)
        self.assertEqual(png, b"\x89PNG fake")
        self.assertEqual(len(calls), 2)
        self.assertIn("--offload-to-cpu", calls[1])
        self.assertEqual((info["width"], info["height"]), (512, 768))   # SD 1.5: short side 512, same shape
        shutil.rmtree(tmp, ignore_errors=True)

    def test_the_route_and_the_version_say_images(self):
        import gnoc_engine as E
        self.assertIn(("POST", "/api/gnoc/image"), E.ROUTES)
        self.assertTrue(E.version().get("images"))


class ImageClientFallback20261123(unittest.TestCase):
    def test_no_comfyui_means_gnoc_s_engine(self):
        import gnoc_image as I
        from unittest import mock
        with mock.patch.object(I, "comfy_configured", return_value=False), \
                mock.patch.object(I, "engine_generate", return_value=("/p.png", 7, 1.0)) as eg:
            self.assertEqual(I.generate("a cat")[0], "/p.png")
            eg.assert_called_once()
        with mock.patch.object(I, "comfy_configured", return_value=True), mock.patch.object(I, "up", return_value=False), \
                mock.patch.object(I, "engine_generate", return_value=("/q.png", 7, 1.0)):
            self.assertEqual(I.generate("a cat")[0], "/q.png")   # a ComfyUI that is down: the engine draws


class ExactDrawings20261123(unittest.TestCase):
    """Stable Diffusion cannot draw exact geometry or a chart; gnoc_draw does, with no extra packages."""

    def test_a_chart_from_the_sentence_is_scaled_right(self):
        import gnoc_draw as D
        data = D.pairs("draw a bar chart of these numbers as an image: mon 3, tue 5, wed 2, thu 8, fri 6; save it")
        self.assertEqual(data, [("mon", 3.0), ("tue", 5.0), ("wed", 2.0), ("thu", 8.0), ("fri", 6.0)])
        svg = D.chart_svg(data, 640, 360)
        heights = [float(h) for h in re.findall(r'<rect x="[\d.]+" y="[\d.]+" width="[\d.]+" height="([\d.]+)"', svg)]
        self.assertEqual(len(heights), 5)
        self.assertEqual(heights.index(max(heights)), 3)           # thu is the tallest bar
        self.assertAlmostEqual(heights[3] / heights[2], 4.0, 1)     # 8 is four times 2

    def test_a_shape_is_an_exact_png_without_pillow(self):
        import gnoc_draw as D
        tmp = tempfile.mkdtemp()
        path, _note = D.shape("a black circle centred on a white square, exactly, 64x64", os.path.join(tmp, "c.png"))
        with open(path, "rb") as f:
            png = f.read()
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual((int.from_bytes(png[16:20], "big"), int.from_bytes(png[20:24], "big")), (64, 64))
        rows = __import__("zlib").decompress(png[png.index(b"IDAT") + 4:png.index(b"IEND") - 8])
        centre = rows[32 * (1 + 64 * 3) + 1 + 32 * 3: 32 * (1 + 64 * 3) + 1 + 32 * 3 + 3]
        corner = rows[1:4]
        self.assertEqual((tuple(centre), tuple(corner)), ((0, 0, 0), (255, 255, 255)))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_plan_tells_charts_and_shapes_from_pictures(self):
        import gnoc_draw as D
        self.assertEqual(D.plan("bar chart: mon 3, tue 5"), "chart")
        self.assertEqual(D.plan("a simple test image: a red square, exactly"), "shape")
        self.assertEqual(D.plan("a photo of a dog on a beach"), "")
        self.assertEqual(D.plan("graph these sales: january 120, february 95, march 140, april 160"), "chart")

    def test_an_edit_changes_the_file_itself_without_imagemagick(self):
        """"make ~/Downloads/cocoa.png black and white" drew a NEW picture (image drive, 2026-11-23)."""
        import gnoc_draw as D
        from unittest import mock
        self.assertEqual(D.edit_plan("make ~/Downloads/cocoa.png black and white"), "grayscale")
        self.assertEqual(D.edit_plan("crop the sailboat picture in Pictures to a square"), "square")
        self.assertEqual(D.edit_plan("make a picture of a cat"), "")
        self.assertEqual(D.edit_plan("make a black and white picture of a cat, it should be moody"), "")
        self.assertEqual(D.edit_plan("make a picture of a rotating fan"), "")
        self.assertEqual(D.edit_plan("make it black and white"), "grayscale")
        self.assertEqual(D.edit_plan("flip it"), "flip")
        self.assertEqual(D.edit_plan("make it a little brighter"), "brighter")   # image batch 7
        self.assertEqual(D.edit_plan("make a bright picture of a beach"), "")
        tmp = tempfile.mkdtemp()
        p, _n = D.shape("a red rectangle, exactly, 64x32", os.path.join(tmp, "r.png"))
        with mock.patch.object(D.shutil, "which", return_value=None):
            D.edit(p, "square")
            D.edit(p, "grayscale")
        w, h, rows = D._read_png(p)
        self.assertEqual((w, h), (32, 32))
        self.assertTrue(all(len(set(px)) == 1 for row in rows for px in row))   # grey: r == g == b
        self.assertTrue(os.path.exists(os.path.join(tmp, "r-original.png")))
        shutil.rmtree(tmp, ignore_errors=True)


class PictureBoundaries20261123(unittest.TestCase):
    """No realistic photo of a real, identifiable person and no copy of a brand's mark: the 9B asked "what outfit are
    you wearing?" for "a realistic photo of me with the president" (image drive, 2026-11-23)."""

    def test_the_detector(self):
        from gnoc_tools.media import real_person_or_brand as R
        self.assertEqual(R("make a realistic photo of me with the president at the white house"), "person")
        self.assertEqual(R("generate the Nike logo for my shoe store"), "brand")
        for ok in ("a cartoon of a king on a throne", "a realistic photo of an apple on a table",
                   "make a logo for my coffee shop", "a watercolour of a queen bee"):
            self.assertEqual(R(ok), "", ok)

    def test_the_tool_refuses_before_drawing(self):
        import gnoc_agent as G
        ctx = G.Ctx({"sid": "t"})
        ctx.s["_turn_text"] = "make a realistic photo of a famous actor shaking my hand"
        out = G.TOOLS["generate_image"][0](ctx, brief="x" * 60, prompt="actor shaking hands")
        self.assertIn("fake photo", out)



class ImageBatch3_20261123(unittest.TestCase):
    """Image drive batch 3: exact words, video honesty, the seed, 4K."""

    def test_exact_words_are_drawn_not_generated(self):
        import gnoc_draw as D
        self.assertEqual(D.plan("write the word HELLO in big letters on an image"), "text")
        self.assertEqual(D.words_to_draw("make a sign that says \"Open 24 hours\"."), "Open 24 hours")
        self.assertEqual(D.plan("write a poem"), "")
        self.assertEqual(D.plan("make a picture of a robot reading a book"), "")
        tmp = tempfile.mkdtemp()
        p, note = D.text("write the word HELLO in big letters on an image", os.path.join(tmp, "h.svg"))
        self.assertIn(">HELLO</text>", open(p).read())
        self.assertIn('"HELLO" drawn exactly', note)
        shutil.rmtree(tmp, ignore_errors=True)

    def test_make_it_black_and_white_changes_the_last_picture(self):
        """Batch 4: the edit path itself died with NameError: os. Run it end to end on a real PNG."""
        import gnoc_agent as G
        import gnoc_draw as D
        from unittest import mock
        tmp = tempfile.mkdtemp(dir=os.path.expanduser("~"))
        try:
            p, _n = D.shape("a red rectangle, exactly, 64x32", os.path.join(tmp, "made.png"))
            ctx = G.Ctx({"sid": "edit-test"})
            ctx.s["_turn_text"] = "make it black and white"
            ctx.s["_images_made"] = [os.path.realpath(p)]
            with mock.patch.object(D.shutil, "which", return_value=None), \
                    mock.patch.object(G, "_inside_ws", return_value=tmp):
                r = G.TOOLS["generate_image"][0](ctx, brief="black and white")
            self.assertIn("image edited:", r)
            _w, _h, rows = D._read_png(p)
            self.assertTrue(all(len(set(px)) == 1 for row in rows for px in row))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_video_seed_and_4k_are_answered_honestly(self):
        import gnoc_modes as M
        self.assertIn("cannot make video", M.gnoc_howto("generate a short video of waves"))
        self.assertNotIn("cannot make video", M.gnoc_howto("make some clip art of a cat") or "")
        self.assertNotIn("cannot make video", M.gnoc_howto("a movie poster for my film") or "")
        self.assertIn("does NOT reproduce", M.gnoc_howto("what does the seed mean when you make an image"))
        self.assertIn("NOT 3840x2160", M.gnoc_howto("make a 4k image of a mountain lake"))

    def test_a_short_brief_that_answers_the_questions_is_drawn(self):
        """"4K mountain lake at sunset, photo style" (39 characters) was refused "no brief" three times."""
        import gnoc_agent as G
        import gnoc_image
        from unittest import mock
        ctx = G.Ctx({"sid": "brief-test"})
        ctx.s["_turn_text"] = "make a 4k image of a mountain lake at sunset, photo style"
        with mock.patch.object(gnoc_image, "generate", return_value=("/nonexistent/x.png", 1, 0.1)), \
                mock.patch("gnoc_tools.media._seek_references", return_value=([], [])):
            r = G.TOOLS["generate_image"][0](ctx, brief="4K mountain lake at sunset, photo style",
                                             prompt="mountain lake at sunset, photo style")
        self.assertNotIn("no brief", r)
        self.assertIn("_last_image_seed", open(os.path.join(os.path.dirname(G.__file__), "gnoc_tools",
                                                            "media.py")).read())
        ctx = G.Ctx({"sid": "brief-test-2"})
        ctx.s["_turn_text"] = "make a picture"
        self.assertIn("no brief", G.TOOLS["generate_image"][0](ctx, brief="a picture"))


class ImageBatch4_20261123(unittest.TestCase):
    """Image drive batch 4: pie charts, named people, brand-style copies."""

    def test_a_pie_chart_is_a_pie(self):
        import gnoc_draw as D
        tmp = tempfile.mkdtemp()
        p, note = D.chart("a pie chart of my budget: rent 1200, food 400, transport 150, fun 100",
                          os.path.join(tmp, "pie.svg"))
        svg = open(p).read()
        self.assertIn("pie chart of 4 values", note)
        self.assertEqual(svg.count("<path "), 4)
        self.assertIn("rent: 1200 (64.9%)", svg)
        shutil.rmtree(tmp, ignore_errors=True)

    def test_a_line_chart_is_a_line(self):
        """Image batch 6: "a line chart of my weight" was drawn as bars and called a line chart."""
        import gnoc_draw as D
        tmp = tempfile.mkdtemp()
        p, note = D.chart("a line chart of my weight: jan 82, feb 81, mar 79, apr 78", os.path.join(tmp, "l.svg"))
        svg = open(p).read()
        self.assertIn("line chart of 4 values", note)
        self.assertIn("<polyline", svg)
        self.assertEqual(svg.count("<circle"), 4)
        self.assertIn("bar chart", D.chart("a chart of sales: jan 3, feb 5", os.path.join(tmp, "b.svg"))[1])
        shutil.rmtree(tmp, ignore_errors=True)

    def test_a_picture_with_words_gets_the_exact_words_on_top(self):
        """Image batch 6: "a banner for my bakery that says FRESH BREAD" was not seen as wanting words at all."""
        import gnoc_draw as D
        self.assertEqual(D.scene_with_words("make a banner for my bakery that says FRESH BREAD, warm colours, "
                                            "landscape"), "FRESH BREAD")
        self.assertEqual(D.scene_with_words("write the word HELLO in big letters on an image"), "")   # words only
        self.assertEqual(D.words_to_draw("write the words OPEN 24/7 on an image, white on black"), "OPEN 24/7")
        self.assertEqual(D.scene_with_words("make three different book cover ideas for a mystery novel called THE "
                                            "LAST DOOR, portrait"), "THE LAST DOOR")   # image batch 7
        self.assertEqual(D.words_to_draw("make a picture of a dog named Rex"), "")
        if shutil.which("magick") or shutil.which("convert") or shutil.which("gm"):
            tmp = tempfile.mkdtemp()
            p, _n = D.shape("a red rectangle, exactly, 400x200", os.path.join(tmp, "bg.png"))
            before = open(p, "rb").read()
            self.assertTrue(D.overlay_words(p, "FRESH BREAD"))
            self.assertNotEqual(open(p, "rb").read(), before)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_four_variations_are_not_a_loop(self):
        """Image batch 6: "four variations of an owl logo" is four identical seedless calls; the repeat guard
        refused the 3rd and 4th and the turn ended empty after 14 minutes."""
        import gnoc_agent as G
        from gnoc_core import rails
        ctx = G.Ctx({"sid": "variations"})
        args = {"brief": "single minimalist owl logo, square, white background"}
        self.assertEqual([rails._repeat_note(ctx, "generate_image", args) for _ in range(4)], [None] * 4)
        for _ in range(4):
            rails._repeat_note(ctx, "generate_image", args)
        self.assertIn("8 pictures this turn", rails._repeat_note(ctx, "generate_image", args) or "")
        import inspect
        from gnoc_core import agent as A
        self.assertIn("the pictures exist even when the model never answered", inspect.getsource(A.Agent.turn))

    def test_named_people_and_brand_styles(self):
        from gnoc_tools.media import real_person_or_brand as R, possible_named_person as P
        self.assertEqual(R("make a picture of elon musk riding a horse, realistic"), "person")
        self.assertEqual(R("a coffee cup illustration in the style of a famous coffee brand's logo"), "brand")
        self.assertEqual(P("a realistic photo of jane doakes standing in a field"), "jane doakes")
        import inspect
        from gnoc_core import agent as A
        src = inspect.getsource(A.Agent)
        self.assertIn('self.s["_boundary_kind"] = _rk', src)
        # image drives 4-6: the turn note was not enough, so the rule answers before any model call
        self.assertIn("the picture rule answers this", inspect.getsource(A.Agent.turn))
        self.assertIn("the picture rule answered this turn", src)
        for ok in ("a realistic photo of a horse in a field", "a realistic photo of my dog and cat",
                   "a logo for my coffee shop", "drake the bird in a cartoon"):
            self.assertEqual((R(ok), P(ok)), ("", ""), ok)


class ImageShape20261123(unittest.TestCase):
    def test_a_16_9_request_stays_16_9_on_sd15(self):
        """1920x1080 was capped to 1536x1024 first, so a desktop wallpaper came back 768x512 (3:2)."""
        import inspect
        import textwrap
        import gnoc_engine as E
        src = inspect.getsource(E.make_image)
        body = textwrap.dedent(src[src.index("    w, h = _dims(width"):src.index("    n = max(1, min(60")])
        for (W, H), want in (((1920, 1080), (896, 512)), ((1024, 1024), (768, 768)), ((1536, 512), (1536, 512))):
            ns = {"_dims": E._dims, "width": W, "height": H, "m": {"width": 512, "height": 512}, "name": "sd15"}
            exec(body, ns)
            self.assertEqual((ns["w"], ns["h"]), want, (W, H))


class EngineSpeedQAQC20261123(unittest.TestCase):
    """Engine QAQC against Ollama (2026-11-23): an Ollama beside the engine held 6 GB of an 8 GB card, the 9B
    loaded 0/33 layers on the GPU and answered at 7 tok/s instead of 39, with nothing said, and stayed there."""

    def _runner(self, log_text):
        import gnoc_engine as E
        tmp = tempfile.mkdtemp()
        r = E.Runner.__new__(E.Runner)
        r.log = os.path.join(tmp, "r.log")
        r.man = {"size": 6 << 30}
        with open(r.log, "w") as f:
            f.write(log_text)
        self.addCleanup(shutil.rmtree, tmp, True)
        return r

    def test_a_runner_squeezed_onto_the_cpu_knows_it(self):
        import gnoc_engine as E
        from unittest import mock
        squeezed = ("common_params_fit_impl: projected to use 5264 MiB of device memory vs. 646 MiB of free device "
                    "memory\nload_tensors: offloaded 0/33 layers to GPU\n")
        whole = ("common_params_fit_impl: projected to use 5264 MiB of device memory vs. 7924 MiB of free device "
                 "memory\nload_tensors: offloaded 33/33 layers to GPU\n")
        with mock.patch.object(E, "gpu", return_value=("amd", 8 << 30)):
            self.assertEqual(self._runner(squeezed).gpu_short(), 5264)
            self.assertEqual(self._runner(whole).gpu_short(), 0)
            # too big for the card at all: nothing will free up for it, so it is not "short"
            big = squeezed.replace("5264 MiB", "9000 MiB")
            self.assertEqual(self._runner(big).gpu_short(), 0)

    def test_a_runner_with_no_gpu_device_is_reported_on_the_cpu(self):
        """Users: "the models are automatically using cpu instead of gpu". llama.cpp logs 'offloaded 33/33 layers to
        GPU' even when Vulkan found no device, so the model showed as all on the GPU with no warning."""
        import gnoc_engine as E
        from unittest import mock
        none = ("ggml_vulkan: No devices found.\nload_tensors: offloaded 33/33 layers to GPU\n")
        real = ("llama_prepare_model_devices: using device Vulkan0 (AMD Radeon RX 7700S (RADV NAVI33)) - 7924 MiB "
                "free\nload_tensors: offloaded 33/33 layers to GPU\n")
        soft = ("llama_prepare_model_devices: using device Vulkan0 (llvmpipe (LLVM 19.1.7, 256 bits)) - 0 MiB "
                "free\nload_tensors: offloaded 33/33 layers to GPU\n")
        self.assertTrue(self._runner(none).on_cpu())
        self.assertEqual(self._runner(none).size_vram(), 0)
        self.assertFalse(self._runner(real).on_cpu())
        self.assertTrue(self._runner(real).gpu_device().startswith("AMD Radeon"))
        self.assertTrue(self._runner(soft).on_llvmpipe() and self._runner(soft).on_cpu())
        r = E.Runner.__new__(E.Runner)
        r.man, r.port, r.ctx, r.embed, r.cpu_only = {"model": "sha256-x"}, 5, 4096, False, True
        cmd = r._command("/bin/llama-server")
        self.assertEqual(cmd[cmd.index("--device") + 1], "none")

    def test_runners_use_ollamas_prompt_batch(self):
        import gnoc_engine as E
        r = E.Runner.__new__(E.Runner)
        r.man, r.port, r.ctx, r.embed = {"model": "sha256-x"}, 5, 4096, False
        cmd = r._command("/bin/llama-server")
        self.assertEqual(cmd[cmd.index("-b") + 1], "512")

    def test_ps_and_the_chat_say_when_the_model_is_on_the_cpu(self):
        import inspect
        import gnoc_engine as E
        from gnoc_core import agent as A, llm
        self.assertIn("gpu_note", inspect.getsource(E.ps))
        self.assertIn("GPU memory is free again; reloading it on the GPU", inspect.getsource(E.Pool.take))
        self.assertIn("lead_gpu_note", inspect.getsource(A.Agent))
        self.assertTrue(callable(llm.lead_gpu_note))


class ContextPerGpu20261125(Store):
    """the user 2026-11-25: "can we have the harness assign context allotments based on the user's hardware? or give
    the user the choice of how much context on each gpu". auto fits the window to the GPU (llama.cpp -c 0 + fit);
    `gnoc engine context` fixes it per GPU; ngram speculation is on where the build has it."""

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"GNOC_ENGINE_CTX": "", "GNOC_ENGINE_ARGS": ""})
        env.start()
        self.addCleanup(env.stop)

    def save(self, d):
        os.makedirs(E.HOME, exist_ok=True)
        with open(E._ctx_file(), "w") as f:
            json.dump(d, f)

    def test_windows_are_read_as_tokens_or_auto(self):
        self.assertEqual([E.parse_ctx(v) for v in ("auto", "32k", "65536", "64K", "1,048", "1000", "lots", "")],
                         ["auto", 32768, 65536, 65536, None, None, None, None])

    def test_the_choice_is_per_gpu_then_every_gpu_then_auto_and_the_environment_wins(self):
        self.assertEqual(E.ctx_choice("RX 7700S"), "auto")
        self.save({"*": 32768, "RX 7700S": "64k"})
        self.assertEqual((E.ctx_choice("RX 7700S"), E.ctx_choice("RTX 3060")), (65536, 32768))
        with mock.patch.dict(os.environ, {"GNOC_ENGINE_CTX": "auto"}):
            self.assertEqual(E.ctx_choice("RX 7700S"), "auto")

    def runner(self, **kw):
        r = E.Runner({"name": "m", "model": "sha256-x"}, kw.pop("ctx", 16384), kw.pop("embed", False),
                     auto=kw.pop("auto", False))
        r.port = 5
        return r

    def test_auto_starts_llama_server_with_its_fit_and_a_fixed_window_does_not(self):
        with mock.patch.object(E, "server_supports", lambda exe, flag: True), mock.patch.object(E, "SPEC", "ngram-mod"):
            a = self.runner(auto=True)._command("/x/llama-server")
            f = self.runner(ctx=32768)._command("/x/llama-server")
            e = self.runner(embed=True)._command("/x/llama-server")
        self.assertEqual(a[a.index("-c") + 1], "0")
        self.assertEqual((a[a.index("--fit-target") + 1], a[a.index("--fit-ctx") + 1]),
                         (str(E.FIT_MARGIN), str(E.AUTO_MIN)))
        self.assertEqual(f[f.index("-c") + 1], "32768")
        self.assertNotIn("--fit-ctx", f)
        self.assertEqual(a[a.index("--spec-type") + 1], "ngram-mod")
        self.assertNotIn("--spec-type", e, "an embedding runner generates nothing to draft")

    def test_no_speculation_flag_on_a_build_that_does_not_know_it_or_when_switched_off(self):
        with mock.patch.object(E, "server_supports", lambda exe, flag: flag != "--spec-type"):
            self.assertNotIn("--spec-type", self.runner()._command("/x/llama-server"))
        with mock.patch.object(E, "server_supports", lambda exe, flag: True), mock.patch.object(E, "SPEC", "none"):
            self.assertNotIn("--spec-type", self.runner()._command("/x/llama-server"))

    def test_a_bigger_window_serves_a_smaller_request_without_a_reload(self):
        r = types.SimpleNamespace(ctx=61696, digest="d", embed=False)
        man = {"digest": "d"}
        self.assertTrue(E.Pool._serves(r, man, 16384, False))
        self.assertTrue(E.Pool._serves(r, man, 0, False))
        self.assertFalse(E.Pool._serves(r, man, 65536, False))

    def load(self, man, want=0, trained=262144, fit=True, got=61696):
        made = []

        def start(r):
            made.append((r.ctx, r.auto))
            if r.auto:
                r.ctx = got
            return r
        with mock.patch.object(E.Runner, "start", start), mock.patch.object(E, "can_fit_ctx", lambda: fit), \
                mock.patch.object(E, "gpu_name", lambda: "RX 7700S"):
            r = E.Pool._load(man, want, trained, False)
        return r, made

    def test_auto_is_the_default_and_learns_the_window_it_got(self):
        r, made = self.load({"name": "m", "model": "x"}, want=16384)
        self.assertEqual((made, r.ctx), ([(16384, True)], 61696))

    def test_a_request_bigger_than_the_gpu_holds_gets_its_window_as_ollama_would(self):
        r, made = self.load({"name": "m", "model": "x"}, want=100000)
        self.assertEqual(made, [(100000, True), (100000, False)])

    def test_the_models_own_num_ctx_or_the_saved_choice_is_fixed_and_the_cpu_gets_the_default(self):
        _r, made = self.load({"name": "m", "model": "x", "params": {"num_ctx": 8192}}, want=4096)
        self.assertEqual(made, [(8192, False)])
        self.save({"RX 7700S": 32768})
        _r, made = self.load({"name": "m", "model": "x"})
        self.assertEqual(made, [(32768, False)])
        os.remove(E._ctx_file())
        _r, made = self.load({"name": "m", "model": "x"}, fit=False)
        self.assertEqual(made, [(E.DEFAULT_CTX, False)])
        _r, made = self.load({"name": "m", "model": "x"}, trained=8192, fit=False)
        self.assertEqual(made, [(8192, False)], "never past what the model was trained for")

    def test_the_command_saves_the_window_for_this_gpu_or_all(self):
        out = io.StringIO()
        with mock.patch.object(E, "gpu_name", lambda: "RX 7700S"), mock.patch.object(E, "who", lambda *a: ""), \
                contextlib.redirect_stdout(out):
            self.assertEqual(E.main(["context", "48k"]), 0)
            self.assertEqual(E.main(["context", "auto", "--gpu", "all"]), 0)
            self.assertEqual(E.main(["context", "huge"]), 2)
            self.assertEqual(E.main(["context"]), 0)
        self.assertEqual(E.ctx_settings(), {"RX 7700S": 49152, "*": "auto"})
        self.assertIn("RX 7700S", out.getvalue())
        self.assertIn("49,152 tokens", out.getvalue())


@unittest.skipIf(os.name == "nt", "the stand-in llama-server is a #! script")
class TheAnswerSaysItsWindow20261125(ApiCase):
    def test_the_last_chunk_carries_the_window_the_model_is_loaded_with(self):
        _st, rows = self.chat()
        self.assertEqual(rows[-1]["context_length"], 8192)
        _st, rows = self.chat(options={"num_ctx": 4096})      # a smaller ask is served by the loaded window
        self.assertEqual(rows[-1]["context_length"], 8192)
        self.assertEqual(len({tuple(s["argv"]) for s in self.sent()}), 1)
