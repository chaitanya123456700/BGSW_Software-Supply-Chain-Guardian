"""Serve already-cached Transformers weights through the gateway's local chat protocol."""
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def validate_request(body, model):
    if not isinstance(body, dict) or body.get("model") != model or body.get("stream") is not False:
        raise ValueError("Use the configured model with stream=false")
    messages = body.get("messages")
    schema = body.get("format")
    if not isinstance(schema, dict) or not isinstance(messages, list) or not 1 <= len(messages) <= 4:
        raise ValueError("Bounded messages and a JSON schema are required")
    cleaned = []
    for message in messages:
        if (not isinstance(message, dict) or message.get("role") not in {"system", "user"}
                or not isinstance(message.get("content"), str) or len(message["content"]) > 24000):
            raise ValueError("Unsupported message")
        cleaned.append({"role": message["role"], "content": message["content"]})
    instruction = "Return only a JSON object matching this schema. Preserve supplied identifiers exactly. " + json.dumps(schema)
    if len(instruction) > 24000:
        raise ValueError("Schema is too large")
    cleaned.insert(0, {"role": "system", "content": instruction})
    return cleaned


class CachedModel:
    def __init__(self, name):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        torch.set_num_threads(4)
        self.tokenizer = AutoTokenizer.from_pretrained(name, local_files_only=True, trust_remote_code=False)
        self.model = AutoModelForCausalLM.from_pretrained(name, local_files_only=True, trust_remote_code=False, dtype="auto")
        self.model.eval()

    def generate(self, messages):
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
        inputs = self.tokenizer(text, return_tensors="pt")
        if inputs["input_ids"].shape[-1] > 6000:
            raise ValueError("Local context limit exceeded")
        with self.torch.inference_mode():
            output = self.model.generate(**inputs, max_new_tokens=512, max_time=16, do_sample=False,
                                         pad_token_id=self.tokenizer.eos_token_id)
        return self.tokenizer.decode(output[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)


def make_server(model, generator, *, port=11434):
    busy = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Prompts, headers and model outputs never enter access logs.

        def reply(self, status, value):
            raw = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            if self.path == "/api/tags":
                self.reply(200, {"models": [{"name": model}], "backend": "transformers_cached"})
            else:
                self.reply(404, {"error": "Not found"})

        def do_POST(self):
            if self.path != "/api/chat":
                return self.reply(404, {"error": "Not found"})
            if self.headers.get("Origin"):
                return self.reply(403, {"error": "Browser-origin requests are disabled"})
            if not busy.acquire(blocking=False):
                return self.reply(503, {"error": "Local model is busy"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    return self.reply(413, {"error": "Request size limit"})
                self.connection.settimeout(5)
                messages = validate_request(json.loads(self.rfile.read(length)), model)
                content = generator(messages)
                self.reply(200, {"model": model, "backend": "transformers_cached", "done": True,
                                 "message": {"role": "assistant", "content": content}})
            except (ValueError, TypeError, TimeoutError):
                self.reply(400, {"error": "Invalid local generation request"})
            except Exception:
                self.reply(500, {"error": "Local generation failed"})
            finally:
                busy.release()

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description="Serve a cached local model; never download weights or remote code")
    parser.add_argument("--model", default="Qwen/Qwen3-0.6B")
    parser.add_argument("--port", type=int, default=11434)
    args = parser.parse_args()
    cached = CachedModel(args.model)
    server = make_server(args.model, cached.generate, port=args.port)
    print(f"Cached local model {args.model} ready at http://127.0.0.1:{args.port}; no downloads", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
