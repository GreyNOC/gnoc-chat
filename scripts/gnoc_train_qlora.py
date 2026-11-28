"""gnoc_train_qlora.py - QLoRA-distil our Opus transcripts into the local Qwen3.5 model. Runs on the DESKTOP GPU.

Input is `gnoc_distill.py sft` output (train-sft.jsonl: gnoc-shaped multi-turn tool-call sessions). Loss is on the
assistant turns only (tool results and user turns are masked), the chat template is the model's own, and the result
is exported as GGUF for `ollama create`. Launched by scripts/desktop-link/train-desktop.ps1; it can also run anywhere
with a 16 GB+ CUDA GPU:

    python gnoc_train_qlora.py --data train-sft.jsonl --out gnoc-distill [--samples 4000] [--max-seq 8192]

Memory: 9B in 4-bit is ~6 GB of weights; at --max-seq 8192, batch 1 with Unsloth gradient checkpointing it is
expected to fit 16 GB (not yet measured on this card: drop --max-seq to 6144 if it OOMs).
Abliteration may partly come back under LoRA (one unverified report): run `gnoc_bench.py` refusal cases before
adopting the result.
"""
import argparse
import json
import random


def load(path, n, max_seq_chars, seed=7):
    rows = [json.loads(line) for line in open(path, encoding="utf-8")]
    random.Random(seed).shuffle(rows)
    out = []
    for r in rows:
        msgs = []
        for m in r["messages"]:
            m = {k: v for k, v in m.items() if k in ("role", "content", "tool_calls", "name", "tool_call_id")}
            for c in m.get("tool_calls", []):
                if isinstance(c["function"].get("arguments"), str):
                    c["function"]["arguments"] = json.loads(c["function"]["arguments"] or "{}")
            msgs.append(m)
        if sum(len(json.dumps(m)) for m in msgs) <= max_seq_chars:
            out.append({"messages": msgs, "tools": r["tools"]})
        if len(out) >= n:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default="gnoc-distill")
    ap.add_argument("--base", default="huihui-ai/Huihui-Qwen3.5-9B-abliterated")
    ap.add_argument("--samples", type=int, default=4000)
    ap.add_argument("--max-seq", type=int, default=8192)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--rank", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--quant", default="q8_0", help="GGUF quantization for the export (q8_0, q4_k_m)")
    a = ap.parse_args()

    from unsloth import FastModel                     # import first: it patches transformers/trl
    from unsloth.chat_templates import train_on_responses_only
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer

    model, proc = FastModel.from_pretrained(a.base, max_seq_length=a.max_seq, load_in_4bit=True,
                                            full_finetuning=False)
    tok = getattr(proc, "tokenizer", proc)            # Qwen3.5 ships a VL processor; the text tokenizer is inside
    model = FastModel.get_peft_model(
        model, r=a.rank, lora_alpha=a.rank, lora_dropout=0, bias="none",
        finetune_vision_layers=False, finetune_language_layers=True,
        finetune_attention_modules=True, finetune_mlp_modules=True,
        use_gradient_checkpointing="unsloth", random_state=7)

    rows = load(a.data, a.samples, int(a.max_seq * 2.5))  # measured: 3 chars/token put 4.5% over the limit
    texts = []
    for r in rows:
        try:
            texts.append(tok.apply_chat_template(r["messages"], tools=r["tools"], tokenize=False))
        except Exception as e:                         # a template quirk on one sample must not stop the run
            print("skip sample:", str(e)[:120])
    print(f"training on {len(texts)} samples")
    ds = Dataset.from_dict({"text": texts})

    trainer = SFTTrainer(
        model=model, tokenizer=tok, train_dataset=ds,
        args=SFTConfig(dataset_text_field="text", max_seq_length=a.max_seq, per_device_train_batch_size=1,
                       gradient_accumulation_steps=8, num_train_epochs=a.epochs, learning_rate=a.lr,
                       warmup_steps=20, lr_scheduler_type="cosine", optim="adamw_8bit", weight_decay=0.01,
                       logging_steps=5, save_steps=200, save_total_limit=2, output_dir=a.out + "-ckpt",
                       bf16=True, seed=7, report_to="none", packing=False))
    # loss on the model's own moves only: user turns and tool results (rendered as user turns by Qwen) are masked
    trainer = train_on_responses_only(trainer, instruction_part="<|im_start|>user\n",
                                      response_part="<|im_start|>assistant\n")
    stats = trainer.train()
    print(json.dumps({"train_loss": stats.training_loss, "steps": stats.global_step}))
    model.save_pretrained(a.out + "-lora")
    tok.save_pretrained(a.out + "-lora")
    model.save_pretrained_gguf(a.out, tok, quantization_method=a.quant)
    print("GGUF written under", a.out)


if __name__ == "__main__":
    main()
