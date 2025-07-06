print("🛠️  N.i.c.h.o...")

import tkinter as tk
from tkinter import scrolledtext
import os
from dotenv import load_dotenv
from openai import OpenAI

# Load environment variables
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")

if not api_key or not api_key.startswith("sk-"):
    raise RuntimeError("🚨 OpenAI API Key is missing or invalid! Check your `.env` file.")

client = OpenAI(api_key=api_key)

def ask_nicho(prompt, history):
    history.append({"role": "user", "content": prompt})
    try:
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=history
        )
        reply = resp.choices[0].message.content
    except Exception as e:
        reply = f"[Error] {e}"
    history.append({"role": "assistant", "content": reply})
    return reply

class NichoChatApp:
    def __init__(self, root):
        self.root = root
        root.title("NichoGPT Chat")
        root.geometry("600x500")

        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        entry_frame = tk.Frame(root)
        entry_frame.pack(fill=tk.X, padx=10, pady=(0,10))

        self.user_entry = tk.Entry(entry_frame, font=("Arial", 14))
        self.user_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        self.user_entry.bind("<Return>", self.on_send)

        tk.Button(entry_frame, text="Send", command=self.on_send).pack(side=tk.LEFT)

        self.history = [
            {"role": "system",
             "content": "You are NichoGPT, a friendly, witty assistant who helps with coding and creative ideas."}
        ]
        self._append_text("NichoGPT", "CHUR BRO! Whats?")

    def _append_text(self, speaker, text):
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, f"{speaker}: {text}\n")
        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

    def on_send(self, event=None):
        user_msg = self.user_entry.get().strip()
        if not user_msg:
            return

        self._append_text("You", user_msg)
        self.user_entry.delete(0, tk.END)

        if user_msg.lower() in ("exit", "quit"):
            self._append_text("NichoGPT", "Goodbye! 👋")
            self.root.after(500, self.root.destroy)
            return

        reply = ask_nicho(user_msg, self.history)
        self._append_text("NichoGPT", reply)

if __name__ == "__main__":
    root = tk.Tk()
    NichoChatApp(root)
    root.mainloop()

