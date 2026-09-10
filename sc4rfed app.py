#!/usr/bin/env python3
"""
SEARCHER — VÉRIFICATEUR DE MOT DE PASSE
Interface façon hacker/terminal avec pluie Matrix, analyse de robustesse
locale ET vérification de fuite via l'API "Have I Been Pwned" (k-anonymity).

Confidentialité :
  Le mot de passe n'est JAMAIS envoyé en clair sur le réseau. On calcule
  son empreinte SHA-1, on n'envoie QUE les 5 premiers caractères de cette
  empreinte à l'API (technique dite "k-anonymity"), et on compare la fin
  du hash localement parmi les résultats renvoyés. Voir :
  https://haveibeenpwned.com/API/v3#PwnedPasswords

Usage : python password_checker.py
Compilation en exécutable : voir README_BUILD.txt
"""

import tkinter as tk
from tkinter import font as tkfont
import hashlib
import random
import string
import threading
import urllib.request
import urllib.error

# ----------------------------- CONFIG -----------------------------
WIDTH, HEIGHT = 980, 680
BG_COLOR = "#000000"
FG_COLOR = "#00FF41"
FG_DIM = "#0B6E1A"
FG_ACCENT = "#39FF14"
FG_WARN = "#FFB000"
FG_DANGER = "#FF3131"
FONT_NAME = "Consolas"
MATRIX_CHARS = string.ascii_uppercase + string.digits + "アイウエオカキクケコサシスセソタチツテト"

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"

BANNER = r"""
 ███████╗███████╗ █████╗ ██████╗  ██████╗██╗  ██╗███████╗██████╗
 ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
 ███████╗█████╗  ███████║██████╔╝██║     ███████║█████╗  ██████╔╝
 ╚════██║██╔══╝  ██╔══██║██╔══██╗██║     ██╔══██║██╔══╝  ██╔══██╗
 ███████║███████╗██║  ██║██║  ██║╚██████╗██║  ██║███████╗██║  ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
      P A S S W O R D   S E C U R I T Y   A U D I T
"""

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "azerty", "111111",
    "abc123", "letmein", "admin", "welcome", "monkey", "dragon",
    "iloveyou", "sunshine", "master", "football", "123123", "000000",
    "password1", "1234567890", "motdepasse", "soleil", "bonjour",
}


class MatrixRain(tk.Canvas):
    def __init__(self, master, width, height, **kwargs):
        super().__init__(master, width=width, height=height,
                          bg=BG_COLOR, highlightthickness=0, **kwargs)
        self.width = width
        self.height = height
        self.font_size = 14
        self.columns = width // self.font_size
        self.drops = [random.randint(-30, 0) for _ in range(self.columns)]
        self.after(0, self.animate)

    def animate(self):
        self.delete("all")
        for i in range(self.columns):
            x = i * self.font_size
            y = self.drops[i] * self.font_size
            char = random.choice(MATRIX_CHARS)
            color = FG_ACCENT if random.random() > 0.9 else FG_DIM
            self.create_text(x, y, text=char, fill=color,
                              font=(FONT_NAME, self.font_size), anchor="n")
            if y > self.height and random.random() > 0.975:
                self.drops[i] = 0
            else:
                self.drops[i] += 1
        self.after(50, self.animate)


# --------------------------------------------------------------
# Analyse de robustesse locale (aucune donnée envoyée sur le réseau)
# --------------------------------------------------------------
def analyze_strength(pwd: str):
    """Retourne (score 0-4, label, [conseils])."""
    if not pwd:
        return 0, "—", []

    length = len(pwd)
    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_symbol = any(c in string.punctuation for c in pwd)
    classes = sum([has_lower, has_upper, has_digit, has_symbol])

    tips = []
    score = 0

    if length >= 8:
        score += 1
    else:
        tips.append("Utilise au moins 8 caractères (12+ recommandé).")
    if length >= 12:
        score += 1
    if classes >= 3:
        score += 1
    else:
        tips.append("Mélange majuscules, minuscules, chiffres et symboles.")
    if classes == 4 and length >= 12:
        score += 1

    # Pénalités
    lowered = pwd.lower()
    if lowered in COMMON_PASSWORDS:
        score = 0
        tips.insert(0, "Ce mot de passe est extrêmement courant, à bannir.")
    if any(seq in lowered for seq in ("1234", "abcd", "qwerty", "azerty")):
        score = max(0, score - 1)
        tips.append("Évite les séquences prévisibles (1234, abcd, qwerty...).")
    if len(set(pwd)) <= max(1, length // 3):
        score = max(0, score - 1)
        tips.append("Trop de caractères répétés.")

    score = max(0, min(4, score))
    labels = {
        0: ("CRITIQUE", FG_DANGER),
        1: ("FAIBLE", FG_DANGER),
        2: ("MOYEN", FG_WARN),
        3: ("BON", FG_ACCENT),
        4: ("EXCELLENT", FG_ACCENT),
    }
    label, color = labels[score]
    if not tips and score >= 3:
        tips.append("Robustesse correcte. Utilise un gestionnaire de mots de passe unique par site.")
    return score, (label, color), tips


def check_hibp(pwd: str, timeout=8):
    """
    Vérifie via l'API Have I Been Pwned (k-anonymity) si le mot de passe
    apparaît dans des fuites connues. Retourne (nb_occurrences, erreur).
    Seuls les 5 premiers caractères du hash SHA-1 quittent la machine.
    """
    sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        req = urllib.request.Request(
            HIBP_RANGE_URL.format(prefix),
            headers={"User-Agent": "SEARCHER-Password-Checker"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        return None, f"Connexion impossible à l'API HIBP ({e})."
    except Exception as e:
        return None, f"Erreur inattendue : {e}"

    for line in body.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1]), None
    return 0, None


class PasswordChecker(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG_COLOR)
        self.master = master
        self.pack(fill="both", expand=True)

        self.mono = tkfont.Font(family=FONT_NAME, size=12)
        self.mono_bold = tkfont.Font(family=FONT_NAME, size=12, weight="bold")
        self.show_pwd = tk.BooleanVar(value=False)

        self.matrix = MatrixRain(self, WIDTH, HEIGHT)
        self.matrix.place(x=0, y=0)

        self.panel = tk.Frame(self, bg="#001a00")
        self.panel.place(x=30, y=25, width=WIDTH - 60, height=HEIGHT - 70)

        # --- Sortie terminal ---
        self.output = tk.Text(
            self.panel, bg="#001a00", fg=FG_COLOR, insertbackground=FG_COLOR,
            font=self.mono, wrap="word", bd=0, highlightthickness=0, height=18
        )
        self.output.pack(fill="both", expand=True, padx=14, pady=(14, 8))
        for tag, color in [("accent", FG_ACCENT), ("dim", FG_DIM),
                            ("warn", FG_WARN), ("danger", FG_DANGER)]:
            self.output.tag_configure(tag, foreground=color)

        # --- Barre de force ---
        self.strength_canvas = tk.Canvas(
            self.panel, height=18, bg="#001a00", highlightthickness=0
        )
        self.strength_canvas.pack(fill="x", padx=14, pady=(0, 10))

        # --- Ligne de saisie ---
        input_row = tk.Frame(self.panel, bg="#001a00")
        input_row.pack(fill="x", padx=14, pady=(0, 6))

        tk.Label(input_row, text="mot de passe >", bg="#001a00",
                 fg=FG_ACCENT, font=self.mono_bold).pack(side="left")

        self.entry = tk.Entry(
            input_row, bg="#001a00", fg=FG_COLOR, insertbackground=FG_COLOR,
            font=self.mono_bold, bd=0, highlightthickness=0, show="•"
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=(8, 8))
        self.entry.bind("<KeyRelease>", self.on_type)
        self.entry.bind("<Return>", lambda e: self.run_full_check())
        self.entry.focus_set()

        tk.Checkbutton(
            input_row, text="afficher", variable=self.show_pwd,
            command=self.toggle_visibility, bg="#001a00", fg=FG_DIM,
            selectcolor="#001a00", activebackground="#001a00",
            activeforeground=FG_ACCENT, font=self.mono
        ).pack(side="left")

        # --- Boutons ---
        btn_row = tk.Frame(self.panel, bg="#001a00")
        btn_row.pack(fill="x", padx=14, pady=(0, 14))

        self.check_btn = tk.Button(
            btn_row, text="[ VÉRIFIER SUR HIBP ]", command=self.run_full_check,
            bg="#001a00", fg=FG_ACCENT, activebackground="#003300",
            activeforeground=FG_ACCENT, font=self.mono_bold, bd=1,
            relief="solid", highlightbackground=FG_DIM, cursor="hand2"
        )
        self.check_btn.pack(side="left")

        self.gen_btn = tk.Button(
            btn_row, text="[ GÉNÉRER UN MOT DE PASSE SOLIDE ]", command=self.generate_password,
            bg="#001a00", fg=FG_DIM, activebackground="#003300",
            activeforeground=FG_ACCENT, font=self.mono, bd=1,
            relief="solid", highlightbackground=FG_DIM, cursor="hand2"
        )
        self.gen_btn.pack(side="left", padx=(10, 0))

        self.title_label = tk.Label(
            self, text="[ AUDIT LOCAL + BASE DE FUITES HIBP — AUCUN MOT DE PASSE EN CLAIR N'EST TRANSMIS ]",
            bg=BG_COLOR, fg=FG_ACCENT, font=("Consolas", 10, "bold")
        )
        self.title_label.place(x=30, y=4)

        self.boot_sequence()

    # ---------------------------------------------------------------
    def toggle_visibility(self):
        self.entry.config(show="" if self.show_pwd.get() else "•")

    def println(self, text, tag=None):
        self.output.insert("end", text + "\n", tag)
        self.output.see("end")

    def boot_sequence(self):
        self.output.insert("end", BANNER + "\n", "accent")
        self.println("Tape un mot de passe puis clique sur VÉRIFIER SUR HIBP,", "dim")
        self.println("ou appuie sur Entrée.\n", "dim")
        self.draw_strength_bar(0, ("—", FG_DIM))

    def on_type(self, event=None):
        pwd = self.entry.get()
        score, (label, color), _ = analyze_strength(pwd)
        self.draw_strength_bar(score, (label, color))

    def draw_strength_bar(self, score, label_info):
        label, color = label_info
        self.strength_canvas.delete("all")
        w = self.strength_canvas.winfo_width() or (WIDTH - 90)
        segment = w / 4
        for i in range(4):
            fill = color if i < score else "#0a2a0a"
            self.strength_canvas.create_rectangle(
                i * segment + 2, 2, (i + 1) * segment - 2, 16,
                fill=fill, outline="#0a2a0a"
            )
        self.strength_canvas.create_text(
            w - 4, 9, text=label, fill=color, font=self.mono_bold, anchor="e"
        )

    # ---------------------------------------------------------------
    def run_full_check(self):
        pwd = self.entry.get()
        if not pwd:
            self.println("Entre un mot de passe d'abord.", "warn")
            return

        score, (label, color), tips = analyze_strength(pwd)
        self.draw_strength_bar(score, (label, color))

        self.println("─" * 60, "dim")
        self.println(f"Analyse locale : {label}", "accent" if score >= 3 else ("warn" if score == 2 else "danger"))
        for t in tips:
            self.println(f"  → {t}", "dim")

        self.println("Interrogation de la base Have I Been Pwned...", "dim")
        self.check_btn.config(state="disabled", text="[ VÉRIFICATION EN COURS... ]")
        self.output.update()

        threading.Thread(target=self._hibp_worker, args=(pwd,), daemon=True).start()

    def _hibp_worker(self, pwd):
        count, error = check_hibp(pwd)
        self.master.after(0, self._hibp_done, count, error)

    def _hibp_done(self, count, error):
        self.check_btn.config(state="normal", text="[ VÉRIFIER SUR HIBP ]")
        if error:
            self.println(f"⚠ {error}", "warn")
            self.println("Vérifie ta connexion internet et réessaie.", "dim")
            return

        if count and count > 0:
            self.println(
                f"⚠ FUITE DÉTECTÉE : ce mot de passe apparaît {count:,} fois "
                f"dans des bases de données compromises.".replace(",", " "),
                "danger",
            )
            self.println("  → Change-le immédiatement partout où tu l'utilises.", "danger")
        else:
            self.println("✓ Aucune fuite connue trouvée pour ce mot de passe.", "accent")
            self.println("  (Cela ne garantit pas qu'il soit fort, seulement qu'il n'a pas fuité.)", "dim")
        self.println("─" * 60 + "\n", "dim")

    # ---------------------------------------------------------------
    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        pwd = "".join(random.SystemRandom().choice(alphabet) for _ in range(16))
        self.entry.config(show="•")
        self.show_pwd.set(False)
        self.entry.delete(0, "end")
        self.entry.insert(0, pwd)
        self.println(f"Mot de passe généré (16 caractères). Coche 'afficher' pour le voir.", "dim")
        self.on_type()


def main():
    root = tk.Tk()
    root.title("SEARCHER — Vérificateur de mot de passe")
    root.geometry(f"{WIDTH}x{HEIGHT}")
    root.resizable(False, False)
    root.configure(bg=BG_COLOR)
    PasswordChecker(root)
    root.mainloop()


if __name__ == "__main__":
    main()
