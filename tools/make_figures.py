"""Generate the report figures as PNGs into report/figures/."""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(HERE, "report", "figures")
os.makedirs(FIG, exist_ok=True)

INK = "#1b2733"
BLUE = "#2f6f9f"
GREEN = "#2e8b57"
AMBER = "#c9820a"
RED = "#b23b3b"
GREY = "#8a97a4"
LIGHT = "#eef3f7"


def box(ax, x, y, w, h, text, fc=LIGHT, ec=BLUE, tc=INK, fs=10, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                 boxstyle="round,pad=0.02,rounding_size=0.06",
                 linewidth=1.6, edgecolor=ec, facecolor=fc))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, color=tc, fontweight="bold" if bold else "normal",
            wrap=True)


def arrow(ax, x1, y1, x2, y2, color=INK, style="-|>", lw=1.6, ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                 mutation_scale=14, linewidth=lw, color=color, linestyle=ls,
                 shrinkA=2, shrinkB=2))


# -- Figure 1: architecture --------------------------------------------------
def architecture():
    fig, ax = plt.subplots(figsize=(9.2, 5.4))
    ax.set_xlim(0, 10); ax.set_ylim(0, 6.2); ax.axis("off")

    box(ax, 0.3, 2.4, 2.1, 1.3, "Recursive\nresolver\n(SECDNS client)",
        fc="#e7f0f8", ec=BLUE, bold=True)
    box(ax, 7.6, 2.4, 2.1, 1.3, "Authoritative\nserver\n(SECDNS)",
        fc="#e7f0f8", ec=BLUE, bold=True)

    # trust anchor
    box(ax, 0.3, 5.0, 2.1, 0.9, "Pinned trust anchor\n(root KSK analogue)",
        fc="#fdف3e0".replace("ف", "f"), ec=AMBER, fs=9)
    arrow(ax, 1.35, 5.0, 1.35, 3.7, color=AMBER, ls=(0, (4, 2)))

    # Gate A
    box(ax, 3.1, 4.6, 3.8, 1.0,
        "Gate A — Authority\nfetch + verify signed service descriptor\n"
        "anchor → zone key → descriptor", fc="#eafaf0", ec=GREEN, fs=9)
    arrow(ax, 2.4, 3.4, 3.1, 4.9, color=GREEN)
    arrow(ax, 6.9, 4.9, 7.6, 3.4, color=GREEN, style="<|-")

    # Gate B
    box(ax, 3.1, 3.0, 3.8, 0.95,
        "Gate B — Channel\nTLS 1.3 + DANE-style SPKI pin",
        fc="#eef3f7", ec=BLUE, fs=9)
    arrow(ax, 2.4, 3.1, 3.1, 3.4, color=BLUE)
    arrow(ax, 6.9, 3.4, 7.6, 3.1, color=BLUE, style="<|-")

    # Gate C
    box(ax, 3.1, 1.5, 3.8, 1.0,
        "Gate C — Validation firewall\nquestion binding · bailiwick · "
        "work budget\n(before cache insert)", fc="#fdeeee", ec=RED, fs=9)
    arrow(ax, 5.0, 3.0, 5.0, 2.5, color=RED)

    box(ax, 0.3, 0.3, 2.1, 0.95, "Validated\ncache", fc=LIGHT, ec=GREY, fs=9)
    arrow(ax, 3.1, 2.0, 2.4, 1.0, color=RED)

    box(ax, 7.6, 4.6, 2.1, 1.0, "Zone data\n+ signing keys", fc=LIGHT,
        ec=GREY, fs=9)
    arrow(ax, 8.65, 4.6, 8.65, 3.7, color=GREY)

    ax.text(5.0, 0.15, "Bootstrap (Gate A) runs over an untrusted plain channel; "
            "data (Gate B/C) runs inside TLS 1.3.",
            ha="center", va="bottom", fontsize=8.5, color=GREY, style="italic")
    ax.set_title("SECDNS TriGate architecture — recursive ↔ authoritative hop",
                 fontsize=12, color=INK, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "architecture.png"), dpi=170,
                bbox_inches="tight")
    plt.close(fig)


# -- Figure 2: protocol sequence --------------------------------------------
def sequence():
    fig, ax = plt.subplots(figsize=(9.2, 6.0))
    ax.set_xlim(0, 10); ax.set_ylim(0, 10); ax.axis("off")
    rx, sx = 1.6, 8.0
    for x, label in [(rx, "Resolver"), (sx, "Authoritative server")]:
        ax.plot([x, x], [0.5, 9.2], color=GREY, lw=1, ls=(0, (3, 3)))
        box(ax, x - 1.1, 9.1, 2.2, 0.7, label, fc="#e7f0f8", ec=BLUE, bold=True,
            fs=10)

    def msg(y, x1, x2, text, color=INK, dashed=False):
        arrow(ax, x1, y, x2, y, color=color,
              ls=(0, (4, 2)) if dashed else "-")
        mid = (x1 + x2) / 2
        ax.text(mid, y + 0.12, text, ha="center", va="bottom", fontsize=8.6,
                color=color)

    ax.text(5, 8.7, "Gate A — Authority (untrusted plain channel)",
            ha="center", fontsize=9.5, color=GREEN, fontweight="bold")
    msg(8.3, rx, sx, "descriptor_request(zone)", GREEN)
    msg(7.7, sx, rx, "DescriptorBundle (delegation + descriptor)", GREEN, True)
    ax.text(rx - 1.15, 7.2, "verify anchor→zone→descriptor;\ncheck validity",
            ha="left", fontsize=8, color=GREEN)

    ax.text(5, 6.6, "Gate B — Channel (TLS 1.3)", ha="center", fontsize=9.5,
            color=BLUE, fontweight="bold")
    msg(6.2, rx, sx, "TLS 1.3 ClientHello ...", BLUE)
    msg(5.6, sx, rx, "... certificate, Finished", BLUE, True)
    ax.text(rx - 1.15, 5.0, "require spki_sha256(cert)\n== descriptor.spki_pin",
            ha="left", fontsize=8, color=BLUE)

    ax.text(5, 4.3, "Gate C — Validated query/answer (inside TLS)",
            ha="center", fontsize=9.5, color=RED, fontweight="bold")
    msg(3.9, rx, sx, "SDNS QUERY {nonce, DNS question}", INK)
    msg(3.3, sx, rx, "SDNS ANSWER {nonce, DNS answer}", INK, True)
    ax.text(rx - 1.15, 2.4,
            "check nonce; parse within budget;\nquestion binding; bailiwick;\n"
            "then insert into cache", ha="left", fontsize=8, color=RED)

    ax.set_title("SECDNS message flow (one cold resolution)", fontsize=12,
                 color=INK, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "sequence.png"), dpi=170, bbox_inches="tight")
    plt.close(fig)


# -- Figure 3: resolver state machine ---------------------------------------
def state_machine():
    fig, ax = plt.subplots(figsize=(9.2, 2.8))
    ax.set_xlim(0, 12); ax.set_ylim(0, 3); ax.axis("off")
    states = ["START", "FETCH\nDESC", "VERIFY\nCHAIN", "TLS +\nPIN",
              "QUERY", "VALIDATE", "CACHE"]
    xs = [0.3 + i * 1.65 for i in range(len(states))]
    for x, s in zip(xs, states):
        box(ax, x, 1.2, 1.35, 0.9, s, fc="#eef3f7", ec=BLUE, fs=8.5, bold=True)
    for i in range(len(states) - 1):
        arrow(ax, xs[i] + 1.35, 1.65, xs[i + 1], 1.65, color=INK)
    # failure sink
    box(ax, 4.2, 0.1, 2.4, 0.7, "REJECT (typed reason)", fc="#fdeeee", ec=RED,
        fs=8.5, bold=True)
    for i in (2, 3, 5):
        arrow(ax, xs[i] + 0.67, 1.2, 5.4, 0.8, color=RED, ls=(0, (3, 2)))
    ax.set_title("Resolver state machine (fail-closed in strict mode)",
                 fontsize=11.5, color=INK, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "state_machine.png"), dpi=170,
                bbox_inches="tight")
    plt.close(fig)


# -- Figure 4: latency results ----------------------------------------------
def latency_chart():
    with open(os.path.join(HERE, "lab", "results", "bench.json")) as f:
        b = json.load(f)
    labels = ["Plain DNS\n(UDP)", "SECDNS warm\n(pooled)", "SECDNS cold\n(handshake)"]
    vals = [b["plain_udp"]["median_ms"], b["secdns_warm"]["median_ms"],
            b["secdns_cold"]["median_ms"]]
    fig, ax = plt.subplots(figsize=(7.4, 4.0))
    bars = ax.bar(labels, vals, color=[GREY, GREEN, BLUE], width=0.6)
    ax.set_ylabel("Median latency (ms, log scale)")
    ax.set_yscale("log")
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, v, f"{v:.3f} ms",
                ha="center", va="bottom", fontsize=9, color=INK)
    ax.set_title("Per-query latency on localhost (N=%d)" % b["iterations"],
                 fontsize=12, color=INK, fontweight="bold")
    ax.grid(axis="y", ls=":", alpha=0.4)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "latency.png"), dpi=170, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    architecture()
    sequence()
    state_machine()
    latency_chart()
    print("figures written to", FIG)
    print(os.listdir(FIG))
