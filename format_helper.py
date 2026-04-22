import time
def fmt_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


def progress(msg: str, end: str = "\n"):
    ts = time.strftime("%H:%M:%S")
    print(f"  [{ts}] {msg}", end=end, flush=True)