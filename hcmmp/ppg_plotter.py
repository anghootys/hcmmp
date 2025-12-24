import threading
import time
from collections import deque
import logging

try:
    import matplotlib.pyplot as plt
    from matplotlib.animation import FuncAnimation
except ImportError as exc:  # pragma: no cover
    raise SystemExit("matplotlib is required for live plotting: pip install matplotlib") from exc

lg = logging.getLogger("HCMMP")

class PPGPlotter:
    def __init__(self, sample_queue, window_seconds=10, sample_rate=400):
        self.sample_queue = sample_queue
        self.window_samples = int(window_seconds * sample_rate)
        self.sample_rate = sample_rate
        self.red_buf = deque(maxlen=self.window_samples)
        self.ir_buf = deque(maxlen=self.window_samples)
        self.time_buf = deque(maxlen=self.window_samples)
        self._last_t = None
        self._lock = threading.Lock()

    def start_background_reader(self):
        thread = threading.Thread(target=self._drain_queue, daemon=True)
        thread.start()
        return thread

    def _drain_queue(self):
        t0 = time.time()
        while True:
            try:
                sample = self.sample_queue.get(timeout=0.1)
            except Exception:
                continue
            red = sample.get("red")
            ir = sample.get("ir")
            ts = sample.get("timestamp")
            if red is None or ir is None:
                continue
            if ts is None:
                t_rel = time.time() - t0
            else:
                t_rel = (ts - self._last_t) / 1000 if self._last_t else 0
            with self._lock:
                self.red_buf.append(red)
                self.ir_buf.append(ir)
                self.time_buf.append(len(self.time_buf) / self.sample_rate)
            self._last_t = ts if ts is not None else self._last_t

    def run(self):
        fig, (ax1, ax2) = plt.subplots(2, 1, sharex=True)
        red_line, = ax1.plot([], [], color='r', label='RED')
        ir_line, = ax2.plot([], [], color='k', label='IR')
        ax1.set_ylabel('RED'); ax2.set_ylabel('IR'); ax2.set_xlabel('Time (s)')
        ax1.legend(); ax2.legend()

        def init():
            red_line.set_data([], [])
            ir_line.set_data([], [])
            return red_line, ir_line

        def update(_):
            with self._lock:
                x = list(self.time_buf)
                y_red = list(self.red_buf)
                y_ir = list(self.ir_buf)
            if not x:
                return red_line, ir_line
            red_line.set_data(x, y_red)
            ir_line.set_data(x, y_ir)
            ax1.set_xlim(max(0, x[-1] - 10), x[-1] + 0.1)
            if y_red:
                ax1.set_ylim(min(y_red), max(y_red))
            if y_ir:
                ax2.set_ylim(min(y_ir), max(y_ir))
            return red_line, ir_line

        ani = FuncAnimation(fig, update, init_func=init, interval=200, blit=False)
        plt.show()
        return ani

def launch_ppg_plot(sample_queue, window_seconds=10, sample_rate=400):
    plotter = PPGPlotter(sample_queue, window_seconds=window_seconds, sample_rate=sample_rate)
    plotter.start_background_reader()
    plotter.run()

__all__ = ["launch_ppg_plot", "PPGPlotter"]

