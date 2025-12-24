import threading
from collections import deque
import logging

try:
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation
except ImportError as exc:  # pragma: no cover
    raise SystemExit("matplotlib is required for live plotting: pip install matplotlib") from exc

lg = logging.getLogger("HCMMP")


class PPGPlotter:
    def __init__(self, sample_queue, window_seconds=10, sample_rate=400):
        self.sample_queue = sample_queue
        self.window_samples = window_seconds * sample_rate
        self.sample_rate = sample_rate

        self.ir_filtered_buf = deque(maxlen=self.window_samples)
        self.time_buf = deque(maxlen=self.window_samples)

        self._pending_filtered = deque()
        self._pending_time = deque()

        self._pending_lock = threading.Lock()
        self._sample_count = 0
        self.__animation_plot = None

        # latest values received from the producer
        self._latest_bpm = None

    def start_background_reader(self):
        # read samples in group of batches instead of all being displayed once
        thread = threading.Thread(target=self.__take_samples_batch, daemon=True)
        thread.start()
        return thread

    def __take_samples_batch(self):
        while True:
            try:
                sample = self.sample_queue.get(timeout=0.1)
            except Exception:
                continue

            filtered = sample.get("filtered")
            bpm = sample.get("bpm")

            # keep last BPM even if this sample doesn't include it
            if bpm is not None:
                self._latest_bpm = bpm

            if filtered is None:
                continue

            self._sample_count += 1
            t = self._sample_count / self.sample_rate

            with self._pending_lock:
                self._pending_time.append(t)
                self._pending_filtered.append(filtered)

    def run(self):
        plt.ion()
        fig, ax = plt.subplots(1, 1, figsize=(14, 6))

        plot_filtered, = ax.plot([], [], "r-", linewidth=1.5, label="PPG (filtered)")
        ax.set_xlabel("Time (second)")
        ax.set_ylabel("IR Filtered Value")
        ax.grid(True, alpha=0.3)
        ax.legend(loc="upper right")

        def _title_text():
            if self._latest_bpm is None:
                return "PPG Plot (Filtered) | BPM: --"
            try:
                return f"PPG Plot (Filtered) | BPM: {int(self._latest_bpm)}"
            except Exception:
                return f"PPG Plot (Filtered) | BPM: {self._latest_bpm}"

        def animate(frame):
            with self._pending_lock:
                for _ in range(len(self._pending_filtered)):
                    if self._pending_time:
                        self.time_buf.append(self._pending_time.popleft())
                        self.ir_filtered_buf.append(self._pending_filtered.popleft())

            ax.set_title(_title_text())

            if len(self.time_buf) < 2:
                return (plot_filtered,)

            x = list(self.time_buf)
            y_filtered = list(self.ir_filtered_buf)

            plot_filtered.set_data(x, y_filtered)
            ax.set_xlim(max(0, x[-1] - self.window_samples / self.sample_rate), x[-1] + 0.5)
            if y_filtered:
                margin = max(abs(min(y_filtered)), abs(max(y_filtered))) * 0.1 + 1
                ax.set_ylim(min(y_filtered) - margin, max(y_filtered) + margin)

            return (plot_filtered,)

        self.__animation_plot = animation.FuncAnimation(
            fig,
            animate,
            interval=10,
            blit=False,
            cache_frame_data=False,
        )

        plt.tight_layout()
        plt.show(block=True)
        return self.__animation_plot


def launch_ppg_plot(sample_queue):
    plotter = PPGPlotter(sample_queue, window_seconds=10, sample_rate=400)
    plotter.start_background_reader()
    plotter.run()


__all__ = ["launch_ppg_plot", "PPGPlotter"]
