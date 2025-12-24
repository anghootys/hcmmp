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
    """PPG Plotter that displays pre-processed data from BPM detector"""
    def __init__(self, sample_queue, window_seconds=10, sample_rate=400):
        self.sample_queue = sample_queue
        self.window_samples = int(window_seconds * sample_rate)
        self.sample_rate = sample_rate

        # Buffers for display (pre-processed data from BPM detector)
        self.ir_raw_buf = deque(maxlen=self.window_samples)
        self.ir_filtered_buf = deque(maxlen=self.window_samples)
        self.time_buf = deque(maxlen=self.window_samples)

        # Pending data queue - samples wait here before being released to display
        self._pending_raw = deque()
        self._pending_filtered = deque()
        self._pending_time = deque()

        self._pending_lock = threading.Lock()
        self._sample_count = 0
        self._running = True
        self._ani = None

        # Release 20 samples per 50ms frame = 400 samples/second (matches sample rate)
        self._samples_per_frame = 30

    def start_background_reader(self):
        """Start thread to drain pre-processed samples from queue"""
        thread = threading.Thread(target=self._drain_queue, daemon=True)
        thread.start()
        return thread

    def _drain_queue(self):
        """Drain pre-processed samples from queue and add to pending display queue"""
        while self._running:
            try:
                sample = self.sample_queue.get(timeout=0.1)
            except Exception:
                continue

            # Data is already processed by BPM detector
            ac_value = sample.get("ac")
            filtered = sample.get("filtered")

            if ac_value is None or filtered is None:
                continue

            self._sample_count += 1
            t = self._sample_count / self.sample_rate

            with self._pending_lock:
                self._pending_time.append(t)
                self._pending_raw.append(ac_value)
                self._pending_filtered.append(filtered)


    def run(self):
        plt.ion()  # Interactive mode
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)

        # Raw AC signal
        line_raw, = ax1.plot([], [], 'b-', linewidth=0.8, alpha=0.6, label='Raw AC')
        ax1.set_ylabel('Raw AC Value')
        ax1.set_title('PPG Signal - Raw (DC Removed)')
        ax1.legend(loc='upper right')
        ax1.grid(True, alpha=0.3)

        # Filtered signal
        line_filtered, = ax2.plot([], [], 'r-', linewidth=1.5, label='Filtered & Smoothed')
        ax2.set_xlabel('Time (seconds)')
        ax2.set_ylabel('Filtered Value')
        ax2.set_title('PPG Signal - Bandpass Filtered & Smoothed')
        ax2.legend(loc='upper right')
        ax2.grid(True, alpha=0.3)

        def animate(frame):
            # Only release samples to display - processing is in background thread
            # Release samples from pending queue gradually
            # This creates the slow-motion effect for real-time display
            with self._pending_lock:
                samples_to_release = min(self._samples_per_frame, len(self._pending_time))

                for _ in range(samples_to_release):
                    if self._pending_time:
                        self.time_buf.append(self._pending_time.popleft())
                        self.ir_raw_buf.append(self._pending_raw.popleft())
                        self.ir_filtered_buf.append(self._pending_filtered.popleft())

            if len(self.time_buf) < 2:
                return line_raw, line_filtered

            x = list(self.time_buf)
            y_raw = list(self.ir_raw_buf)
            y_filtered = list(self.ir_filtered_buf)

            # Update raw plot
            line_raw.set_data(x, y_raw)
            ax1.set_xlim(max(0, x[-1] - self.window_samples / self.sample_rate), x[-1] + 0.5)
            if y_raw:
                margin = max(abs(min(y_raw)), abs(max(y_raw))) * 0.1 + 1
                ax1.set_ylim(min(y_raw) - margin, max(y_raw) + margin)

            # Update filtered plot
            line_filtered.set_data(x, y_filtered)
            ax2.set_xlim(max(0, x[-1] - self.window_samples / self.sample_rate), x[-1] + 0.5)
            if y_filtered:
                margin = max(abs(min(y_filtered)), abs(max(y_filtered))) * 0.1 + 1
                ax2.set_ylim(min(y_filtered) - margin, max(y_filtered) + margin)

            return line_raw, line_filtered

        # Use blit=False to avoid the disappearing issue
        # Update every 50ms (20 FPS) for smooth continuous display
        self._ani = animation.FuncAnimation(
            fig, animate,
            interval=10,  # 50ms refresh rate for smooth plotting
            blit=False,  # IMPORTANT: blit=False prevents disappearing
            cache_frame_data=False,
        )

        plt.tight_layout()
        plt.show(block=True)  # Block to keep window open
        return self._ani

    def stop(self):
        self._running = False


def launch_ppg_plot(sample_queue):
    plotter = PPGPlotter(sample_queue, window_seconds=10, sample_rate=400)
    plotter.start_background_reader()
    try:
        plotter.run()
    except KeyboardInterrupt:
        plotter.stop()


__all__ = ["launch_ppg_plot", "PPGPlotter"]
