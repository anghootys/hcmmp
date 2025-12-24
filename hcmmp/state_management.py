from threading import Thread

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
import logging
from socket import *
import sys
import struct
import datetime
from os.path import isdir
from os import mkdir

import csv

from queue import Queue, Full

import math
from collections import deque
from time import time, sleep

from hcmmp.connection import (
    HCMMPConnection,
    FingerprintVerificationFailed,
)
from hcmmp.consts import *
from hcmmp.errors import HCMMPConnectionFailed
from hcmmp.ppg_plotter import launch_ppg_plot
from hcmmp.packet import HCMMPPacket

lg = logging.getLogger("HCMMP")

HCMMP_DISCONNECTED = 0x0A
HCMMP_HANDSHAKING = 0x0C
HCMMP_CONNECTED = 0x0D

HCMMP_SENSOR_DATA_SIZE = 12

hcm_sensor_queue = Queue(maxsize=1024 * 1024)
hcm_plot_queue = Queue(maxsize=1024 * 1024)
hcm_store_queue = Queue(maxsize=1024 * 1024 * 50)


def scan_HCMMP_broadcast():
    hcmmp_adv_list = []

    is_first_print = True
    last_hcmmp_broadcast_count = 0

    def print_broadcast_clients():
        nonlocal is_first_print, last_hcmmp_broadcast_count

        if not is_first_print:
            for _ in range(last_hcmmp_broadcast_count + 4):
                sys.stdout.write("\033[2K")
                sys.stdout.write("\033[1A")
            sys.stdout.write("\033[2K")
            sys.stdout.flush()

        is_first_print = False
        last_hcmmp_broadcast_count = len(hcmmp_adv_list)

        tbl_hdr = f"{'#':^5} | {'ID - IP Address:Port':^30}"
        print(tbl_hdr)
        print("-" * len(tbl_hdr))

        for i, pkt in enumerate(hcmmp_adv_list):
            print(f"{i + 1:^5} | {pkt.description():^30}")

        print("\nCtrl+C to stop scanning.")

    with socket(AF_INET, SOCK_DGRAM) as usfd:
        usfd.bind(("", HCMMP_BROADCAST_PORT))

        while True:
            usfd.settimeout(1)
            print_broadcast_clients()

            try:
                hcmmp_pkt = HCMMPPacket.from_bytes(usfd)
                if (
                        hcmmp_pkt.is_advertisement()
                        and hcmmp_pkt.get_session_id()
                        not in map(lambda x: x.get_session_id(), hcmmp_adv_list)
                ):
                    hcmmp_adv_list.append(hcmmp_pkt)
            except ValueError as e:
                lg.warning(f"Received invalid HCMMP packet: {e}")
            except TimeoutError:
                continue
            except KeyboardInterrupt:
                sys.stdout.write("\n")
                sys.stdout.flush()
                break

    if len(hcmmp_adv_list) == 0:
        return None

    while True:
        try:
            return hcmmp_adv_list[
                int(input("Enter the number of the client to connect to: ")) - 1
                ]
        except Exception:
            print("Invalid input.")


def handle_HCMMP_data_gathering(hcmmp_connection: HCMMPConnection):
    # process sensor data
    sensor_reader_thread = Thread(target=process_hcm_sensor_data)
    sensor_reader_thread.start()

    # plot processed data
    plot_thread = Thread(target=launch_ppg_plot, args=(hcm_plot_queue,))
    plot_thread.daemon = True
    plot_thread.start()

    # store processed data
    store_thread = Thread(target=store_hcm_sensor_data, args=(hcmmp_connection.get_host_id(),))
    store_thread.start()

    # timeout counter for connection timeouts (if it reaches 10, reconnect to host using host_id)
    timeout_count = 0

    while True:
        try:
            pkt = hcmmp_connection.get_pkt()
            timeout_count = 0

            if pkt is None:
                lg.warning("Failed to get pkt")
                break

            data = pkt.get_raw_data()
            num_samples = len(data) // HCMMP_SENSOR_DATA_SIZE

            for i in range(num_samples):
                offset = i * HCMMP_SENSOR_DATA_SIZE
                sample_data = data[offset: offset + HCMMP_SENSOR_DATA_SIZE]

                if len(sample_data) != HCMMP_SENSOR_DATA_SIZE:
                    break

                red, ir, timestamp = struct.unpack("!III", sample_data)
                sample = {"red": red, "ir": ir, "timestamp": timestamp}
                try:
                    # there are two queues: one for sensor data processing, one for plotting
                    # it is done to avoid blocking the sensor data processing when the plotting queue is full
                    hcm_sensor_queue.put_nowait(sample)
                    # Plot queue gets raw sample - will be processed later after BPM processing
                except Full:
                    pass

        except KeyboardInterrupt:
            hcmmp_connection.close()
            raise
        except TimeoutError:
            timeout_count += 1
            if timeout_count > 10:
                hcmmp_connection.close()
                raise ConnectionError("Connection failed")
        except Exception as e:
            lg.error(e)


def get_HCMMP_host_fresh_adv_pkt(host_id: int):
    with socket(AF_INET, SOCK_DGRAM) as usfd:
        usfd.bind(("", HCMMP_BROADCAST_PORT))

        while True:
            usfd.settimeout(1)
            try:
                hcmmp_pkt = HCMMPPacket.from_bytes(usfd)

                if hcmmp_pkt.is_advertisement() and hcmmp_pkt.get_host_id() == host_id:
                    return hcmmp_pkt

            except ValueError as e:
                lg.warning(f"Received invalid HCMMP packet: {e}")
            except TimeoutError:
                continue
            except KeyboardInterrupt:
                sys.stdout.write("\n")
                sys.stdout.flush()
                break
    return None

def establish_connection_to_HCMMP_Host(prv_key: RSAPrivateKey, pub_key: RSAPublicKey, adv_pkt: HCMMPPacket = None):
    hcmmp_connection = None

    while hcmmp_connection is None:
        lg.info("Scanning for HCMMP broadcasts...")
        try:
            if adv_pkt is None:
                adv_pkt = scan_HCMMP_broadcast()
                if adv_pkt is None:
                    return None

                assert (isinstance(adv_pkt, HCMMPPacket))
                lg.info(f"Found HCMMP advertisement from {adv_pkt.description()}")

            hcmmp_connection = HCMMPConnection(prv_key, pub_key, adv_pkt)
        except Exception as e:
            print("scanning failed, check logs for more information.")
            lg.error(f"HCMMP scanning broadcast advertisements failed: {e}")

    if hcmmp_connection is None:
        return None

    connection_establishment_retries = 0
    while connection_establishment_retries < HCMMP_TCP_CONNECTION_RETRY_LIMIT:
        try:
            hcmmp_connection.establish_connection()
            break
        except Exception as e:
            lg.error(f"Failed to establish HCMMP TCP connection: {e}")
            connection_establishment_retries += 1
            if connection_establishment_retries >= HCMMP_TCP_CONNECTION_RETRY_LIMIT:
                lg.error(
                    "Reached maximum TCP connection retry limit. Aborting HCMMP handling."
                )
                raise HCMMPConnectionFailed(e)

    handshake_retries = 0
    while handshake_retries < HCMMP_HANDSHAKE_RETRY_LIMIT:
        try:
            lg.info("Starting HCMMP handshake...")
            handshake_result = hcmmp_connection.do_handshake()

            if not handshake_result:
                lg.error("HCMMP handshake failed.")
                hcmmp_connection.close()
                handshake_retries += 1
                continue

            lg.info("HCMMP handshake completed successfully.")
            break
        except ConnectionResetError:
            lg.error("Connection was reset by peer during handshake.")
            continue
        except KeyboardInterrupt:
            lg.info("HCMMP handler interrupted by user.")
            hcmmp_connection.close()
            return None
        except FingerprintVerificationFailed as e:
            lg.error(f"Fingerprint verification failed: {e}")
            hcmmp_connection.close()
            raise

    if handshake_retries >= HCMMP_HANDSHAKE_RETRY_LIMIT:
        lg.error("Reached maximum handshake retry limit. Aborting HCMMP handling.")
        raise HCMMPConnectionFailed("Handshake failed after maximum retries.")

    lg.info("HCMMP connection established and authenticated successfully.")

    return hcmmp_connection

def handle_HCMMP(prv_key: RSAPrivateKey, pub_key: RSAPublicKey):

    hcmmp_connection = establish_connection_to_HCMMP_Host(prv_key, pub_key)

    while True:
        try:
            handle_HCMMP_data_gathering(hcmmp_connection)
        except KeyboardInterrupt:
            raise
        except ConnectionError:
            print("Reconnecting to the HCMMP peer...")
            adv_pkt = get_HCMMP_host_fresh_adv_pkt(hcmmp_connection.get_host_id())
            hcmmp_connection = establish_connection_to_HCMMP_Host(prv_key, pub_key, adv_pkt)


def process_hcm_sensor_data():
    # todo: it should be dynamic and based on hcm device configurations
    SAMPLE_RATE = 400

    # window size for direct current buffer (here 5 seconds)
    DC_WINDOW = SAMPLE_RATE * 5

    # for computing bpm, we should find out peaks, so for filtering noises, we should define a boundary for peak intervals
    # here min peak interval is 0.5s (means each 0.5 seconds, a heart pulse would be happened, or 120 beats per minute)
    # and max peak interval is 1.5s (means each 1.5 seconds, a heart pulse would be happened, or 40 beats per minute)
    MIN_PEAK_INTERVAL = 0.5
    MAX_PEAK_INTERVAL = 1.5

    # BPM buffer is used to average BPM for smoother calculation
    # more BPM_BUFFER_SIZE means lower fluctuation in bpm
    BPM_BUFFER_SIZE = 50

    # this queue is used to store DC values for filtering them in batches
    dc_buffer_queue = deque(maxlen=DC_WINDOW)

    # Multi-stage low-pass filter state (cascaded for stronger filtering)
    # Stage 1: 4 Hz low-pass
    lp1_x1, lp1_y1 = 0.0, 0.0
    # Stage 2: 4 Hz low-pass (cascaded = 2nd order)
    lp2_x1, lp2_y1 = 0.0, 0.0
    # Stage 3: Additional smoothing at 3 Hz
    lp3_x1, lp3_y1 = 0.0, 0.0

    # High-pass filter state (0.5 Hz cutoff - removes DC drift)
    hp_x1, hp_y1 = 0.0, 0.0

    # High-pass filter coefficients (0.5 Hz cutoff)
    hp_wc = 2 * math.tan(math.pi * 0.5 / SAMPLE_RATE)
    hp_k = hp_wc / 2
    hp_a0 = 1 / (1 + hp_k)
    hp_a1 = -hp_a0
    hp_b1 = (1 - hp_k) / (1 + hp_k)

    # Low-pass filter coefficients (4 Hz cutoff - removes noise, keeps heartbeat)
    lp_wc = 2 * math.tan(math.pi * 4.0 / SAMPLE_RATE)
    lp_k = lp_wc / 2
    lp_a0 = lp_k / (1 + lp_k)
    lp_a1 = lp_a0
    lp_b1 = (lp_k - 1) / (1 + lp_k)

    # Extra smoothing filter coefficients (3 Hz)
    lp3_wc = 2 * math.tan(math.pi * 3.0 / SAMPLE_RATE)
    lp3_k = lp3_wc / 2
    lp3_a0 = lp3_k / (1 + lp3_k)
    lp3_a1 = lp3_a0
    lp3_b1 = (lp3_k - 1) / (1 + lp3_k)

    # using 5 samples buffer to find local maximum (and check if the local maximum is actually a peak by comparing with threshold)
    filtered_data_buf = deque(maxlen=5)
    sample_count = 0
    samples_since_last_peak = 0
    is_bpm_delay = False
    bpm_delay_counter = 0

    # Adaptive threshold using percentile
    signal_buffer = deque(maxlen=SAMPLE_RATE * 5)
    threshold = 0

    min_since_last_peak = float('inf')
    max_since_last_peak = float('-inf')

    bpm_buffer = deque(maxlen=BPM_BUFFER_SIZE)
    current_bpm = 0

    prev_timestamp = None
    ts_deltas = deque(maxlen=100)
    actual_sample_rate = SAMPLE_RATE

    lg.info("BPM detector started...")

    while True:
        try:
            while not hcm_sensor_queue.empty():
                try:
                    sample = hcm_sensor_queue.get_nowait()
                except Exception:
                    break

                ir_value = sample.get('ir', 0)
                timestamp = sample.get('timestamp')

                # Filter out invalid sensor ranges
                # these values are found based on experiments with real sensor data
                if ir_value < 50000 or ir_value > 250000:
                    continue

                sample_count += 1

                # sample rate would be fluctuated, so we could derive actual sample rate from in-order timestamps
                # so we gather 20+ deltas (current timestamp - previous timestamp) and calculate median delta to derive actual sample rate
                # this formula is based on standard definition of sample rate = number of samples / second
                if timestamp is not None and prev_timestamp is not None:
                    ts_delta = timestamp - prev_timestamp
                    if ts_delta > 0:
                        ts_deltas.append(ts_delta)
                        if len(ts_deltas) >= 20:
                            sorted_deltas = sorted(ts_deltas)
                            median_delta = sorted_deltas[len(sorted_deltas) // 2]
                            derived_rate = 1000 / median_delta

                            if 290 <= derived_rate <= 510:
                                actual_sample_rate = derived_rate

                prev_timestamp = timestamp

                dc_buffer_queue.append(ir_value)
                if len(dc_buffer_queue) < 100:
                    continue

                # moving avg filtering
                dc_avg = sum(dc_buffer_queue) / len(dc_buffer_queue)
                ac_value = ir_value - dc_avg

                # ===== Multi-stage Bandpass Filter =====
                # High-pass filter (remove baseline drift)
                hp_out = hp_a0 * ac_value + hp_a1 * hp_x1 - hp_b1 * hp_y1
                hp_x1 = ac_value
                hp_y1 = hp_out

                # Low-pass filter stage 1
                lp1_out = lp_a0 * hp_out + lp_a1 * lp1_x1 - lp_b1 * lp1_y1
                lp1_x1 = hp_out
                lp1_y1 = lp1_out

                # Low-pass filter stage 2 (cascaded)
                lp2_out = lp_a0 * lp1_out + lp_a1 * lp2_x1 - lp_b1 * lp2_y1
                lp2_x1 = lp1_out
                lp2_y1 = lp2_out

                # Low-pass filter stage 3 (extra smoothing)
                lp3_out = lp3_a0 * lp2_out + lp3_a1 * lp3_x1 - lp3_b1 * lp3_y1
                lp3_x1 = lp2_out
                lp3_y1 = lp3_out

                # after 3 levels of bypass filtering, we get the final filtered value
                # this is shown in plot as well
                filtered = lp3_out
                last_filtered_value = filtered

                # Send processed data to plot queue to show on animated plot
                try:
                    hcm_plot_queue.put_nowait({
                        "ac": ac_value,
                        "filtered": filtered,
                        "timestamp": timestamp
                    })
                except Full:
                    pass

                if current_bpm > 0:
                    try:
                        hcm_store_queue.put_nowait({
                            "timestamp": timestamp,
                            "ir": ir_value,
                            "filtered": filtered,
                            "bpm": current_bpm
                        })
                    except Full:
                        pass

                # Add to history
                filtered_data_buf.append(filtered)

                # we should wait for some seconds to gather enough data for threshold calculation
                # because of 5 seconds window defined in hcm device, we wait for 5 seconds here too
                if sample_count < (SAMPLE_RATE * 5):
                    continue


                signal_buffer.append(filtered)
                if len(signal_buffer) >= 200:
                    # Use 75th percentile of positive values for threshold
                    positive_vals = sorted([x for x in signal_buffer if x > 0])
                    if len(positive_vals) > 10:
                        # Threshold at 60% of the 80th percentile
                        idx = int(len(positive_vals) * 0.8)
                        threshold = positive_vals[idx] * 0.6
                    else:
                        rms = math.sqrt(sum(x * x for x in signal_buffer) / len(signal_buffer))
                        threshold = rms * 0.7

                samples_since_last_peak += 1


                # after each bpm calculated, we should wait for some time to avoid repeated calculation of same peaks
                # here we wait for 300ms
                if is_bpm_delay:
                    bpm_delay_counter -= 1
                    if bpm_delay_counter <= 0:
                        is_bpm_delay = False
                    continue

                # min and max since last peak
                min_since_last_peak = min(min_since_last_peak, filtered)
                max_since_last_peak = max(max_since_last_peak, filtered)

                # wait until we have enough samples in buffer
                if len(filtered_data_buf) < 5:
                    continue

                # Check if middle sample is a local maximum
                h = list(filtered_data_buf)
                mid = h[2]
                is_peak = mid > h[0] and mid > h[1] and mid > h[3] and mid > h[4]

                # check if it's a valid peak
                if is_peak and mid > threshold:
                    peak_value = mid

                    # Calculate prominence (peak must stand out from recent minimum)
                    prominence = peak_value - min_since_last_peak

                    # Require significant prominence
                    min_prominence = threshold * 1.0  # Must be at least as high as threshold

                    if prominence > min_prominence:
                        # Check minimum interval
                        min_samples = int(actual_sample_rate * MIN_PEAK_INTERVAL)
                        max_samples = int(actual_sample_rate * MAX_PEAK_INTERVAL)

                        if samples_since_last_peak >= min_samples:

                            # Valid peak - calculate BPM
                            if samples_since_last_peak <= max_samples:
                                inst_bpm = 60.0 * actual_sample_rate / samples_since_last_peak

                                # Sanity check and outlier rejection
                                if 40 <= inst_bpm <= 150:
                                    # If we have history, reject if too different
                                    if len(bpm_buffer) >= 3:
                                        avg_bpm = sum(bpm_buffer) / len(bpm_buffer)
                                        # Allow ±25% deviation from average
                                        if abs(inst_bpm - avg_bpm) <= avg_bpm * 0.25:
                                            bpm_buffer.append(inst_bpm)
                                        # If very different, might be resetting - still add with lower weight
                                        elif abs(inst_bpm - avg_bpm) <= avg_bpm * 0.4:
                                            bpm_buffer.append(inst_bpm)
                                    else:
                                        bpm_buffer.append(inst_bpm)

                                    # Calculate median BPM
                                    if len(bpm_buffer) >= 3:
                                        sorted_bpm = sorted(bpm_buffer)
                                        mid_idx = len(sorted_bpm) // 2
                                        if len(sorted_bpm) % 2 == 0:
                                            current_bpm = (sorted_bpm[mid_idx - 1] + sorted_bpm[mid_idx]) / 2
                                        else:
                                            current_bpm = sorted_bpm[mid_idx]


                            # Reset counters and enter refractory period
                            samples_since_last_peak = 0
                            min_since_last_peak = float('inf')
                            max_since_last_peak = float('-inf')

                            # Refractory period: ignore peaks for 300ms after detection
                            is_bpm_delay = True
                            bpm_delay_counter = int(actual_sample_rate * 0.3)

            sleep(0.01)

        except KeyboardInterrupt:
            lg.info("BPM detector stopped by user")
            break
        except Exception as e:
            lg.error(f"Error in BPM detection: {e}")
            sleep(0.1)

def store_hcm_sensor_data(hcm_host_id):
    if not isdir("datasets"):
        mkdir("datasets")

    while True:
        rows = []

        while not hcm_store_queue.empty():
            try:
                sample: dict[str, int] = hcm_store_queue.get_nowait()

                timestamp = sample.get('timestamp', 0)
                ir_dc = sample.get('ir', 0)
                filtered = sample.get('filtered', 0)
                bpm = sample.get('bpm', 0)

                rows.append([timestamp, ir_dc, filtered, bpm])

            except Exception as e:
                print(e)
                continue

        if len(rows) > 0:
            with open(f"datasets/{datetime.datetime.now().strftime('%d-%m-%y')}-hcm_{hcm_host_id}.csv", "a") as f:
                writer = csv.writer(f)
                writer.writerows(rows)

        sleep(10)
