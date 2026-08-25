import math


class Flow:
    def __init__(
        self,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
    ):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = None
        self.end_time = None

        # Each packet:
        #
        # (
        #     timestamp,
        #     length,
        #     tcp_flags,
        #     header_length,
        #     tcp_window
        # )
        #
        self.forward_packets = []
        self.backward_packets = []

        # CICIDS-style initial TCP window sizes.
        #
        # These are taken from the first TCP packet observed
        # in each direction.
        self.init_fwd_win_bytes = 0
        self.init_bwd_win_bytes = 0

        self._fwd_window_seen = False
        self._bwd_window_seen = False

    def add_packet(
        self,
        timestamp,
        length,
        direction,
        tcp_flags=0,
        header_length=0,
        tcp_window=0,
    ):
        if self.start_time is None:
            self.start_time = timestamp

        self.end_time = timestamp

        packet = (
            timestamp,
            length,
            tcp_flags,
            header_length,
            tcp_window,
        )

        if direction == "forward":
            self.forward_packets.append(packet)

            if not self._fwd_window_seen:
                self.init_fwd_win_bytes = int(
                    tcp_window
                )
                self._fwd_window_seen = True

        else:
            self.backward_packets.append(packet)

            if not self._bwd_window_seen:
                self.init_bwd_win_bytes = int(
                    tcp_window
                )
                self._bwd_window_seen = True

    # ---------------------------------------------------------
    # Basic properties
    # ---------------------------------------------------------

    @property
    def duration(self):
        if (
            self.start_time is None
            or self.end_time is None
        ):
            return 0.0

        return max(
            self.end_time - self.start_time,
            0.0,
        )

    @property
    def forward_bytes(self):
        return sum(
            length
            for _, length, _, _, _ in self.forward_packets
        )

    @property
    def backward_bytes(self):
        return sum(
            length
            for _, length, _, _, _ in self.backward_packets
        )

    @property
    def total_packets(self):
        return (
            len(self.forward_packets)
            + len(self.backward_packets)
        )

    @property
    def total_bytes(self):
        return (
            self.forward_bytes
            + self.backward_bytes
        )

    # ---------------------------------------------------------
    # Statistical helpers
    # ---------------------------------------------------------

    @staticmethod
    def _values(packets):
        return [
            length
            for _, length, _, _, _ in packets
        ]

    @staticmethod
    def _timestamps(packets):
        return [
            timestamp
            for timestamp, _, _, _, _ in packets
        ]

    @staticmethod
    def _mean(values):
        if not values:
            return 0.0

        return sum(values) / len(values)

    @staticmethod
    def _std(values):
        if len(values) <= 1:
            return 0.0

        mean = sum(values) / len(values)

        variance = sum(
            (x - mean) ** 2
            for x in values
        ) / len(values)

        return math.sqrt(variance)

    @staticmethod
    def _iat_values(packets):
        timestamps = Flow._timestamps(packets)

        if len(timestamps) < 2:
            return []

        return [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

    @staticmethod
    def _safe_rate(value, duration):
        if duration <= 0:
            return 0.0

        return value / duration

    # ---------------------------------------------------------
    # TCP flag helpers
    # ---------------------------------------------------------

    def _flag_count(self, packets, mask):
        return sum(
            1
            for _, _, flags, _, _ in packets
            if flags & mask
        )

    @property
    def fin_count(self):
        return self._flag_count(
            self.forward_packets
            + self.backward_packets,
            0x01,
        )

    @property
    def syn_count(self):
        return self._flag_count(
            self.forward_packets
            + self.backward_packets,
            0x02,
        )

    @property
    def rst_count(self):
        return self._flag_count(
            self.forward_packets
            + self.backward_packets,
            0x04,
        )

    @property
    def psh_count(self):
        return self._flag_count(
            self.forward_packets
            + self.backward_packets,
            0x08,
        )

    @property
    def ack_count(self):
        return self._flag_count(
            self.forward_packets
            + self.backward_packets,
            0x10,
        )

    @property
    def urg_count(self):
        return self._flag_count(
            self.forward_packets
            + self.backward_packets,
            0x20,
        )

    @property
    def ece_count(self):
        return self._flag_count(
            self.forward_packets
            + self.backward_packets,
            0x40,
        )

    @property
    def cwe_count(self):
        return self._flag_count(
            self.forward_packets
            + self.backward_packets,
            0x80,
        )

    # ---------------------------------------------------------
    # Feature generation
    # ---------------------------------------------------------

    def to_features(self):
        fwd = self.forward_packets
        bwd = self.backward_packets

        all_packets = fwd + bwd

        fwd_lengths = self._values(fwd)
        bwd_lengths = self._values(bwd)
        all_lengths = self._values(all_packets)

        fwd_iat = self._iat_values(fwd)
        bwd_iat = self._iat_values(bwd)

        flow_iat = self._iat_values(
            sorted(
                all_packets,
                key=lambda x: x[0],
            )
        )

        duration = self.duration

        flow_bytes_per_second = self._safe_rate(
            self.total_bytes,
            duration,
        )

        flow_packets_per_second = self._safe_rate(
            self.total_packets,
            duration,
        )

        fwd_packets_per_second = self._safe_rate(
            len(fwd),
            duration,
        )

        bwd_packets_per_second = self._safe_rate(
            len(bwd),
            duration,
        )

        # -----------------------------------------------------
        # Packet statistics
        # -----------------------------------------------------

        packet_min = (
            min(all_lengths)
            if all_lengths
            else 0.0
        )

        packet_max = (
            max(all_lengths)
            if all_lengths
            else 0.0
        )

        packet_mean = self._mean(
            all_lengths
        )

        packet_std = self._std(
            all_lengths
        )

        packet_variance = (
            packet_std ** 2
        )

        fwd_mean = self._mean(
            fwd_lengths
        )

        fwd_std = self._std(
            fwd_lengths
        )

        bwd_mean = self._mean(
            bwd_lengths
        )

        bwd_std = self._std(
            bwd_lengths
        )

        # -----------------------------------------------------
        # IAT statistics
        # -----------------------------------------------------

        flow_iat_mean = self._mean(
            flow_iat
        )

        flow_iat_std = self._std(
            flow_iat
        )

        flow_iat_max = (
            max(flow_iat)
            if flow_iat
            else 0.0
        )

        flow_iat_min = (
            min(flow_iat)
            if flow_iat
            else 0.0
        )

        fwd_iat_total = sum(
            fwd_iat
        )

        fwd_iat_mean = self._mean(
            fwd_iat
        )

        fwd_iat_std = self._std(
            fwd_iat
        )

        fwd_iat_max = (
            max(fwd_iat)
            if fwd_iat
            else 0.0
        )

        fwd_iat_min = (
            min(fwd_iat)
            if fwd_iat
            else 0.0
        )

        bwd_iat_total = sum(
            bwd_iat
        )

        bwd_iat_mean = self._mean(
            bwd_iat
        )

        bwd_iat_std = self._std(
            bwd_iat
        )

        bwd_iat_max = (
            max(bwd_iat)
            if bwd_iat
            else 0.0
        )

        bwd_iat_min = (
            min(bwd_iat)
            if bwd_iat
            else 0.0
        )

        # -----------------------------------------------------
        # Header lengths
        # -----------------------------------------------------

        fwd_header_length = sum(
            header
            for _, _, _, header, _ in fwd
        )

        bwd_header_length = sum(
            header
            for _, _, _, header, _ in bwd
        )

        # -----------------------------------------------------
        # Average packet size
        # -----------------------------------------------------

        avg_packet_size = self._mean(
            all_lengths
        )

        avg_fwd_segment_size = fwd_mean
        avg_bwd_segment_size = bwd_mean

        # -----------------------------------------------------
        # Direction ratio
        # -----------------------------------------------------

        if len(bwd) == 0:
            down_up_ratio = 0.0
        else:
            down_up_ratio = (
                len(bwd)
                / max(len(fwd), 1)
            )

        # -----------------------------------------------------
        # Active / idle statistics
        #
        # These remain zero for now because we have not yet
        # confirmed the exact active/idle calculation used
        # during model training.
        # -----------------------------------------------------

        active_mean = 0.0
        active_std = 0.0
        active_max = 0.0
        active_min = 0.0

        idle_mean = 0.0
        idle_std = 0.0
        idle_max = 0.0
        idle_min = 0.0

        # -----------------------------------------------------
        # Forward data packets
        # -----------------------------------------------------

        fwd_act_data_packets = 0

        if fwd:
            fwd_act_data_packets = sum(
                1
                for _, length, _, _, _ in fwd
                if length > 0
            )

        fwd_seg_size_min = (
            min(fwd_lengths)
            if fwd_lengths
            else 0.0
        )

        # -----------------------------------------------------
        # EXACT 77 MODEL FEATURES
        # -----------------------------------------------------

        features = {
            "Protocol": self.protocol,

            "Flow_Duration": duration,

            "Total_Fwd_Packets":
                len(fwd),

            "Total_Backward_Packets":
                len(bwd),

            "Fwd_Packets_Length_Total":
                self.forward_bytes,

            "Bwd_Packets_Length_Total":
                self.backward_bytes,

            "Fwd_Packet_Length_Max":
                max(fwd_lengths)
                if fwd_lengths
                else 0.0,

            "Fwd_Packet_Length_Min":
                min(fwd_lengths)
                if fwd_lengths
                else 0.0,

            "Fwd_Packet_Length_Mean":
                fwd_mean,

            "Fwd_Packet_Length_Std":
                fwd_std,

            "Bwd_Packet_Length_Max":
                max(bwd_lengths)
                if bwd_lengths
                else 0.0,

            "Bwd_Packet_Length_Min":
                min(bwd_lengths)
                if bwd_lengths
                else 0.0,

            "Bwd_Packet_Length_Mean":
                bwd_mean,

            "Bwd_Packet_Length_Std":
                bwd_std,

            "Flow_Bytes/s":
                flow_bytes_per_second,

            "Flow_Packets/s":
                flow_packets_per_second,

            "Flow_IAT_Mean":
                flow_iat_mean,

            "Flow_IAT_Std":
                flow_iat_std,

            "Flow_IAT_Max":
                flow_iat_max,

            "Flow_IAT_Min":
                flow_iat_min,

            "Fwd_IAT_Total":
                fwd_iat_total,

            "Fwd_IAT_Mean":
                fwd_iat_mean,

            "Fwd_IAT_Std":
                fwd_iat_std,

            "Fwd_IAT_Max":
                fwd_iat_max,

            "Fwd_IAT_Min":
                fwd_iat_min,

            "Bwd_IAT_Total":
                bwd_iat_total,

            "Bwd_IAT_Mean":
                bwd_iat_mean,

            "Bwd_IAT_Std":
                bwd_iat_std,

            "Bwd_IAT_Max":
                bwd_iat_max,

            "Bwd_IAT_Min":
                bwd_iat_min,

            "Fwd_PSH_Flags":
                self._flag_count(
                    fwd,
                    0x08,
                ),

            "Bwd_PSH_Flags":
                self._flag_count(
                    bwd,
                    0x08,
                ),

            "Fwd_URG_Flags":
                self._flag_count(
                    fwd,
                    0x20,
                ),

            "Bwd_URG_Flags":
                self._flag_count(
                    bwd,
                    0x20,
                ),

            "Fwd_Header_Length":
                fwd_header_length,

            "Bwd_Header_Length":
                bwd_header_length,

            "Fwd_Packets/s":
                fwd_packets_per_second,

            "Bwd_Packets/s":
                bwd_packets_per_second,

            "Packet_Length_Min":
                packet_min,

            "Packet_Length_Max":
                packet_max,

            "Packet_Length_Mean":
                packet_mean,

            "Packet_Length_Std":
                packet_std,

            "Packet_Length_Variance":
                packet_variance,

            "FIN_Flag_Count":
                self.fin_count,

            "SYN_Flag_Count":
                self.syn_count,

            "RST_Flag_Count":
                self.rst_count,

            "PSH_Flag_Count":
                self.psh_count,

            "ACK_Flag_Count":
                self.ack_count,

            "URG_Flag_Count":
                self.urg_count,

            "CWE_Flag_Count":
                self.cwe_count,

            "ECE_Flag_Count":
                self.ece_count,

            "Down/Up_Ratio":
                down_up_ratio,

            "Avg_Packet_Size":
                avg_packet_size,

            "Avg_Fwd_Segment_Size":
                avg_fwd_segment_size,

            "Avg_Bwd_Segment_Size":
                avg_bwd_segment_size,

            "Fwd_Avg_Bytes/Bulk":
                0.0,

            "Fwd_Avg_Packets/Bulk":
                0.0,

            "Fwd_Avg_Bulk_Rate":
                0.0,

            "Bwd_Avg_Bytes/Bulk":
                0.0,

            "Bwd_Avg_Packets/Bulk":
                0.0,

            "Bwd_Avg_Bulk_Rate":
                0.0,

            "Subflow_Fwd_Packets":
                len(fwd),

            "Subflow_Fwd_Bytes":
                self.forward_bytes,

            "Subflow_Bwd_Packets":
                len(bwd),

            "Subflow_Bwd_Bytes":
                self.backward_bytes,

            "Init_Fwd_Win_Bytes":
                self.init_fwd_win_bytes,

            "Init_Bwd_Win_Bytes":
                self.init_bwd_win_bytes,

            "Fwd_Act_Data_Packets":
                fwd_act_data_packets,

            "Fwd_Seg_Size_Min":
                fwd_seg_size_min,

            "Active_Mean":
                active_mean,

            "Active_Std":
                active_std,

            "Active_Max":
                active_max,

            "Active_Min":
                active_min,

            "Idle_Mean":
                idle_mean,

            "Idle_Std":
                idle_std,

            "Idle_Max":
                idle_max,

            "Idle_Min":
                idle_min,
        }

        return features

    # ---------------------------------------------------------
    # Flow summary
    # ---------------------------------------------------------

    def summary(self):
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,

            "forward_packets":
                len(self.forward_packets),

            "backward_packets":
                len(self.backward_packets),

            "total_packets":
                self.total_packets,

            "forward_bytes":
                self.forward_bytes,

            "backward_bytes":
                self.backward_bytes,

            "total_bytes":
                self.total_bytes,

            "duration":
                self.duration,

            "init_fwd_win_bytes":
                self.init_fwd_win_bytes,

            "init_bwd_win_bytes":
                self.init_bwd_win_bytes,
        }


def get_flow_key(
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    protocol,
):
    forward_key = (
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
    )

    backward_key = (
        dst_ip,
        dst_port,
        src_ip,
        src_port,
        protocol,
    )

    return forward_key, backward_key


def main():
    print("=" * 60)
    print("LIVE FLOW BUILDER")
    print("=" * 60)

    flows = {}

    print()
    print("Flow builder module created successfully.")
    print("Ready to receive live packets.")
    print()
    print(
        "Current flow count:",
        len(flows),
    )


if __name__ == "__main__":
    main()