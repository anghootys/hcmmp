from enum import Enum


class HCMMPConnectionState(Enum):
    DISCONNECTED = 0x0A
    HANDSHAKING = 0x0B
    CONNECTED = 0x0C

def get_state_title(state: HCMMPConnectionState) -> str:
    titles = {
        HCMMPConnectionState.DISCONNECTED: "disconnected",
        HCMMPConnectionState.HANDSHAKING: "handshaking",
        HCMMPConnectionState.CONNECTED: "connected"
    }
    return titles.get(state, "unknown")
