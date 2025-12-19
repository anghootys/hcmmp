class HCMMPError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"[HCMMP EXCEPTION] {msg}")

class HCMMPConnectionFailed(HCMMPError):
    def __init__(self, e):
        super().__init__(f"Failed to establish TCP connection: {e}")

class HCMMPPubKeyExchangeFailed(HCMMPError):
    def __init__(self, e):
        super().__init__(f"Public key exchange failed during handshake: {e}")

class HCMMPFetchHandshakeNonceFailed(HCMMPError):
    def __init__(self, e):
        super().__init__(f"Failed to fetch handshake nonce from peer: {e}")

class HCMMPAuthenticationFailed(HCMMPError):
    def __init__(self, e):
        super().__init__(f"Authentication failed during handshake: {e}")

class HCMMPAESKeyRenewalFailed(HCMMPError):
    def __init__(self, e):
        super().__init__(f"AES key renewal failed: {e}")