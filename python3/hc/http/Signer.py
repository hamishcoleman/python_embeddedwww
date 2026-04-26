import base64
import hashlib
import hmac
import time


class Base:
    """
    The Signer object is used when signed url are in use
    """

    def create_url(self, url, timeout=None):
        """
        Return the params to add to create a signed URL for this url.
        """
        raise NotImplementedError

    def check_signature(self, handler):
        """
        Check the handler params and if they contain a signature, confirm that
        it is correct.
        """
        raise NotImplementedError


class Simple(Base):
    def __init__(self, secret):
        super().__init__()
        self.secret = secret

    def create_url(self, url, timeout=3600):
        exp = (int(time.time()) + timeout).to_bytes(8)

        sig = hmac.digest(
            self.secret,
            exp + url.encode("utf8"),
            hashlib.sha256
        )
        param = exp + sig
        param_enc = base64.urlsafe_b64encode(param).rstrip(b"=")
        return {"sign": param_enc}

    def check_signature(self, handler):
        if "sign" not in handler.param:
            # No signature, cannot validate
            return False
        if len(handler.param) > 1:
            # TODO:
            # - in future, could support signing params as well, but skip now
            return False

        param_enc = handler.param["sign"][0]
        param = base64.urlsafe_b64decode(param_enc + "===")
        exp = param[:8]
        exp_timestamp = int.from_bytes(exp)

        if time.time() > exp_timestamp:
            # Dont even bother if the signature has expired
            return False

        sig_got = param[8:]
        url = handler.path

        sig_need = hmac.digest(
            self.secret,
            exp + url.encode("utf8"),
            hashlib.sha256
        )

        return sig_got == sig_need
