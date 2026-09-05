class ProtocolPlazaError(Exception):
    """Base error for expected protocol failures."""


class AuthenticationError(ProtocolPlazaError):
    pass


class AuthorizationError(ProtocolPlazaError):
    pass


class CryptographicError(ProtocolPlazaError):
    pass


class CausalError(ProtocolPlazaError):
    pass


class ProtocolError(ProtocolPlazaError):
    pass
