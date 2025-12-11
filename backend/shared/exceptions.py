"""Custom exceptions for sdbx."""


class SdbxError(Exception):
    """Base exception for sdbx."""
    pass


class ValidationError(SdbxError):
    """Invalid input data."""
    pass


class FileNotFoundError(SdbxError):
    """File does not exist."""
    pass


class FileAlreadyDownloadedError(SdbxError):
    """File was already downloaded."""
    pass


class FileExpiredError(SdbxError):
    """File has expired."""
    pass
