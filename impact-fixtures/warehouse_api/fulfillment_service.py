from crypto_helpers import sign_manifest


def dispatch_manifest() -> str:
    return sign_manifest()
