from datetime import datetime, timezone, timedelta
from functools import wraps
import ipaddress


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def until(
    *, days=0, seconds=0, microseconds=0, milliseconds=0, minutes=0, hours=0, weeks=0
) -> datetime:
    td = timedelta(
        days=days,
        seconds=seconds,
        microseconds=microseconds,
        milliseconds=milliseconds,
        minutes=minutes,
        hours=hours,
        weeks=weeks,
    )
    return datetime.now(timezone.utc).replace(tzinfo=None) + td


def auto_commit(*, rollback=True):
    """
    :param rollback: if true, will roll back on error
    """
    from openid_server import db

    def _decorator(func):
        @wraps(func)
        def _wrapper(*args, **kwargs):
            try:
                output = func(*args, **kwargs)
            except:
                if rollback:
                    db.session.rollback()
                else:
                    db.session.commit()
                raise
            else:
                db.session.commit()
            return output

        return _wrapper

    return _decorator


def anonymize_ip(ip_str, mask_size):
    """
    Anonymizes an IPv4 or IPv6 address based on the mask size.

    For IPv4:
    - mask_size 1: Masks to /24 (zeros the last octet)
    - mask_size 2: Masks to /16 (zeros the last two octets)

    For IPv6:
    - mask_size 1: Masks to /64 (zeros the last 64 bits, hiding the interface ID)
    - mask_size 2: Masks to /48 (zeros the last 80 bits, hiding subnet and interface)

    Args:
    ip_str (str): The IP address to anonymize.
    mask_size (int): The mask size (1 or 2).

    Returns:
    str: The anonymized IP address as a string.

    Raises:
    ValueError: If mask_size is not 1 or 2, or if ip_str is invalid.
    """
    if mask_size not in (1, 2):
        raise ValueError("Mask size must be 1 or 2.")

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")

    if ip.version == 4:
        if mask_size == 1:
            prefix = 24
        else:
            prefix = 16
    elif ip.version == 6:
        if mask_size == 1:
            prefix = 64
        else:
            prefix = 48
    else:
        raise ValueError("Unsupported IP version.")

    # Create a network with the given prefix and get the network address
    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(network.network_address)
