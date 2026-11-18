"""The request-path guard against httpx's own resolution, over every path of
up to three caller segments drawn from plain ids and every dot form: a path
the guard passes resolves to itself, and the guard refuses a path exactly
when one of its segments is a dot segment."""

import itertools

import httpx
import pytest

from mipiti_mcp.client import UnsafePath, _GuardedClient, is_dot_segment

BASE = "https://api.example.com"
#: Plain ids (some with dots or an encoded dot inside), and every dot form.
ALPHABET = ["m1", "a%2e", "x..y", ".hidden", "v1.2", ".", "..", "%2e", "%2E",
            ".%2e", "%2E.", "%2e%2E", "%2E%2E", ".\t.", "%2e\n"]
DOTS = {".", "..", "%2e", "%2E", ".%2e", "%2E.", "%2e%2E", "%2E%2E", ".\t.", "%2e\n"}
PATHS = [seq for n in range(1, 4) for seq in itertools.product(ALPHABET, repeat=n)]


#: Characters a random segment is drawn from: what URL parsers treat
#: specially, and look-alikes of the dot and the slash.
_CHARS = list(".%2eE/\\?#;:@&=+ \t\nab09-_~") + ["．", "。", "／", "＼", "%2e", "%2E", "%2f", "%5c"]
_SEED = 20261118
_CASES = 4000


def _random_segment(rng) -> str:
    return "".join(rng.choice(_CHARS) for _ in range(rng.randint(1, 6)))


def test_a_random_id_is_one_segment_sent_intact():
    """Seeded property: any id either is refused (empty or a dot segment) or
    reaches the server as exactly one segment that decodes to the id."""
    import random
    from urllib.parse import unquote

    from mipiti_mcp.client import _seg

    rng = random.Random(_SEED)
    client = _GuardedClient(base_url=BASE)
    for _ in range(_CASES):
        ident = _random_segment(rng)
        try:
            seg = _seg(ident)
        except UnsafePath:
            assert ident == "" or is_dot_segment(ident), repr(ident)
            continue
        sent = client.build_request("GET", f"/api/models/{seg}/x").url.raw_path.decode()
        parts = sent.split("/")
        assert len(parts) == 5 and parts[:3] == ["", "api", "models"] and parts[4] == "x", (
            repr(ident), sent)
        assert unquote(parts[3]) == ident, (repr(ident), sent)


def test_a_random_raw_path_is_sent_as_written_or_refused():
    """Seeded property over raw, unencoded paths of 1 to 8 random segments:
    a path the guard passes is sent exactly as written, and a path httpx
    would move is refused."""
    import random
    from urllib.parse import unquote

    rng = random.Random(_SEED + 1)
    guarded = _GuardedClient(base_url=BASE)
    plain = httpx.Client(base_url=BASE)
    for _ in range(_CASES):
        segs = [_random_segment(rng) for _ in range(rng.randint(1, 8))]
        path = "/api/models/" + "/".join(segs)
        try:
            moved = unquote(plain.build_request("GET", path).url.raw_path.decode().split("?")[0]) \
                != unquote(path.split("?")[0].split("#")[0])
        except httpx.InvalidURL:
            continue  # httpx refuses it itself; nothing is sent
        try:
            sent = guarded.build_request("GET", path).url.raw_path.decode().split("?")[0]
        except UnsafePath:
            continue
        except httpx.InvalidURL:
            continue
        assert not moved, path
        assert unquote(sent) == unquote(path.split("?")[0].split("#")[0]), path


def test_the_dot_forms_are_exactly_the_alphabet_s_dots():
    assert {s for s in ALPHABET if is_dot_segment(s)} == DOTS


@pytest.mark.parametrize("n", [1, 2, 3])
def test_a_guarded_path_resolves_to_itself_and_only_dot_segments_are_refused(n):
    guarded = _GuardedClient(base_url=BASE)
    plain = httpx.Client(base_url=BASE)
    for seq in (p for p in PATHS if len(p) == n):
        path = "/api/models/" + "/".join(seq) + "/x"
        has_dot = any(s in DOTS for s in seq)
        try:
            req = guarded.build_request("GET", path)
        except UnsafePath:
            assert has_dot, path  # refused only what must be
            continue
        assert not has_dot, path
        # httpx sends exactly the path built.
        assert req.url.raw_path.decode() == path
        assert plain.build_request("GET", path).url.raw_path.decode() == path
