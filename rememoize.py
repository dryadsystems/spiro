import pickle
from collections import defaultdict
from dataclasses import dataclass
from struct import pack
from typing import Iterator, Optional
from fickling import pickle as p
from spiro import Opcodes, Variables, get_index, make_get


@dataclass
class GetPlaceholder:
    name: str | bytes
    old: Optional[p.Opcode] = None


@dataclass
class MemoPlaceholder:
    name: str


Get = p.BinGet | p.LongBinGet
Placeholder = GetPlaceholder | MemoPlaceholder


class PlaceholderVariables(Variables):
    # programs should use this guy
    def assign(self, name: str, id: Optional[str] = None) -> MemoPlaceholder:
        return MemoPlaceholder(name)

    def __getattr__(self, name: str) -> GetPlaceholder:
        return GetPlaceholder(name)


def postprocess(opcodes: Opcodes) -> Opcodes:
    """
    1. memoize strings used more than twice longer than 3 bytes
    2. remove unused memos
    3. determine indexes of old memos and new memos
    4. map old memo indexes and variable names to new memo indexes (Variables takes care of this)
    """
    constant_uses: dict[bytes, list] = {}
    for i, opcode in enumerate(opcodes):
        # maybe also binbytes and shit?
        if isinstance(opcode, p.Unicode | p.BinUnicode):
            if opcode.arg not in constant_uses:
                constant_uses[opcode.arg] = []
            constant_uses[opcode.arg].append(i)

    most_used = {k: v for k, v in constant_uses.items() if len(v) > 2 and len(k) > 3}
    used_memos = {get_index(op) for op in opcodes if isinstance(op, Get)}
    removed_memos = 0
    added_memos = 0
    orig_len = len(p.Pickled(opcodes).dumps())

    def memoize_op(i: int, op: p.Opcode) -> Iterator[p.Opcode | Placeholder]:
        nonlocal added_memos
        if op.arg in most_used:
            if i == most_used[op.arg][0]:
                added_memos += 1
                yield op
                yield MemoPlaceholder(op.arg)
            else:
                yield GetPlaceholder(op.arg)
        elif isinstance(op, (p.BinGet, p.LongBinGet)):
            yield GetPlaceholder(None, old=op)
        else:
            yield op

    placeholders = [_op for op in enumerate(opcodes) for _op in memoize_op(*op)]
    old_memo_index = 0
    # real_vars.memo_indexes maps both meaningful var names and old memo indexes to new memo indexes
    vars = Variables()
    frame_lens = []
    frame_indexes = []

    # resolve placeholders
    for i, op in enumerate(placeholders):
        if isinstance(op, GetPlaceholder):
            if op.name:
                placeholders[i] = vars[op.name]
            else:
                placeholders[i] = vars[get_index(op.old)]
        elif isinstance(op, p.Memoize):
            # discard unused memos
            if old_memo_index not in used_memos:
                placeholders[i] = None
                removed_memos += 1
            else:
                placeholders[i] = vars.assign(old_memo_index)
            # always increment this so we can correctly resolve which index future memos refer to
            old_memo_index += 1
        elif isinstance(op, MemoPlaceholder):
            # new variable
            placeholders[i] = vars.assign(op.name)
        elif isinstance(op, p.Frame):
            op.arg = len(frame_lens)  # placeholder pointing at index
            frame_indexes.append(i)
            frame_lens.append(0)
            # the frame data is the length in bytes of following upcode including stop or  up until the next frame
        if frame_lens and placeholders[i]:
            frame_lens[-1] += len(placeholders[i].data)
    for frame_index, frame_len in zip(frame_indexes, frame_lens):
        placeholders[frame_index].data = pickle.FRAME + pack("<Q", frame_len)
    result = p.Pickled(list(filter(None, placeholders)))
    change = len(result.dumps()) - orig_len
    print(f"removed {removed_memos} memos, added {added_memos}. {change} bytes")
    return result
