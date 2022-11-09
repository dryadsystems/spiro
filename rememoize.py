import pickle
from struct import pack
from typing import Iterator
from fickling import pickle as p
import spiro
from spiro import GetPlaceholder, MemoPlaceholder, Variables, get_index


def get_most_used(opcodes: list[p.Opcode]) -> dict[bytes, list]:
    "{opcode.data: [uses]} for common ops"
    constant_uses: dict[bytes, list] = {}
    for i, opcode in enumerate(opcodes):
        if isinstance(opcode, p.Unicode | p.BinUnicode | p.BinBytes | p.ShortBinBytes):
            if opcode.data not in constant_uses:
                constant_uses[opcode.data] = []
            constant_uses[opcode.data].append(i)

    # LongBinGet is 5 bytes, extra memo is 1
    most_used = {
        data: indices
        for data, indicies in constant_uses.items()
        if len(data) * len(indicies) > 6 and len(indicies) > 2
    }
    return most_used


def postprocess(opcodes: list[p.Opcode], optimize=True) -> p.Pickled:
    """
    1. memoize strings/bytes used more than twice longer than 3 bytes
    2. remove unused memos
    3. determine indexes of old memos and new memos
    4. map old memo indexes and variable names to new memo indexes (Variables takes care of this)
    """
    most_used = get_most_used(opcodes)
    used_memos = {
        get_index(op) for op in opcodes if isinstance(op, p.BinGet | p.LongBinGet)
    }
    removed_memos = 0
    added_memos = 0

    def memoize_op(
        i: int, op: p.Opcode
    ) -> Iterator[p.Opcode | GetPlaceholder | MemoPlaceholder]:
        "replace memo/get with placeholders, remove unused memos, add used memos"
        nonlocal added_memos
        # already a placeholder from PlaceholderVariables
        if not isinstance(op, p.Opcode):
            yield op
        elif op.data in most_used:
            # first use needs to be memoized
            # using the op.data as the memo key
            ## maybe op.arg was somehow dangerous though?
            ## sometimes fickling/genops is wrong about the arg
            if i == most_used[op.data][0]:
                added_memos += 1
                yield op
                yield MemoPlaceholder(op.data)
            # following uses are gets
            else:
                yield GetPlaceholder(op.data)
        elif isinstance(op, (p.BinGet, p.LongBinGet)):
            # keep that reference to old for the old memo index,
            # which will be the "variable name"
            yield GetPlaceholder(None, old=op)
        else:
            yield op

    if optimize:
        placeholders = [_op for op in enumerate(opcodes) for _op in memoize_op(*op)]
    else:
        placeholders = list(opcodes)
    old_memo_index = 0
    # memos.memo_indexes maps both meaningful var names and old memo indexes to new memo indexes
    memos = Variables()
    frame_lens: list[int] = []
    frame_indexes: list[int] = []

    # resolve placeholders
    for i, op in enumerate(placeholders):
        if isinstance(op, GetPlaceholder):
            if op.name:
                placeholders[i] = memos[op.name]
            else:
                placeholders[i] = memos[get_index(op.old)]
        elif isinstance(op, p.Memoize):
            # discard unused memos
            if optimize and old_memo_index not in used_memos:
                placeholders[i] = None
                removed_memos += 1
            else:
                placeholders[i] = memos.assign(old_memo_index)
            # always increment this so we can correctly resolve which index future memos refer to
            old_memo_index += 1
        elif isinstance(op, MemoPlaceholder):
            # new variable
            placeholders[i] = memos.assign(op.name)
        elif isinstance(op, p.Frame):
            # start a tracking a new frame size
            frame_indexes.append(i)  # location of the frame op
            frame_lens.append(0)
        # the frame data is the length in bytes of following upcode including stop or up until the next frame
        # if there was already a frame, increment the frame length
        if frame_lens and placeholders[i]:
            frame_lens[-1] += len(getattr(placeholders[i], "data", ""))
    # match frame op indexes with frame lengths
    # (although this matches number of bytes correctly,
    # it seems to sum to much more than normal pickle frames?
    for frame_index, frame_len in zip(frame_indexes, frame_lens):
        placeholders[frame_index].data = pickle.FRAME + pack("<Q", frame_len)
    result = p.Pickled(list(filter(None, placeholders)))
    assert all(isinstance(x, (p.Opcode)) for x in result)
    change = len(result.dumps()) - len(p.Pickled(opcodes).dumps())
    print(f"removed {removed_memos} memos, added {added_memos}. {change} bytes")
    return result


# this ought to be the same, but isn't
# write a test
def roundtrip(obj):
    import torch
    first, orig, last = spiro.find_main_pickle(obj)
    orig_pickle = p.Pickled.load(orig)
    f = open("/tmp/roundtrip_output", "wb")
    f.write(first)
    f.write(postprocess(orig_pickle).dumps())
    f.write(last)
    f.close()
    return torch.load("/tmp/roundtrip_output")
