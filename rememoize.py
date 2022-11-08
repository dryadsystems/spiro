import pickle
from struct import pack
from typing import Iterator
from fickling import pickle as p
from spiro import GetPlaceholder, MemoPlaceholder, Variables, get_index


def get_most_used(opcodes: list[p.Opcode]) -> dict[bytes, list]:
    constant_uses: dict[bytes, list] = {}
    for i, opcode in enumerate(opcodes):
        # maybe also binbytes and shit?
        if isinstance(opcode, p.Unicode | p.BinUnicode):
            if opcode.arg not in constant_uses:
                constant_uses[opcode.arg] = []
            constant_uses[opcode.arg].append(i)

    most_used = {k: v for k, v in constant_uses.items() if len(v) > 2 and len(k) > 3}
    return most_used


def postprocess(opcodes: list[p.Opcode], optimize=True) -> p.Pickled:
    """
    1. memoize strings used more than twice longer than 3 bytes
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
        nonlocal added_memos
        if not isinstance(op, p.Opcode):
            yield op
        elif op.arg in most_used:
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
    if optimize:
        placeholders = [_op for op in enumerate(opcodes) for _op in memoize_op(*op)]
    else:
        placeholders = list(opcodes)
    old_memo_index = 0
    # real_vars.memo_indexes maps both meaningful var names and old memo indexes to new memo indexes
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
            op.arg = len(frame_lens)  # placeholder pointing at index
            frame_indexes.append(i)
            frame_lens.append(0)
            # the frame data is the length in bytes of following upcode including stop or  up until the next frame
        if frame_lens and placeholders[i]:
            frame_lens[-1] += len(getattr(placeholders[i], "data", ""))
    for frame_index, frame_len in zip(frame_indexes, frame_lens):
        placeholders[frame_index].data = pickle.FRAME + pack("<Q", frame_len)
    result = p.Pickled(list(filter(None, placeholders)))
    assert all(isinstance(x, (p.Opcode)) for x in result)
    change = len(result.dumps()) - len(p.Pickled(opcodes).dumps())
    print(f"removed {removed_memos} memos, added {added_memos}. {change} bytes")
    return result


def roundtrip(obj):
    import spiro
    first, orig, last = spiro.find_main_pickle(obj)
    orig_pickle = p.Pickled.load(orig)
    f = open("/tmp/roundtrip_output", "wb")
    f.write(first)
    f.write(postprocess(orig_pickle).dumps())
    f.write(last)
    f.close()
    return torch.load("/tmp/roundtrip_output")
