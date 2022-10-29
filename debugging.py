import ast
import pickle
import pickletools as pt
from typing import Any
from fickling import pickle as p
from fickling.pickle import Pickled


def trunc(obj: Any, limit: int = 32) -> str:
    text = str(obj)
    if len(text) < limit:
        return text
    return f"{text[:limit]}..."


def show(thing: Any) -> Any:
    # pylint: disable=too-many-return-statements
    if isinstance(thing, (list, tuple)):
        return "[" + ",".join([str(show(item)) for item in thing]) + "]"
    match type(thing):
        case ast.Constant:
            return f"<Constant {trunc(thing.value)}>"
        case ast.Tuple:
            return f"<Tuple {show(thing.dims)}>"
        case p.Stack:
            return f"<Stack [{','.join([str(show(item)) for item in thing])}]>"
        case __builtins__.dict:
            return {key: show(value) for key, value in thing.items()}
        case ast.Name:
            if thing.id == "OrderedDict":
                return "<OrderedDict (getattr)>"
            return f"<Name {thing.id}>"
        case ast.alias:
            return thing.name
        case ast.ImportFrom:
            return f"<ImportFrom names={show(thing.names)}>"
        case p.Interpreter:
            return f"<Interpreter(stack={show(thing.stack)}, memory={show(thing.memory)}, counter={thing._var_counter})>"
        case other:
            del other
            return thing


def dis(ops: list[p.Opcode]) -> None:
    try:
        pt.dis(Pickled(ops).dumps())
    except:
        pass


def debug(pickled: Pickled) -> None:
    interp = p.Interpreter(pickled)
    interp.run()
    while 1:
        op = interp.step()
        print(op)
        print(show(interp))
        input()
