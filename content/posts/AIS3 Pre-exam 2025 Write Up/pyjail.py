#!/usr/local/bin/python3
from traceback import print_exception
import unicodedata
print(open(__file__).read())
while True:
    try:
        expr = unicodedata.normalize("NFKC", input("> "))
        if "._" in expr:
            raise NameError("no __ %r" % expr)

        if "breakpoint" in expr:
            raise NameError("no breakpoint %r" % expr)

        if any([x in "([ ])" for x in expr]):
            raise NameError("no ([ ]) %r" % expr)

        # baby version: response for free OUO
        result = eval(expr)
        print(result)
    except Exception as e:
        print_exception(e)
    except KeyboardInterrupt:
        break