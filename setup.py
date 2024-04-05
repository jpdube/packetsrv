from Cython.Build import cythonize
from setuptools import setup

setup(
    name='Packet lib',
    ext_modules=cythonize(("./app/packet/layers/ethernet.pyx", "./app/packet/layers/packet.pyx", "./app/packet/layers/ipv4.pyx", "./app/packet/layers/tcp.pyx"), annotate=True,
                          compiler_directives={"language_level": 3}),
)
