from Cython.Build import cythonize
from setuptools import setup

setup(
    name='Packet lib',
    ext_modules=cythonize(("./app/packet/layers/packet_decode.pyx"), annotate=True,
                          compiler_directives={"language_level": 3}),
)
