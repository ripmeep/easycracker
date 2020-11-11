from distutils.core import setup, Extension

setup(name="easycracker", version="1.0",
	ext_modules=[
		Extension(
			"easycracker", ["easycracker.c"],
			extra_link_args = ["-lcrypto", "-lcurl"]
		)
	]
)
