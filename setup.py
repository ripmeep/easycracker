from distutils.core import setup, Extension

setup(name="easycracker", version="1.2.1",
	ext_modules=[
		Extension(
			"easycracker", ["easycracker.c"],
			extra_link_args = ["-lcrypto", "-lcurl", "-lsqlite3"]
		)
	]
)
