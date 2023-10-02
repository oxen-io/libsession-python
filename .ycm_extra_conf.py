def Settings(**kwargs):
    import sysconfig

    includes = (f"-I{p}" for p in sysconfig.get_config_vars("INCLUDEPY"))

    return {
        "flags": ["-x", "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", *includes]
    }
