import powermake

def on_build(config: powermake.Config):
    config.add_flags("-Wall", "-Wextra")

    config.add_includedirs("./include")
    
    config.add_shared_libs("pcap")

    files = powermake.get_files("**/*.c",
        "**/*.cpp", "**/*.cc", "**/*.C",
        "**/*.asm", "**/*.s", "**/*.rc")

    objects = powermake.compile_files(config, files)

    powermake.link_files(config, objects)

powermake.run("my_project", build_callback=on_build)
