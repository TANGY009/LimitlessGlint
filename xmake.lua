set_project("LimitlessGlint")
set_version("1.0.1")

set_languages("cxx23")

add_rules("mode.release")

add_cxflags("-O2", "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections", "-flto", "-w")
add_ldflags("-Wl,--gc-sections", "-Wl,--strip-all", "-s")

add_repositories(
    "xmake-repo https://github.com/xmake-io/xmake-repo.git"
)

target("LimitlessGlint")
    set_kind("shared")
    add_files("src/*.cpp")
    add_includedirs("src")
    
    add_links("log")