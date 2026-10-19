//! libppcemu is an OPTIONAL dependency. If the libppcemu is prebuilt AND its headers exist AND libclang are present:
//! we link against it, generate bindings, and emit cfg 'have_ppcemu'
//! otherwise we build without it and the PPC LLE backend becomes a stub.
use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(have_ppcemu)");

    let backend_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = backend_dir.join("..").canonicalize().unwrap();
    let libppcemu_dir = workspace_dir.join("cronic/libppcemu");
    let include_dir = libppcemu_dir.join("include");

    let mut ppcemu_lib_path = libppcemu_dir.join("bin/libppcemu.a");
    // not testing ts on Windows right now but at least have it in the back of our heads
    if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
        ppcemu_lib_path.set_extension("lib");
    }

    let wrapper = backend_dir.join("wrapper.h");
    println!("cargo::rerun-if-changed={}", wrapper.display());
    println!("cargo::rerun-if-changed={}", ppcemu_lib_path.display());
    println!("cargo::rerun-if-changed={}", include_dir.display());

    let have_lib = std::fs::exists(&ppcemu_lib_path).unwrap_or(false);
    let have_headers = std::fs::exists(&include_dir).unwrap_or(false);
    if !(have_lib && have_headers) {
        // libppcemu not available, time to bail
        return;
    }

    // bindgen requires libclang but I don't want to force this dep at all.
    // unfortunately, bindgen will panic in this case instead of using Result, even though it returns Result.
    // seriously.... who designed this?
    // I guess we are the panic catching business now...

    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bindings_out = out_path.join("ppcemu_bindings.rs");

    let include_dir_c = include_dir.clone();
    let wrapper_c = wrapper.clone();
    let bindings_out_c = bindings_out.clone();

    // the backtrace will still print even if we catch the panic, temporarily override the panic hook to supress that
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(move || {
        let mut builder = bindgen::Builder::default()
            .header(wrapper_c.to_str().unwrap())
            .clang_arg(format!("-I{}", include_dir_c.display()));

        // *Some* environments ship libclang without its builtin freestanding
        // headers (stdbool.h, stdint.h, ...) on the default search path. Try to
        // locate clang's resource include dir and add it.
        // if nothing is found we fall through and rely on the system default.
        // and if that doesn't work the user will have to override via BINDGEN_EXTRA_CLANG_ARGS
        if let Some(res_dir) = clang_resource_include_dir() {
            builder = builder.clang_arg(format!("-isystem{}", res_dir.display()));
        }

        let bindings = builder
            .allowlist_function("ppcemu_.*")
            .allowlist_type("ppcemu_.*")
            .allowlist_var("PPCEMU_.*")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .map_err(|e| format!("bindgen failed to generate bindings: {e}"))?;

        bindings
            .write_to_file(&bindings_out_c)
            .map_err(|e| format!("failed to write libppcemu bindings: {e}"))?;

        Ok::<(), String>(())
    });
    std::panic::set_hook(prev_hook);

    let outcome = match result {
        Ok(inner) => inner,
        Err(_) => Err(
            "generating libppcemu bindings panicked (is `libclang` installed?)".to_string(),
        ),
    };

    if let Err(msg) = outcome {
        // didn't early bail, so they have the lib and headers and probably want integration
        // print message letting them know about the extra libclang dep
        println!("cargo::warning=libppcemu C integration disabled: {msg}");
        println!(
            "cargo::warning=install `libclang` (e.g. the `clang`/`libclang-dev` package) to enable it"
        );
        return;
    }

    // Bindings succeeded: now it's safe to link and advertise the cfg.
    let lib_search = ppcemu_lib_path.parent().unwrap();
    println!("cargo::rustc-link-search=native={}", lib_search.display());
    println!("cargo::rustc-link-lib=static:+whole-archive=ppcemu");
    println!("cargo::rustc-cfg=have_ppcemu");
}

fn clang_resource_include_dir() -> Option<PathBuf> {
    // ask nicely
    for clang in ["clang", "clang-cl"] {
        if let Ok(out) = std::process::Command::new(clang)
            .arg("-print-resource-dir")
            .output()
        {
            if out.status.success() {
                let dir = String::from_utf8_lossy(&out.stdout);
                let inc = PathBuf::from(dir.trim()).join("include");
                if inc.is_dir() {
                    return Some(inc);
                }
            }
        }
    }

    // ask less nicely
    let base = PathBuf::from("/usr/lib/clang");
    let mut candidates: Vec<(u64, PathBuf)> = std::fs::read_dir(&base)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let inc = e.path().join("include");
            if !inc.join("stdbool.h").is_file() {
                return None;
            }
            let ver = e
                .file_name()
                .to_str()
                .and_then(|n| n.split('.').next())
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
            Some((ver, inc))
        })
        .collect();
    candidates.sort_by_key(|(ver, _)| *ver);
    candidates.pop().map(|(_, inc)| inc)
}
