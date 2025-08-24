// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

fn main() {
    println!("cargo:rerun-if-changed=../monad-cxx/monad-execution");
    println!("cargo:rerun-if-env-changed=TRIEDB_TARGET");

    let build_execution_lib =
        std::env::var("TRIEDB_TARGET").is_ok_and(|target| target == "triedb_driver");
    if build_execution_lib {
        /*
         * libmonad_execution.so - hosted execution functionality
         */

        let exec_target = "monad_execution";
        let exec_dst = cmake::Config::new("monad-execution")
            .define("BUILD_SHARED_LIBS", "ON")
            .build_target(exec_target)
            .build();

        println!("cargo:rustc-link-search=native={}/build", exec_dst.display());
        println!("cargo:rustc-link-lib=dylib={}", &exec_target);

        // Tell dependent packages where libmonad_execution.so is
        println!("cargo:CMAKE_BINARY_DIR={}/build", exec_dst.display());

        /*
         * libmonad_cxx_env.so - needed to bring up the C++ environment inside Rust
         */

        let cxx_env_target = "monad_cxx_env";
        let cxx_env_dst = cmake::Config::new("monad-cxx-env")
            .define("BUILD_SHARED_LIBS", "ON")
            .build_target(cxx_env_target)
            .build();

        println!("cargo:rustc-link-search=native={}/build", cxx_env_dst.display());
        println!("cargo:rustc-link-lib=dylib={}", &cxx_env_target);
    }
}
