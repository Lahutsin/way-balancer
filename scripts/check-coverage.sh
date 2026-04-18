#!/usr/bin/env sh
set -eu

min_file_coverage="${MIN_FILE_COVERAGE:-80}"
coverage_dir="${COVERAGE_OUTPUT_DIR:-.coverage}"
lcov_path="${coverage_dir}/lcov.info"
workspace_root="$(pwd)"

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov is required for coverage enforcement; install it with: cargo install cargo-llvm-cov --locked" >&2
  exit 1
fi

if ! rustup component list --installed | grep -q '^llvm-tools'; then
  echo "llvm-tools-preview is required for coverage enforcement; install it with: rustup component add llvm-tools-preview" >&2
  exit 1
fi

mkdir -p "$coverage_dir"

cargo llvm-cov --workspace --all-features --jobs 1 --lcov --output-path "$lcov_path" -- --test-threads=1

awk -v threshold="$min_file_coverage" -v root="$workspace_root" '
function normalize(path) {
  gsub("\\\\", "/", path)
  return path
}

function should_check(path) {
  path = normalize(path)
  if (path ~ /^\/rustc\//) {
    return 0
  }
  if (index(path, root "/") == 1) {
    path = substr(path, length(root) + 2)
  }
  return path ~ "^(crates|binaries)/[^/]+/src/.*\\.rs$"
}

function finish_record() {
  if (current_file == "") {
    return
  }

  if (should_check(current_file)) {
    checked_files += 1
    percent = executable_lines == 0 ? 100 : (covered_lines * 100.0) / executable_lines
    printf "%6.2f%% %s\n", percent, current_file
    if (percent + 0.0001 < threshold) {
      failing_files += 1
      printf "coverage gate failed: %.2f%% < %s%% for %s\n", percent, threshold, current_file > "/dev/stderr"
    }
  }

  current_file = ""
  executable_lines = 0
  covered_lines = 0
}

BEGIN {
  current_file = ""
  executable_lines = 0
  covered_lines = 0
  checked_files = 0
  failing_files = 0
}

/^SF:/ {
  finish_record()
  current_file = substr($0, 4)
  next
}

/^DA:/ {
  split(substr($0, 4), parts, ",")
  executable_lines += 1
  if ((parts[2] + 0) > 0) {
    covered_lines += 1
  }
  next
}

/^end_of_record$/ {
  finish_record()
  next
}

END {
  finish_record()
  if (checked_files == 0) {
    print "coverage gate did not find any workspace source files to evaluate" > "/dev/stderr"
    exit 1
  }
  if (failing_files > 0) {
    exit 1
  }
}
' "$lcov_path"