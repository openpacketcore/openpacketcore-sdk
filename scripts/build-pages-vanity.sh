#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
book_dir="${1:-"$repo_root/book"}"
sdk_dir="$repo_root/operators/operator-sdk-go"

module_path="openpacketcore.io/operator-sdk-go"
repo_url="https://github.com/openpacketcore/openpacketcore-sdk"
module_subdir="operators/operator-sdk-go"

write_vanity_page() {
	local dir="$1"
	local import_path="$2"
	mkdir -p "$dir"
	cat >"$dir/index.html" <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="go-import" content="${module_path} git ${repo_url} ${module_subdir}">
<meta name="go-source" content="${module_path} ${repo_url} ${repo_url}/tree/main/${module_subdir}{/dir} ${repo_url}/blob/main/${module_subdir}{/dir}/{file}#L{line}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="0; url=/">
<link rel="canonical" href="https://${import_path}">
<title>${import_path}</title>
</head>
<body>
<p>Go package metadata for <code>${import_path}</code>.</p>
<p><a href="${repo_url}/tree/main/${module_subdir}">View source on GitHub</a>.</p>
</body>
</html>
HTML
}

if [[ ! -d "$book_dir" ]]; then
	echo "book directory not found: $book_dir" >&2
	exit 1
fi

if [[ ! -d "$sdk_dir" ]]; then
	echo "operator-sdk-go directory not found: $sdk_dir" >&2
	exit 1
fi

printf 'openpacketcore.io\n' >"$book_dir/CNAME"
touch "$book_dir/.nojekyll"

write_vanity_page "$book_dir/operator-sdk-go" "$module_path"

while IFS= read -r package_dir; do
	relative="${package_dir#"$sdk_dir"/}"
	[[ "$relative" == "$package_dir" ]] && continue
	if [[ -z "$(find "$package_dir" -maxdepth 1 -type f -name '*.go' -print -quit)" ]]; then
		continue
	fi
	write_vanity_page "$book_dir/operator-sdk-go/$relative" "$module_path/$relative"
done < <(find "$sdk_dir" -mindepth 1 -maxdepth 1 -type d | sort)

cat >"$book_dir/404.html" <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="go-import" content="${module_path} git ${repo_url} ${module_subdir}">
<meta name="go-source" content="${module_path} ${repo_url} ${repo_url}/tree/main/${module_subdir}{/dir} ${repo_url}/blob/main/${module_subdir}{/dir}/{file}#L{line}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenPacketCore SDK</title>
</head>
<body>
<h1>OpenPacketCore SDK</h1>
<p>The requested page was not found. Documentation starts at <a href="/">openpacketcore.io</a>.</p>
</body>
</html>
HTML
