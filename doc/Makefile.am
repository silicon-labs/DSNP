# 
#  Copyright (c) 2011, Adrian Thurston <thurston@complang.org>
#
#  Permission to use, copy, modify, and/or distribute this software for any
#  purpose with or without fee is hereby granted, provided that the above
#  copyright notice and this permission notice appear in all copies.
#
#  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

all: spec-asciidoc.html

generate.bin: generate.lm
	colm generate.lm

spec-asciidoc.html: spec-asciidoc.txt
	a2x -d book -f xhtml spec-asciidoc.txt

spec-asciidoc.txt: generate.bin spec.txt
	./generate.bin < spec.txt > spec-asciidoc.txt

spec.pdf: spec.tex
	pdflatex -interaction=nonstopmode $< >/dev/null
	pdflatex -interaction=nonstopmode $< >/dev/null
	pdflatex -interaction=nonstopmode $< >/dev/null

clean:
	rm -f spec.pdf spec.log
