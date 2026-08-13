SRC     := ietf_presentation.md
HTML    := ietf_presentation.html
PDF     := ietf_presentation.pdf

MARP      := npx @marp-team/marp-cli
MARPFLAGS := --allow-local-files

.PHONY: all html pdf clean

all: html pdf

html: $(HTML)

$(HTML): $(SRC)
	$(MARP) $(MARPFLAGS) --html $< -o $@

pdf: $(PDF)

$(PDF): $(SRC)
	$(MARP) $(MARPFLAGS) --pdf $< -o $@

clean:
	rm -f $(HTML) $(PDF)
