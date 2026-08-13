SRC     := pita30_presentation.md
HTML    := pita30_presentation.html
PDF     := pita30_presentation.pdf

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
