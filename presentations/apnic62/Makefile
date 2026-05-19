SRC     := apnic62_presentation.md
THEME   := apnic62-theme.css
HTML    := apnic62_presentation.html
PDF     := apnic62_presentation.pdf

MARP    := marp
SLIDES  := 45
MARPFLAGS := --theme-set $(THEME) --allow-local-files

.PHONY: all html pdf check clean

all: html pdf

html: $(HTML)

$(HTML): $(SRC) $(THEME)
	$(MARP) $(MARPFLAGS) $< -o $@

pdf: $(PDF)

$(PDF): $(SRC) $(THEME)
	$(MARP) $(MARPFLAGS) --pdf --pdf-outlines $< -o $@

check:
	@python3 check_render.py $(HTML) $(PDF) $(SLIDES)

clean:
	rm -f $(HTML) $(PDF)
