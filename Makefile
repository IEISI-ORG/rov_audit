# --- Variables ---
GO := go
BINARY_EXTRACTOR := bgp-extractor
BINARY_CALCULATOR := cone-calculator
BINARY_FETCHROA := fetch-roa
MARP := npx @marp-team/marp-cli

# Source files — constants.go is shared across all binaries
SRC_SHARED    := constants.go
SRC_EXTRACTOR := bgp-extractor.go
SRC_CALCULATOR := cone-calculator.go
SRC_FETCHROA := fetch-roa.go

# Data URLs
RIB_URL := http://data.ris.ripe.net/rrc00/latest-bview.gz
RIB_FILE := latest-bview.gz

# Directories
OUTPUT_DIR := output

# --- Main Targets ---

.PHONY: all build clean setup download pipeline help

# Default target
all: build

# Help menu
help:
	@echo "Available commands:"
	@echo "  make build         - Compile the Go binaries"
	@echo "  make setup         - Initialize Go module and tidy dependencies"
	@echo "  make download      - Download the latest RIPE RIS BGP dump"
	@echo "  make pipeline      - Run the full extraction and calculation pipeline"
	@echo "  make present-apnic - Build APNIC-62 presentation (PITA30/31 use presentations/<event>/Makefile)"
	@echo "  make clean         - Remove binaries and output directory"

# 1. Setup Environment
setup:
	@[ -f go.mod ] || $(GO) mod init bgp-analysis
	$(GO) mod tidy

# 2. Compile Binaries
build: $(BINARY_EXTRACTOR) $(BINARY_CALCULATOR) $(BINARY_FETCHROA)

$(BINARY_EXTRACTOR): $(SRC_EXTRACTOR) $(SRC_SHARED)
	@echo "[*] Building $(BINARY_EXTRACTOR)..."
	$(GO) build -o $(BINARY_EXTRACTOR) $(SRC_EXTRACTOR) $(SRC_SHARED)

$(BINARY_CALCULATOR): $(SRC_CALCULATOR) $(SRC_SHARED)
	@echo "[*] Building $(BINARY_CALCULATOR)..."
	$(GO) build -o $(BINARY_CALCULATOR) $(SRC_CALCULATOR) $(SRC_SHARED)

$(BINARY_FETCHROA): $(SRC_FETCHROA) $(SRC_SHARED)
	@echo "[*] Building $(BINARY_FETCHROA)..."
	$(GO) build -o $(BINARY_FETCHROA) $(SRC_FETCHROA) $(SRC_SHARED)

# 3. Download Data
download:
	@echo "[*] Downloading latest RIB from RIPE..."
	wget -nc $(RIB_URL) -O $(RIB_FILE)

# 4. Run Full Pipeline
pipeline: build download
	@echo "[*] Step 1: Extracting Relationships (Go + bgpdump)..."
	@mkdir -p $(OUTPUT_DIR)
	# Note: This requires 'bgpdump' installed on your system
	bgpdump -m $(RIB_FILE) | ./$(BINARY_EXTRACTOR) -input /dev/stdin -output $(OUTPUT_DIR) -workers 16
	
	@echo "\n[*] Step 2: Calculating Cones (Go)..."
	./$(BINARY_CALCULATOR) -input $(OUTPUT_DIR)/relationships.csv -output final_as_rank.csv -top 0
	
	@echo "\n[+] Pipeline Complete. Topology saved to 'final_as_rank.csv'"

# Presentation targets (PITA30/31 and IETF are built via their own
# presentations/<event>/Makefile)
present-apnic: presentations/apnic62/apnic62_presentation.md
	@echo "[*] Building APNIC-62 Mumbai presentation..."
	$(MARP) --pdf --allow-local-files presentations/apnic62/apnic62_presentation.md -o presentations/apnic62/apnic62_presentation.pdf
	$(MARP) --html --allow-local-files presentations/apnic62/apnic62_presentation.md -o presentations/apnic62/apnic62_presentation.html
	@echo "[+] Files saved to presentations/apnic62/"

# Cleanup
clean:
	@echo "[*] Cleaning up..."
	rm -f $(BINARY_EXTRACTOR) $(BINARY_CALCULATOR) $(BINARY_FETCHROA)
	rm -rf $(OUTPUT_DIR)
	# Note: We do not delete the large .gz file by default to save bandwidth

