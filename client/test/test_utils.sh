#!/bin/bash

# ANSI color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to run a test command and format its output
run_test_with_format() {
    local test_cmd="$1"
    local indent="    "  # 4 spaces for indentation
    
    echo -e "${BLUE}Running test: $test_cmd${NC}"
    echo "----------------------------------------"
    
    # Run the command and capture stdout and stderr separately
    local stdout
    local stderr
    stdout=$(eval "$test_cmd" 2> >(tee /dev/stderr))
    exit_code=$?
    stderr=$(cat)
    
    # Format and print the stdout with indentation
    if [ -n "$stdout" ]; then
        echo "$stdout" | while IFS= read -r line; do
            echo -e "${GREEN}$indent$line${NC}"
        done
    fi
    
    # Check for stderr output and exit code
    if [ -n "$stderr" ] || [ $exit_code -ne 0 ]; then
        echo -e "${RED}${indent}Test failed:${NC}"
        if [ -n "$stderr" ]; then
            echo "$stderr" | while IFS= read -r line; do
                echo -e "${RED}${indent}$line${NC}"
            done
        fi
        if [ $exit_code -ne 0 ]; then
            echo -e "${RED}${indent}Exit code: $exit_code${NC}"
        fi
        echo "----------------------------------------"
        return 1
    fi
    
    echo -e "${GREEN}${indent}Test completed successfully${NC}"
    echo "----------------------------------------"
    return 0
} 